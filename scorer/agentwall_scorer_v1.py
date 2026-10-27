#!/usr/bin/env python3
# =============================================================================
# agentwall_scorer_v1.py
# -----------------------------------------------------------------------------
# Streaming anomaly detector for autonomous LLM/AI pentest agents.
#
# DEPRECATED: this is the v1 reference implementation. Use
# agentwall_scorer.py (v2) in production: it adds population-relative
# cutoffs, human-ness gating, good-bot verification, verified challenge support,
# IPv6 aggregation, bounded state, and atomic checkpoints. v1 is kept only for
# comparison/rollback and still works for small single-site deployments.
#
# Pipeline:
#   nginx access log  ->  per-IP sliding-window features  ->  online anomaly
#   model (river HalfSpaceTrees, unsupervised)  ->  graduated action
#   (log / watch / block via fail2ban or Redis).
#
# Why this layer: static WAF signatures miss the adaptive multi-stage behaviour
# (recon -> enumeration -> probe -> auth, persistence past 403/429). This scores
# that BEHAVIOUR per source, learned from your own baseline traffic, so there is
# no training dataset to build. It is a detection/scoring aid, NOT an unbypassable
# wall: a slow low-and-wide run across rotating IPs can still stay under it, and a
# bad threshold blocks real users. Run --dry-run first, baseline, then --enforce.
#
# Usage:
#   python3 agentwall_scorer_v1.py --log /var/log/nginx/agentwall_access.log            # dry-run
#   python3 agentwall_scorer_v1.py --log ... --enforce --backend fail2ban --jail agentwall-ml
#   python3 agentwall_scorer_v1.py --log ... --enforce --backend redis --redis-url redis://127.0.0.1:6379/0
#
# Requires: pip install -r requirements.txt   (redis only needed for --backend redis/both)
# =============================================================================

import argparse
import ipaddress
import logging
import math
import os
import pickle
import re
import subprocess
import sys
import time
from collections import OrderedDict, deque
from datetime import datetime

try:
    from river import anomaly
except ImportError:
    sys.exit("river is required: pip install -r requirements.txt")


# --- Log parsing -------------------------------------------------------------
# Matches the custom 'agentwall' log_format (with ua_flag=/probe= tails) AND falls
# back to standard combined format (the extra tails are optional).
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)?\s*(?P<path>[^"\s]*)[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
    r'(?:\s+rt=(?P<rt>\S+))?'
    r'(?:\s+urt=(?P<urt>\S+))?'
    r'(?:\s+ua_flag=(?P<ua_flag>\d))?'
    r'(?:\s+probe=(?P<probe>\d))?'
)

AUTH_RE = re.compile(
    r'/(login|signin|sign-in|auth|oauth|token|verify|otp|mfa|2fa|password/(reset|forgot))',
    re.IGNORECASE,
)
STATIC_EXT = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".webp", ".avif",
}
# Coarse injection/traversal markers (path+query); mirrors the WAF marker list.
PROBE_RE = re.compile(
    r'(\.\./|union[\s/*]+select|<script|;\s*drop\s+table|/etc/passwd|\bor\s+1=1)',
    re.IGNORECASE,
)
MISS_CODES = {400, 404}
DENY_CODES = {401, 403, 429}


def parse_line(line):
    """Return an event dict, or None if the line cannot be parsed."""
    m = LOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        ts = datetime.strptime(g["time"], "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        ts = time.time()
    try:
        status = int(g["status"])
    except (TypeError, ValueError):
        return None
    path = g["path"] or ""
    stem = path.split("?", 1)[0]
    ext = os.path.splitext(stem)[1].lower()
    return {
        "ip": g["ip"],
        "ts": ts,
        "status": status,
        "path": stem,
        "is_auth": bool(AUTH_RE.search(path)),
        "is_static": ext in STATIC_EXT,
        "is_probe": bool(PROBE_RE.search(path)) or g.get("probe") == "1",
        "ua_flag": g.get("ua_flag") == "1",
    }


# --- Per-IP sliding window + feature extraction ------------------------------
class IPWindow:
    __slots__ = ("events", "last_action")

    def __init__(self):
        self.events = deque()          # list of event dicts, time-ordered
        self.last_action = 0.0         # unix ts of last block/watch action (cooldown)

    def add(self, ev, window):
        self.events.append(ev)
        cutoff = ev["ts"] - window
        while self.events and self.events[0]["ts"] < cutoff:
            self.events.popleft()

    def features(self):
        """Compute a normalised [0,1] feature dict + a hard-signal flag."""
        evs = self.events
        n = len(evs)
        if n == 0:
            return None, False

        miss = sum(1 for e in evs if e["status"] in MISS_CODES)
        deny = sum(1 for e in evs if e["status"] in DENY_CODES)
        auth = sum(1 for e in evs if e["is_auth"])
        static = sum(1 for e in evs if e["is_static"])
        probe = sum(1 for e in evs if e["is_probe"])
        ua_flag = sum(1 for e in evs if e["ua_flag"])

        paths = [e["path"] for e in evs]
        uniq = len(set(paths))

        # Shannon entropy of the path distribution, normalised to [0,1].
        counts = {}
        for p in paths:
            counts[p] = counts.get(p, 0) + 1
        ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
        ent_norm = ent / math.log2(n) if n > 1 else 0.0

        # Timing: coefficient of variation of inter-arrival deltas.
        # Metronomic (bot-like) -> low CV -> high 'regularity'.
        ts_sorted = sorted(e["ts"] for e in evs)
        deltas = [b - a for a, b in zip(ts_sorted, ts_sorted[1:])]
        if len(deltas) >= 2:
            mean = sum(deltas) / len(deltas)
            var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            cv = (math.sqrt(var) / mean) if mean > 0 else 0.0
            regularity = 1.0 / (1.0 + cv)
        else:
            regularity = 0.0

        # Persistence: share of requests issued AFTER the first deny in the window.
        first_deny = next((e["ts"] for e in evs if e["status"] in DENY_CODES), None)
        if first_deny is not None:
            after = sum(1 for e in evs if e["ts"] > first_deny)
            persistence = after / n
        else:
            persistence = 0.0

        # Multi-stage co-occurrence: the behaviour-based core from the defense
        # guide (enumeration + probe + auth within one window). Strong signal.
        has_enum = miss >= 3
        has_probe = probe >= 1
        has_auth = auth >= 1
        multistage = 1.0 if (has_enum and has_probe and has_auth) else 0.0

        x = {
            "req_rate": min(n / 120.0, 1.0),          # normalise against a cap
            "miss_ratio": miss / n,
            "deny_ratio": deny / n,
            "auth_ratio": auth / n,
            "uniq_ratio": uniq / n,
            "path_entropy": ent_norm,
            "nonstatic_ratio": 1.0 - static / n,
            "probe_ratio": probe / n,
            "regularity": regularity,
            "persistence": persistence,
            "ua_flag_ratio": ua_flag / n,
            "multistage": multistage,
        }
        # Hard signal: trust these regardless of the (possibly cold) model.
        hard = bool(multistage) or ua_flag > 0 or (probe >= 2 and persistence > 0.5)
        return x, hard


# --- Action backends ---------------------------------------------------------
class Blocker:
    def __init__(self, args):
        self.backend = args.backend
        self.jail = args.jail
        self.ttl = args.block_ttl
        self.enforce = args.enforce
        self.redis = None
        if self.backend in ("redis", "both"):
            try:
                import redis
            except ImportError:
                sys.exit("redis backend needs: pip install redis")
            self.redis = redis.Redis.from_url(args.redis_url, decode_responses=True)

    def block(self, ip, score, reason):
        tag = "BLOCK" if self.enforce else "BLOCK(dry-run)"
        logging.warning("%s ip=%s score=%.3f reason=%s", tag, ip, score, reason)
        if not self.enforce:
            return
        if self.backend in ("fail2ban", "both"):
            self._fail2ban(ip)
        if self.backend in ("redis", "both"):
            self._redis(ip)

    def _fail2ban(self, ip):
        try:
            subprocess.run(
                ["fail2ban-client", "set", self.jail, "banip", ip],
                check=True, capture_output=True, timeout=5,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.error("fail2ban ban failed ip=%s err=%s", ip, e)

    def _redis(self, ip):
        try:
            self.redis.set(f"agentwall:block:{ip}", "1", ex=self.ttl)
        except Exception as e:  # noqa: BLE001 - redis errors vary
            logging.error("redis ban failed ip=%s err=%s", ip, e)


# --- Allowlist ---------------------------------------------------------------
class Allowlist:
    def __init__(self, cidrs):
        self.nets = []
        for c in cidrs:
            c = c.strip()
            if c:
                try:
                    self.nets.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    logging.error("invalid allowlist entry: %s", c)

    def allows(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.nets)


# --- State persistence (atomic, guarded) -------------------------------------
def save_state(model, path):
    """Write the checkpoint atomically so a crash mid-write cannot corrupt it."""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    tmp = "{}.tmp.{}".format(path, os.getpid())
    with open(tmp, "wb") as fh:
        pickle.dump({"version": 1, "model": model}, fh,
                    protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, path)


def load_state(path):
    """Load a checkpoint; return None (fresh model) instead of crashing."""
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as fh:
            blob = pickle.load(fh)
        if isinstance(blob, dict) and "model" in blob:
            return blob["model"]
        return blob  # legacy checkpoint
    except Exception as e:  # noqa: BLE001
        logging.error("could not load state %s: %s -- starting from a fresh model", path, e)
        return None


# --- Log tailer (follows rotation/truncation) --------------------------------
def tail(path, from_start=False):
    while not os.path.exists(path):
        logging.info("waiting for log file: %s", path)
        time.sleep(1)
    f = open(path, "r", errors="replace")
    inode = os.fstat(f.fileno()).st_ino
    if not from_start:
        f.seek(0, os.SEEK_END)
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        time.sleep(0.25)
        try:
            if os.stat(path).st_ino != inode or os.stat(path).st_size < f.tell():
                f.close()
                f = open(path, "r", errors="replace")
                inode = os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            time.sleep(1)


# --- Main loop ---------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Streaming ML blocker for autonomous LLM/AI pentest agents")
    ap.add_argument("--log", required=True, help="nginx access log path")
    ap.add_argument("--from-start", action="store_true", help="read the whole file, not just new lines")
    ap.add_argument("--window", type=float, default=60.0, help="per-IP window seconds")
    ap.add_argument("--min-events", type=int, default=15, help="min events in window before acting on an IP")
    ap.add_argument("--warmup", type=int, default=500, help="events the model learns before any action")
    ap.add_argument("--watch-threshold", type=float, default=0.72)
    ap.add_argument("--block-threshold", type=float, default=0.86)
    ap.add_argument("--cooldown", type=float, default=300.0, help="seconds between actions on the same IP")
    ap.add_argument("--enforce", action="store_true", help="actually block (default: dry-run, log only)")
    ap.add_argument("--backend", choices=["none", "fail2ban", "redis", "both"], default="none")
    ap.add_argument("--jail", default="agentwall-ml", help="fail2ban jail for manual bans")
    ap.add_argument("--redis-url",
                    default=os.environ.get("REDIS_URL") or "redis://127.0.0.1:6379/0")
    ap.add_argument("--block-ttl", type=int, default=1800, help="redis block TTL seconds")
    ap.add_argument("--allowlist", default="127.0.0.1/32,::1/128", help="comma CIDRs to never block")
    ap.add_argument("--allowlist-file", help="file with one CIDR per line")
    ap.add_argument("--state", help="model checkpoint path (load on start, save periodically)")
    ap.add_argument("--idle-evict", type=float, default=600.0, help="drop per-IP state idle for N seconds")
    ap.add_argument("--max-ips", type=int, default=50000, help="LRU cap on tracked IPs (bounds memory)")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )

    cidrs = args.allowlist.split(",")
    if args.allowlist_file and os.path.exists(args.allowlist_file):
        with open(args.allowlist_file) as fh:
            cidrs += fh.read().splitlines()
    allow = Allowlist(cidrs)
    blocker = Blocker(args)

    # Online anomaly model. Unsupervised: learns the baseline continuously so
    # rare, odd per-IP behaviour scores high. Note: a sustained attack can drift
    # into the baseline over time -- that is an inherent streaming trade-off.
    model = load_state(args.state)
    if model is not None:
        logging.info("loaded model state: %s", args.state)
    else:
        model = anomaly.HalfSpaceTrees(n_trees=10, height=8, window_size=250, seed=42)

    windows = OrderedDict()  # ip -> IPWindow (LRU: move_to_end on touch)
    learned = 0
    last_save = time.time()
    last_evict = time.time()

    mode = "ENFORCE" if args.enforce else "DRY-RUN"
    logging.info("started mode=%s backend=%s window=%.0fs block>=%.2f watch>=%.2f",
                 mode, args.backend, args.window, args.block_threshold, args.watch_threshold)

    for line in tail(args.log, from_start=args.from_start):
        ev = parse_line(line)
        if not ev:
            continue
        ip = ev["ip"]

        w = windows.get(ip)
        if w is None:
            w = windows[ip] = IPWindow()
            if len(windows) > args.max_ips:
                windows.popitem(last=False)
        else:
            windows.move_to_end(ip)
        w.add(ev, args.window)

        x, hard = w.features()
        if x is None:
            continue

        # Score with the current model, then learn the point (score-then-learn).
        score = model.score_one(x)
        model.learn_one(x)
        learned += 1

        # Don't act during warmup or on too-thin windows.
        if learned < args.warmup or len(w.events) < args.min_events:
            continue
        if allow.allows(ip):
            continue
        if ev["ts"] - w.last_action < args.cooldown:
            continue

        if hard or score >= args.block_threshold:
            reason = "hard-signal+multistage" if hard else f"anomaly={score:.3f}"
            blocker.block(ip, score, reason)
            w.last_action = ev["ts"]
        elif score >= args.watch_threshold:
            logging.info("WATCH ip=%s score=%.3f miss=%.2f auth=%.2f probe=%.2f persist=%.2f",
                         ip, score, x["miss_ratio"], x["auth_ratio"],
                         x["probe_ratio"], x["persistence"])
            w.last_action = ev["ts"]

        # Periodic housekeeping: checkpoint + evict idle IPs to bound memory.
        now = time.time()
        if args.state and now - last_save > 60:
            try:
                save_state(model, args.state)
                last_save = now
            except Exception as e:  # noqa: BLE001
                logging.error("state save failed: %s", e)
        if now - last_evict > 60:
            dead = [k for k, v in windows.items()
                    if not v.events or now - v.events[-1]["ts"] > args.idle_evict]
            for k in dead:
                del windows[k]
            last_evict = now


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
