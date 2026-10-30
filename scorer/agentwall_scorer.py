#!/usr/bin/env python3
# =============================================================================
# agentwall_scorer.py  — scale-aware successor to agentwall_scorer_v1.py
# -----------------------------------------------------------------------------
# Built for "millions of requests from many IPs, mostly normal visitors". The
# core idea: DO NOT use volume as a signal. A flash crowd is many IPs each still
# behaving like a human. A scanner is an IP whose *session shape* is non-human,
# whatever its request count. So every decision is per-IP SHAPE, scored RELATIVE
# to the current population, and gated by a human-ness score so real users are
# protected even at the top percentile.
#
# Design points:
#   1. Real client IP (XFF) + good-bot verification (FCrDNS: Googlebot/Bingbot/...)
#      with a bounded timeout so DNS cannot stall the scoring loop.
#   2. Population-relative scoring: an IP is flagged only if it is an outlier
#      vs all IPs right now (rolling P99/P95), not a fixed threshold. A flash
#      crowd lifts the whole distribution, so the relative cutoff adapts and the
#      crowd does not trip it. Absolute floors stop a quiet period from flagging
#      mildly-odd benign IPs.
#   3. Human-ness features: static-asset loading, Referer presence, browser vs
#      tool UA. Browsers pull CSS/JS and navigate with referers; scanners don't.
#      `--profile api` re-weights them for JSON-only services.
#   4. Challenge-first + bounded LRU memory: suspicious -> challenge (verified
#      JS PoW done in nginx-lua), block only on hard signal, on a human-ness
#      floor breach, or if they keep being suspicious after the challenge grace.
#      A successful challenge clears a short Redis key the scorer honours.
#   5. IPv6 sources are aggregated to a /64 network for detection AND for the
#      Redis verdict keys, so rotating within a /64 does not reset suspicion.
#   6. Atomic model checkpoints (tmp + os.replace), guarded load, SIGTERM save.
#   7. Optional Prometheus metrics endpoint (stdlib only) for the runbook's
#      observability requirements.
#
# Still NOT an unbypassable wall: low-and-slow spread across many rotating IPs
# stays under per-IP windows (close that at the SIEM layer), and a wrong
# human-floor can still challenge real users. Run dry-run, baseline, enforce.
#
# For true web-scale, run this on the SUSPICIOUS RESIDUE only: let a cheap tier-1
# (CDN/good-bot allowlist, obvious-normal drop) pass first, feed the rest here.
#
# Usage:
#   python3 agentwall_scorer.py --log /var/log/nginx/agentwall_access.log --use-xff
#   python3 agentwall_scorer.py --log ... --enforce --backend redis
#   python3 agentwall_scorer.py --log ... --metrics-port 9101 --metrics-bind 127.0.0.1
#
# Requires: pip install -r requirements.txt   (redis only for --backend redis/both)
# =============================================================================

from __future__ import annotations

import argparse
import ipaddress
import logging
import math
import os
import pickle
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from urllib.parse import unquote_plus
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from river import anomaly
except ImportError:  # pragma: no cover - dependency check
    sys.exit("river is required: pip install -r requirements.txt")


# --- Defaults / environment --------------------------------------------------
DEFAULT_REDIS_URL = os.environ.get("REDIS_URL") or "redis://127.0.0.1:6379/0"
DEFAULT_FAIL2BAN_CMD = os.environ.get("AGENTWALL_FAIL2BAN_CMD") or "fail2ban-client"

STATE_VERSION = 2


# --- Log parsing -------------------------------------------------------------
# Combined format + optional 'agentwall' tails (ua_flag=/probe=) + optional xff="..."
# The nginx/apache snippets in waf/ write the xff field; without it --use-xff
# cannot recover the client IP and this program warns loudly.
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)?\s*(?P<path>[^"\s]*)[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"'
    r'(?:\s+rt=\S+)?(?:\s+urt=\S+)?'
    r'(?:\s+ua_flag=(?P<ua_flag>\d))?'
    r'(?:\s+probe=(?P<probe>\d))?'
    r'(?:\s+xff="(?P<xff>[^"]*)")?'
)

# Whole path segment only: "/auth", "/auth/callback", "/login.php" match;
# "/authors/jane", "/tokenomics", "/verify-email-preview" do not.
AUTH_RE = re.compile(
    r'/(login|signin|sign-in|auth|oauth|token|verify|otp|mfa|2fa|password/(reset|forgot))'
    r'(?=[/.?;]|$)',
    re.IGNORECASE,
)
STATIC_EXT = {
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map", ".webp", ".avif", ".mp4", ".webm",
}
PROBE_RE = re.compile(
    r'(\.\./|union[\s/*]+select|<script|;\s*drop\s+table|/etc/passwd|\bor\s+1=1)',
    re.IGNORECASE,
)
# Real browsers (rough; spoofable, so weighted low and backed by static-asset signal)
BROWSER_UA_RE = re.compile(r'Mozilla/\d.*(Chrome|Firefox|Safari|Edg|Gecko|Version)/', re.IGNORECASE)
# Automation / scanner clients (strong non-human signal)
TOOL_UA_RE = re.compile(
    r'(curl|wget|python-requests|httpx|aiohttp|go-http-client|okhttp|libwww|java/|'
    r'nikto|sqlmap|nmap|masscan|zgrab|gobuster|feroxbuster|dirb|wpscan|nuclei|scrapy|'
    r'axios|node-fetch|\bbot\b|crawler|spider|'
    r'artex-enrich|artex-selfupdate|norma/|ffuf|fuzz faster u fool|'
    r'nmap scripting engine|dirsearch|wafw00f|arjun|katana|subfinder|naabu|'
    r'gospider|interactsh)',
    re.IGNORECASE,
)
# Good bots that claim an identity we can verify via forward-confirmed reverse DNS
GOODBOT_UA_RE = re.compile(
    r'(Googlebot|APIs-Google|AdsBot-Google|Mediapartners-Google|bingbot|BingPreview|'
    r'Applebot|DuckDuckBot|YandexBot|Baiduspider|facebookexternalhit)',
    re.IGNORECASE,
)
GOODBOT_DOMAINS = (
    ".googlebot.com", ".google.com", ".search.msn.com", ".applebot.apple.com",
    ".crawl.yandex.net", ".crawl.baidu.com", ".duckduckgo.com",
)
MISS_CODES = {400, 404}
DENY_CODES = {401, 403, 429}


# --- IP normalisation --------------------------------------------------------
def canonical_ip(ip):
    """Return the canonical text form of an IP, or None if it is not an IP.

    IPv4-mapped IPv6 (::ffff:1.2.3.4) is reduced to the IPv4 form so the nginx
    Lua layer (which sees the raw socket address) and this scorer agree.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def ip_key(ip, ipv6_prefix=64):
    """Redis/verdict key for an address.

    IPv4 stays a single address; IPv6 is aggregated to ``ipv6_prefix`` bits so
    an attacker rotating inside one /64 shares one suspicion window and one ban.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    if isinstance(addr, ipaddress.IPv6Address) and ipv6_prefix < 128:
        net = ipaddress.ip_network("{}/{}".format(addr, ipv6_prefix), strict=False)
        return str(net.network_address)
    return str(addr)


def is_trusted_ip(ip, trusted_nets):
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in trusted_nets)


def resolve_client_ip(remote_ip, xff, trusted_nets):
    """Resolve the real client from an access-log line.

    The log's first field is already the real client when the edge runs
    ``real_ip``/``mod_remoteip``. When that is not available, XFF must be parsed
    **right-to-left, skipping trusted proxy hops** (the same rule nginx uses
    with ``real_ip_recursive on``). The left-most hop is attacker-controlled and
    must never be trusted.
    """
    peer = canonical_ip(remote_ip)
    if not xff:
        return peer or remote_ip
    trusted_nets = tuple(trusted_nets or ())
    hops = []
    for part in xff.split(","):
        addr = canonical_ip(part.strip())
        if addr is not None:
            hops.append(addr)
    chain = hops + ([peer] if peer else [])
    for candidate in reversed(chain):
        if not is_trusted_ip(candidate, trusted_nets):
            return candidate
    # Every hop (including the socket peer) is a trusted proxy: we cannot see a
    # client address, so fall back to the socket peer rather than guessing.
    return peer or remote_ip


def parse_line(line, use_xff=False, trusted_proxies=None):
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

    ip = g["ip"]
    xff = g.get("xff")
    if use_xff:
        ip = resolve_client_ip(ip, xff, trusted_proxies or ())

    path = g["path"] or ""
    stem = path.split("?", 1)[0]
    ext = os.path.splitext(stem)[1].lower()
    ua = g["ua"] or ""
    ref = g["ref"] or ""
    return {
        "ip": ip,
        "xff": xff,
        "ts": ts,
        "status": status,
        "path": stem,
        "ua": ua,
        "is_auth": bool(AUTH_RE.search(path)),
        "is_static": ext in STATIC_EXT,
        # Probe markers are checked on the raw path AND on a decoded copy: the
        # reverse proxy maps cannot URL-decode, but the scorer can, so encoded
        # traversal/SQLi/XSS probes still raise this signal.
        "is_probe": bool(PROBE_RE.search(path))
        or bool(PROBE_RE.search(unquote_plus(path)))
        or g.get("probe") == "1",
        "ua_flag": g.get("ua_flag") == "1",
        "is_browser": bool(BROWSER_UA_RE.search(ua)),
        "is_tool": bool(TOOL_UA_RE.search(ua)),
        "has_ref": ref not in ("", "-"),
    }


# --- Good-bot verification (FCrDNS), cached and timeout-bounded --------------
class GoodBotVerifier:
    """Verify a claimed good bot via reverse DNS + forward confirmation.

    rDNS is slow, so it runs in a small worker pool with a hard timeout and the
    result is cached per IP (positive longer than negative). A spoofed-Googlebot
    flood therefore cannot stall the scoring loop.
    """

    def __init__(self, ttl=3600.0, negative_ttl=300.0, timeout=0.8, enabled=True,
                 workers=4, max_pending=None, metrics=None):
        self.ttl = ttl
        self.negative_ttl = negative_ttl
        self.timeout = timeout
        self.enabled = enabled
        self.metrics = metrics
        self.cache = {}  # ip -> (bool, expiry)
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="fcrdns")
        # A timed-out .result() does NOT cancel the DNS task, so an attacker
        # flooding distinct IPs with a good-bot UA could otherwise grow the
        # executor queue without bound. Shed new lookups when saturated.
        self._pending = threading.BoundedSemaphore(max_pending or workers * 4)

    def is_good_bot(self, ip, ua):
        if not self.enabled or not GOODBOT_UA_RE.search(ua):
            return False
        now = time.time()
        hit = self.cache.get(ip)
        if hit and hit[1] > now:
            return hit[0]

        if not self._pending.acquire(blocking=False):
            # Saturated: fail closed for verification (treat as not-a-good-bot)
            # and cache the short negative result to avoid a retry storm.
            self.cache[ip] = (False, now + 30.0)
            if self.metrics:
                self.metrics.inc("agentwall_dns_shed_total")
            return False

        ok = False
        try:
            future = self._pool.submit(self._verify, ip)
        except RuntimeError:  # executor shut down
            self._pending.release()
            return False
        future.add_done_callback(lambda _f: self._pending.release())
        try:
            ok = bool(future.result(timeout=self.timeout))
        except FuturesTimeoutError:
            ok = False
            if self.metrics:
                self.metrics.inc("agentwall_dns_timeouts_total")
        except Exception:  # noqa: BLE001 - DNS failures must never break scoring
            ok = False

        self.cache[ip] = (ok, now + (self.ttl if ok else self.negative_ttl))
        if len(self.cache) > 50000:  # bound memory on spoofed-UA floods
            for stale in [k for k, v in self.cache.items() if v[1] <= now]:
                del self.cache[stale]
            if len(self.cache) > 50000:
                self.cache.clear()
        return ok

    @staticmethod
    def _verify(ip):
        try:
            host = socket.gethostbyaddr(ip)[0].lower()
        except (socket.herror, socket.gaierror, OSError):
            return False
        if not host.endswith(GOODBOT_DOMAINS):
            return False
        try:
            addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
        except (socket.gaierror, OSError):
            return False
        return ip in addrs


# --- Per-IP sliding window + feature extraction ------------------------------
class IPWindow:
    __slots__ = ("events", "last_challenge", "last_block", "last_watch", "challenged_at")

    def __init__(self):
        self.events = deque()          # time-ordered event dicts
        self.last_challenge = 0.0      # unix ts of last challenge issued to this key
        self.last_block = 0.0          # unix ts of last block issued to this key
        self.last_watch = 0.0          # unix ts of last WATCH log line
        self.challenged_at = 0.0       # unix ts of the FIRST challenge (0 = none)

    def add(self, ev, window):
        self.events.append(ev)
        cutoff = ev["ts"] - window
        while self.events and self.events[0]["ts"] < cutoff:
            self.events.popleft()

    def features(self):
        """Return (feature dict, signal ratios, hard-signal bool)."""
        evs = self.events
        n = len(evs)
        if n == 0:
            return None, None, False

        miss = sum(1 for e in evs if e["status"] in MISS_CODES)
        deny = sum(1 for e in evs if e["status"] in DENY_CODES)
        auth = sum(1 for e in evs if e["is_auth"])
        static = sum(1 for e in evs if e["is_static"])
        probe = sum(1 for e in evs if e["is_probe"])
        ua_flag = sum(1 for e in evs if e["ua_flag"])
        browser = sum(1 for e in evs if e["is_browser"])
        tool = sum(1 for e in evs if e["is_tool"])
        referer = sum(1 for e in evs if e["has_ref"])

        paths = [e["path"] for e in evs]
        uniq = len(set(paths))
        counts = {}
        for p in paths:
            counts[p] = counts.get(p, 0) + 1
        ent = -sum((c / n) * math.log2(c / n) for c in counts.values())
        ent_norm = ent / math.log2(n) if n > 1 else 0.0

        ts_sorted = sorted(e["ts"] for e in evs)
        deltas = [b - a for a, b in zip(ts_sorted, ts_sorted[1:])]
        if len(deltas) >= 2:
            mean = sum(deltas) / len(deltas)
            var = sum((d - mean) ** 2 for d in deltas) / len(deltas)
            cv = (math.sqrt(var) / mean) if mean > 0 else 0.0
            regularity = 1.0 / (1.0 + cv)
        else:
            regularity = 0.0

        first_deny = next((e["ts"] for e in evs if e["status"] in DENY_CODES), None)
        persistence = (sum(1 for e in evs if e["ts"] > first_deny) / n) if first_deny else 0.0

        has_enum = miss >= 3
        multistage = 1.0 if (has_enum and probe >= 1 and auth >= 1) else 0.0

        stats = {
            "static_ratio": static / n,
            "referer_ratio": referer / n,
            "browser_ratio": browser / n,
            "tool_ratio": tool / n,
            "miss_ratio": miss / n,
            "probe_ratio": probe / n,
        }
        x = {
            "req_rate": min(n / 120.0, 1.0),
            "miss_ratio": stats["miss_ratio"],
            "deny_ratio": deny / n,
            "auth_ratio": auth / n,
            "uniq_ratio": uniq / n,
            "path_entropy": ent_norm,
            "nonstatic_ratio": 1.0 - stats["static_ratio"],
            "probe_ratio": stats["probe_ratio"],
            "regularity": regularity,
            "persistence": persistence,
            "ua_flag_ratio": ua_flag / n,
            "multistage": multistage,
        }
        # Hard signal: trust these regardless of the (possibly cold) model.
        hard = bool(multistage) or ua_flag > 0 or (probe >= 2 and persistence > 0.5)
        return x, stats, hard


# Human-ness weights per site profile. `web` expects browsers pulling assets;
# `api` expects JSON clients (no static, no referer), so it leans on a clean
# response profile instead and penalises tool UAs far less.
HUMAN_WEIGHTS = {
    "web": {"static": 0.45, "referer": 0.25, "browser": 0.20, "clean": 0.10,
            "tool": 0.50, "probe": 0.30},
    "api": {"static": 0.00, "referer": 0.10, "browser": 0.10, "clean": 0.80,
            "tool": 0.20, "probe": 0.30},
}


def humanness(stats, profile="web"):
    """Human-ness score in [0,1]: 1 = behaves like a real client session."""
    w = HUMAN_WEIGHTS.get(profile, HUMAN_WEIGHTS["web"])
    score = (
        w["static"] * stats["static_ratio"]
        + w["referer"] * stats["referer_ratio"]
        + w["browser"] * stats["browser_ratio"]
        + w["clean"] * (1.0 - stats["miss_ratio"])
        - w["tool"] * stats["tool_ratio"]
        - w["probe"] * stats["probe_ratio"]
    )
    return max(0.0, min(1.0, score))


# --- Population-relative quantiles (rolling, cheap) --------------------------
class PopulationQuantiles:
    """Rolling window of recent per-IP suspicion scores. Recomputes the P-cuts
    lazily every N updates so cost stays bounded at scale."""

    def __init__(self, window=4000, recompute_every=200, qs=(0.95, 0.99)):
        self.buf = deque(maxlen=window)
        self.recompute_every = recompute_every
        self.qs = qs
        self._since = 0
        self._cache = {q: None for q in qs}

    def update(self, x):
        self.buf.append(x)
        self._since += 1

    def get(self, q):
        if self._since >= self.recompute_every or q not in self._cache or self._cache[q] is None:
            self._recompute()
        return self._cache.get(q)

    def _recompute(self):
        self._since = 0
        if not self.buf:
            for q in self.qs:
                self._cache[q] = None
            return
        s = sorted(self.buf)
        n = len(s)
        for q in self.qs:
            idx = min(n - 1, int(q * n))
            self._cache[q] = s[idx]

    def ready(self, minimum=500):
        return len(self.buf) >= minimum


# --- Metrics (stdlib Prometheus text endpoint) -------------------------------
class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters = {}
        self._gauges = {}

    def inc(self, name, n=1):
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + n

    def set(self, name, value):
        with self._lock:
            self._gauges[name] = value

    @staticmethod
    def _fmt(value):
        return "{:.6f}".format(value) if isinstance(value, float) else str(value)

    def value(self, name, default=None):
        with self._lock:
            return self._gauges.get(name, default)

    def render(self):
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
        lines = []
        for name in sorted(counters):
            lines.append("# TYPE {} counter".format(name))
            lines.append("{} {}".format(name, counters[name]))
        for name in sorted(gauges):
            lines.append("# TYPE {} gauge".format(name))
            lines.append("{} {}".format(name, self._fmt(gauges[name])))
        return "\n".join(lines) + "\n"


def start_metrics_server(metrics, bind, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib naming
            route = self.path.split("?", 1)[0]
            if route == "/metrics":
                body = metrics.render().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif route == "/healthz":
                body = b"ok\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, fmt, *args):  # silence access logging
            return

    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.daemon_threads = True
    thread = threading.Thread(target=httpd.serve_forever, name="agentwall-metrics", daemon=True)
    thread.start()
    return httpd


# --- Action backends ---------------------------------------------------------
class Actioner:
    def __init__(self, args, metrics=None):
        self.backend = args.backend
        self.jail = args.jail
        self.block_ttl = args.block_ttl
        self.challenge_ttl = args.challenge_ttl
        self.enforce = args.enforce
        self.metrics = metrics
        self.redis = None
        self._err_last = {}            # error tag -> last log ts (log rate limit)
        self._f2b_last = {}            # ip key -> last fail2ban call ts
        self._f2b_cmd = [args.fail2ban_cmd]
        if args.fail2ban_sudo:
            self._f2b_cmd = ["sudo", "-n"] + self._f2b_cmd
        if self.backend in ("redis", "both"):
            try:
                import redis
            except ImportError:
                sys.exit("redis backend needs: pip install redis")
            self.redis = redis.Redis.from_url(
                args.redis_url, decode_responses=True, socket_timeout=args.redis_timeout,
                socket_connect_timeout=args.redis_timeout,
            )

    # -- helpers ---------------------------------------------------------
    def _err(self, tag, err):
        now = time.time()
        if now - self._err_last.get(tag, 0.0) > 30.0:
            logging.error("%s failed: %s (suppressing repeats for 30s)", tag, err)
            self._err_last[tag] = now
        if self.metrics:
            self.metrics.inc("agentwall_redis_errors_total" if tag.startswith("redis") else "agentwall_action_errors_total")

    def _redis_set(self, key, ttl):
        try:
            self.redis.set(key, "1", ex=ttl)
            return True
        except Exception as e:  # noqa: BLE001 - redis errors vary
            self._err("redis set " + key.split(":", 2)[1], e)
            return False

    def _redis_del(self, key):
        try:
            self.redis.delete(key)
            return True
        except Exception as e:  # noqa: BLE001
            self._err("redis del " + key.split(":", 2)[1], e)
            return False

    # -- preflight -------------------------------------------------------
    def preflight(self):
        if not self.redis:
            return True
        try:
            self.redis.ping()
            if self.metrics:
                self.metrics.set("agentwall_redis_up", 1)
            logging.info("redis preflight: PONG")
            return True
        except Exception as e:  # noqa: BLE001
            if self.metrics:
                self.metrics.set("agentwall_redis_up", 0)
                self.metrics.inc("agentwall_redis_errors_total")
            logging.critical("redis preflight FAILED: %s -- enforcement will fail OPEN", e)
            return False

    # -- actions ---------------------------------------------------------
    def challenge(self, key, score):
        tag = "CHALLENGE" if self.enforce else "CHALLENGE(dry-run)"
        logging.warning("%s ip_key=%s suspicion=%.3f", tag, key, score)
        if not self.enforce or not self.redis:
            return  # fail2ban/none cannot challenge -> log only
        self._redis_set("agentwall:challenge:" + key, self.challenge_ttl)

    def block(self, key, score, reason, raw_ip=None):
        tag = "BLOCK" if self.enforce else "BLOCK(dry-run)"
        logging.warning("%s ip=%s key=%s suspicion=%.3f reason=%s",
                        tag, raw_ip or key, key, score, reason)
        if not self.enforce:
            return
        if self.backend in ("fail2ban", "both"):
            # fail2ban bans one address: use the raw client address, never the
            # aggregated IPv6 /64 network address (which would ban almost nobody).
            self._fail2ban(raw_ip or key)
        if self.backend in ("redis", "both"):
            self._redis_set("agentwall:block:" + key, self.block_ttl)
            self._redis_del("agentwall:challenge:" + key)

    def _fail2ban(self, key):
        now = time.time()
        if now - self._f2b_last.get(key, 0.0) < 60.0:
            return  # debounce: one subprocess per IP per minute, even if re-triggered
        self._f2b_last[key] = now
        if len(self._f2b_last) > 50000:
            self._f2b_last.clear()
        try:
            subprocess.run(
                self._f2b_cmd + ["set", self.jail, "banip", key],
                check=True, capture_output=True, timeout=5,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            if self.metrics:
                self.metrics.inc("agentwall_fail2ban_errors_total")
            logging.error("fail2ban ban failed key=%s err=%s", key, e)

    def is_cleared(self, key):
        """True when the client passed the JS challenge (nginx-lua wrote the key)."""
        if not self.redis:
            return False
        try:
            return bool(self.redis.exists("agentwall:cleared:" + key))
        except Exception as e:  # noqa: BLE001
            self._err("redis exists cleared", e)
            return False

    def is_headless(self, key):
        """True when the Lua layer detected headless/automation behaviour."""
        if not self.redis:
            return False
        try:
            return bool(self.redis.exists("agentwall:headless:" + key))
        except Exception as e:  # noqa: BLE001
            self._err("redis exists headless", e)
            return False


class Allowlist:
    def __init__(self, cidrs):
        self.nets = []
        for c in cidrs:
            c = (c or "").strip()
            if not c:
                continue
            try:
                self.nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                logging.error("invalid allowlist entry: %s", c)

    def allows(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            return False
        return any(addr in net for net in self.nets)


# --- State persistence (atomic, guarded) -------------------------------------
def _secure_state_dir(path):
    """Create/validate the state directory and warn if it is group/other writable.

    The checkpoint is a pickle (deserialisation = code execution). The state
    directory must be owned by the scorer user and not writable by anyone else;
    the file is written 0600. This is a defence-in-depth check, not a sandbox.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        st = os.stat(directory)
        if st.st_mode & 0o077:
            logging.warning("state directory %s is group/other accessible (mode %o); "
                            "the pickle checkpoint is code-executable -- set it to 0700",
                            directory, st.st_mode & 0o777)
        if st.st_uid != os.getuid():
            logging.warning("state directory %s is owned by uid %s, not the scorer uid %s",
                            directory, st.st_uid, os.getuid())
    except OSError:
        pass
    return directory


def save_state(model, path):
    """Write the model checkpoint atomically (tmp file + os.replace, mode 0600)."""
    _secure_state_dir(path)
    tmp = "{}.tmp.{}".format(path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        pickle.dump({"version": STATE_VERSION, "model": model}, fh,
                    protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def load_state(path):
    """Load a checkpoint; return None (fresh model) instead of crashing.

    Refuses symlinks (a symlink could redirect the pickle load elsewhere) and
    warns when the file/directory permissions are too open. Pickle loads are
    code execution, so the state path must be trusted and 0700/0600.
    """
    if not path or not os.path.exists(path):
        return None
    if os.path.islink(path):
        logging.error("refusing to load state %s: it is a symlink", path)
        return None
    try:
        st = os.stat(path)
        if st.st_mode & 0o077:
            logging.warning("state file %s is group/other accessible (mode %o); "
                            "set it to 0600", path, st.st_mode & 0o777)
    except OSError:
        pass
    try:
        with open(path, "rb") as fh:
            blob = pickle.load(fh)
        if isinstance(blob, dict) and "model" in blob:
            return blob["model"]
        return blob  # legacy checkpoint: a bare model object
    except Exception as e:  # noqa: BLE001 - a corrupt state must not stop the service
        logging.error("could not load state %s: %s -- starting from a fresh model", path, e)
        return None


# --- Log readers -------------------------------------------------------------
def read_once(path):
    """Yield every line of the file, then stop (batch mode; no tailing)."""
    with open(path, "r", errors="replace") as fh:
        for line in fh:
            yield line


def _open_log(path, sleep=time.sleep):
    """Open the access log, waiting (never crashing) while it is missing or unreadable.

    logrotate recreates the file (``create 0640 root adm``); a scorer that is not
    in the log's group used to die with PermissionError on the first reopen and
    crash-loop, silently ending enforcement. Keep retrying and say why, loudly.
    """
    last_log = 0.0
    while True:
        try:
            return open(path, "r", errors="replace")
        except FileNotFoundError:
            reason = "waiting for log file"
            level = logging.INFO
        except PermissionError:
            reason = ("cannot read log file (permission denied) -- run the scorer in the "
                      "log's group (systemd: SupplementaryGroups=adm; docker: group_add)")
            level = logging.ERROR
        now = time.time()
        if now - last_log >= 30.0:
            logging.log(level, "%s: %s (retrying)", reason, path)
            last_log = now
        sleep(1)


def tail(path, from_start=False):
    f = _open_log(path)
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
            st = os.stat(path)
        except OSError:
            time.sleep(1)
            continue
        if st.st_ino != inode or st.st_size < f.tell():
            f.close()
            f = _open_log(path)
            inode = os.fstat(f.fileno()).st_ino


# --- Decision (pure, unit-testable) ------------------------------------------
def decide(window, *, suspicion, humanness_score, hard, now, cooldown, grace,
           block_cut, watch_cut, human_floor):
    """Return "block", "challenge", "watch" or None for one event.

    Ordering matters:
      * hard signal bypasses the population cutoffs and the human-ness floor,
        but NOT the block cooldown (bounds fail2ban subprocess churn).
      * human-ness floor protects the flash crowd from percentile-only blocks.
      * a challenged key escalates to a block once ``grace`` seconds have
        passed, independently of the (shorter) challenge cooldown.
    """
    if hard:
        return "block" if now - window.last_block >= cooldown else None
    if humanness_score >= human_floor:
        return None
    if suspicion >= block_cut:
        if window.challenged_at and now - window.challenged_at >= grace:
            return "block" if now - window.last_block >= cooldown else None
        return "challenge" if now - window.last_challenge >= cooldown else None
    if suspicion >= watch_cut and now - window.last_watch >= cooldown:
        return "watch"
    return None


def population_eligible(humanness_score, hard, human_floor):
    """Only human-like, non-hard events may shape the population percentile.

    This is the fix for percentile poisoning: a burst of high-scoring attack
    events must not raise the P99 used to challenge quieter families. Human-like
    traffic (including a flash crowd) still calibrates the population; explicit
    automation/hard signals are excluded.
    """
    return (not hard) and humanness_score >= human_floor


def compute_suspicion(x, humanness_score, anomaly_score):
    base = anomaly_score * (1.0 - humanness_score)
    boost = (0.30 * x["persistence"] + 0.30 * x["probe_ratio"]
             + 0.20 * x["miss_ratio"] + 0.20 * x["multistage"])
    return max(0.0, min(1.0, 0.6 * base + 0.4 * boost))


# --- CLI ---------------------------------------------------------------------
def build_argparser():
    ap = argparse.ArgumentParser(description="Scale-aware ML blocker for autonomous LLM/AI pentest agents")
    ap.add_argument("--log", required=True)
    ap.add_argument("--from-start", action="store_true",
                    help="start at the beginning of the log instead of the end")
    ap.add_argument("--once", action="store_true",
                    help="process the log from the beginning to EOF once, then exit "
                         "(batch backfill / benchmarking; implies --from-start)")
    ap.add_argument("--use-xff", action="store_true",
                    help="resolve the client from X-Forwarded-For; REQUIRES --trust-proxies. "
                         "Do NOT use when nginx real_ip/mod_remoteip already rewrites the "
                         "first log field (the default topology)")
    ap.add_argument("--trust-proxies", default=os.environ.get("AGENTWALL_TRUSTED_PROXIES", ""),
                    help="comma-separated CIDRs of your own edge proxies for --use-xff; XFF is "
                         "walked right-to-left skipping these hops (the left-most value is never trusted)")
    ap.add_argument("--window", type=float, default=60.0, help="per-IP window seconds")
    ap.add_argument("--min-events", type=int, default=12, help="min events before acting on an IP")
    ap.add_argument("--warmup", type=int, default=800, help="events learned before any action")
    # HST sizing: cost/memory scale with n_trees * 2**height, so the old
    # 25/15 defaults (~1.6M nodes, ~500 MB, <500 events/s) were not production
    # grade. River's defaults (10/8/250) are the starting point; raise height
    # only after measuring, and expect roughly x2 cost per +1 height.
    ap.add_argument("--hst-trees", type=int, default=10,
                    help="HalfSpaceTrees n_trees (default: %(default)s)")
    ap.add_argument("--hst-height", type=int, default=8,
                    help="HalfSpaceTrees height; memory/time scale with 2**height (default: %(default)s)")
    ap.add_argument("--hst-window", type=int, default=250,
                    help="HalfSpaceTrees window_size before mass pivoting (default: %(default)s)")
    ap.add_argument("--p-block", type=float, default=0.99, help="population percentile for block")
    ap.add_argument("--p-watch", type=float, default=0.95, help="population percentile for challenge/watch")
    ap.add_argument("--pop-window", type=int, default=4000, help="rolling IP-scores kept for percentiles")
    ap.add_argument("--floor-block", type=float, default=0.55)
    ap.add_argument("--floor-watch", type=float, default=0.40)
    ap.add_argument("--human-floor", type=float, default=0.55,
                    help="never block an IP at/above this human-ness, whatever the percentile")
    ap.add_argument("--profile", choices=["web", "api"], default="web",
                    help="human-ness weighting profile (web pages vs JSON APIs)")
    ap.add_argument("--challenge-grace", type=float, default=120.0,
                    help="seconds after the first challenge before escalating to a block")
    ap.add_argument("--cooldown", type=float, default=120.0,
                    help="seconds between challenge/block/watch actions on one key")
    ap.add_argument("--enforce", action="store_true", help="actually act (default: dry-run)")
    ap.add_argument("--headless-mode", choices=["mark", "block"],
                    default=(os.environ.get("AGENTWALL_HEADLESS_MODE") or "mark").strip().lower(),
                    help="what the scorer does with the Lua agentwall:headless marker: 'mark' "
                         "(default) only logs/counts it, 'block' hard-blocks challenged keys. "
                         "Keep it equal to the edge's AGENTWALL_HEADLESS_MODE")
    ap.add_argument("--dry-run", action="store_true", help="explicit dry-run (the default)")
    ap.add_argument("--backend", choices=["none", "fail2ban", "redis", "both"], default="none")
    ap.add_argument("--jail", default="agentwall-ml")
    ap.add_argument("--fail2ban-cmd", default=DEFAULT_FAIL2BAN_CMD,
                    help="fail2ban-client path (default: %(default)s)")
    ap.add_argument("--fail2ban-sudo", action="store_true",
                    help="run fail2ban-client through 'sudo -n' (see deploy/sudoers.d-agentwall)")
    ap.add_argument("--redis-url", default=DEFAULT_REDIS_URL,
                    help="default: $REDIS_URL or redis://127.0.0.1:6379/0")
    ap.add_argument("--redis-timeout", type=float, default=1.0)
    ap.add_argument("--block-ttl", type=int, default=1800)
    ap.add_argument("--challenge-ttl", type=int, default=600)
    ap.add_argument("--no-verify-bots", action="store_true", help="disable FCrDNS good-bot verification")
    ap.add_argument("--dns-timeout", type=float, default=0.8, help="FCrDNS lookup budget seconds")
    ap.add_argument("--allowlist", default="127.0.0.1/32,::1/128")
    ap.add_argument("--allowlist-file")
    ap.add_argument("--ipv6-prefix", type=int, default=64,
                    help="IPv6 aggregation prefix for windows and bans (128 = exact address)")
    ap.add_argument("--max-ips", type=int, default=200000, help="LRU cap on tracked keys (bounds memory)")
    ap.add_argument("--idle-evict", type=float, default=600.0)
    ap.add_argument("--state", help="model checkpoint path (atomic save, guarded load)")
    ap.add_argument("--metrics-port", type=int, default=0, help="Prometheus /metrics port (0 = off)")
    ap.add_argument("--metrics-bind", default="127.0.0.1")
    ap.add_argument("--log-level", default="INFO")
    return ap


def parse_trusted_proxies(raw):
    """Parse a comma-separated CIDR list; raises ValueError on a bad entry."""
    nets = []
    for part in (raw or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise ValueError("invalid --trust-proxies entry: {}".format(part))
    return nets


def validate_args(args):
    """Return a list of configuration errors (the caller turns them into usage errors)."""
    errors = []
    if args.enforce and args.dry_run:
        errors.append("--enforce and --dry-run are mutually exclusive")
    if args.headless_mode not in ("mark", "block"):
        errors.append("--headless-mode / AGENTWALL_HEADLESS_MODE must be 'mark' or 'block'")
    if args.enforce and args.backend == "none":
        errors.append("--enforce requires --backend redis, fail2ban or both")
    if args.use_xff:
        if not (args.trust_proxies or "").strip():
            errors.append("--use-xff requires --trust-proxies (CIDRs of your edge proxies); "
                          "with real_ip configured, drop --use-xff entirely")
        else:
            try:
                parse_trusted_proxies(args.trust_proxies)
            except ValueError as exc:
                errors.append(str(exc))
    if args.window <= 0:
        errors.append("--window must be > 0")
    if args.min_events < 1:
        errors.append("--min-events must be >= 1")
    if args.warmup < 0:
        errors.append("--warmup must be >= 0")
    for name in ("p_block", "p_watch", "floor_block", "floor_watch", "human_floor"):
        value = getattr(args, name)
        if not 0.0 <= value <= 1.0:
            errors.append("--{} must be within [0,1]".format(name.replace("_", "-")))
    if args.p_block <= args.p_watch:
        errors.append("--p-block must be greater than --p-watch")
    if args.challenge_grace <= 0:
        errors.append("--challenge-grace must be > 0")
    if args.cooldown < 0:
        errors.append("--cooldown must be >= 0")
    if not 0 <= args.ipv6_prefix <= 128:
        errors.append("--ipv6-prefix must be within [0,128]")
    if args.max_ips < 1:
        errors.append("--max-ips must be >= 1")
    if args.hst_trees < 1:
        errors.append("--hst-trees must be >= 1")
    if not 1 <= args.hst_height <= 20:
        errors.append("--hst-height must be within [1,20]")
    if args.hst_window < 10:
        errors.append("--hst-window must be >= 10")
    if args.metrics_port and not 0 <= args.metrics_port <= 65535:
        errors.append("--metrics-port must be within [0,65535]")
    if args.redis_timeout <= 0:
        errors.append("--redis-timeout must be > 0")
    if args.dns_timeout <= 0:
        errors.append("--dns-timeout must be > 0")
    if args.block_ttl < 1 or args.challenge_ttl < 1:
        errors.append("--block-ttl and --challenge-ttl must be >= 1")
    return errors


# --- Main loop ---------------------------------------------------------------
def housekeep(windows, model, args, last_save, last_evict, metrics):
    now = time.time()
    if args.state and now - last_save > 60:
        try:
            save_state(model, args.state)
            last_save = now
            metrics.inc("agentwall_state_saves_total")
        except Exception as e:  # noqa: BLE001
            logging.error("state save failed: %s", e)
            metrics.inc("agentwall_state_save_errors_total")
    if now - last_evict > 60:
        dead = [k for k, v in windows.items()
                if not v.events or now - v.events[-1]["ts"] > args.idle_evict]
        for k in dead:
            del windows[k]
        metrics.set("agentwall_tracked_ips", len(windows))
        last_evict = now
    return last_save, last_evict


def main(argv=None):
    ap = build_argparser()
    args = ap.parse_args(argv)
    errors = validate_args(args)
    if errors:
        ap.error("; ".join(errors))

    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO),
                        format="%(asctime)s %(levelname)s %(message)s")

    metrics = Metrics()
    cidrs = [c for c in args.allowlist.split(",")]
    if args.allowlist_file and os.path.exists(args.allowlist_file):
        with open(args.allowlist_file) as fh:
            cidrs += fh.read().splitlines()
    allow = Allowlist(cidrs)
    trusted_proxies = parse_trusted_proxies(args.trust_proxies) if args.use_xff else []
    act = Actioner(args, metrics=metrics)
    verifier = GoodBotVerifier(enabled=not args.no_verify_bots,
                               timeout=args.dns_timeout, metrics=metrics)
    pop = PopulationQuantiles(window=args.pop_window, qs=(args.p_watch, args.p_block))

    model = load_state(args.state)
    if model is not None:
        logging.info("loaded model state: %s", args.state)
        loaded_hst = (getattr(model, "n_trees", None), getattr(model, "height", None),
                      getattr(model, "window_size", None))
        wanted_hst = (args.hst_trees, args.hst_height, args.hst_window)
        if loaded_hst != wanted_hst:
            logging.warning(
                "state was trained with HST (n_trees,height,window)=%s but the current flags "
                "imply %s; delete %s to retrain with the new geometry",
                loaded_hst, wanted_hst, args.state)
        metrics.inc("agentwall_state_loads_total")
    else:
        if args.state and os.path.exists(args.state):
            metrics.inc("agentwall_state_load_failures_total")
        model = anomaly.HalfSpaceTrees(
            n_trees=args.hst_trees, height=args.hst_height,
            window_size=args.hst_window, seed=42,
        )

    windows = OrderedDict()   # ip_key -> IPWindow (LRU: move_to_end on touch)
    learned = 0
    last_save = time.time()
    last_evict = time.time()
    parsed = 0
    xff_seen = 0
    xff_warned = False

    mode = "ENFORCE" if args.enforce else "DRY-RUN"
    if args.enforce and args.headless_mode == "mark":
        logging.info("headless marker policy: mark (logged, not blocked); set "
                     "--headless-mode block / AGENTWALL_HEADLESS_MODE=block to enforce it")
    metrics.set("agentwall_warmup_done", 0)
    if act.redis is not None:
        metrics.set("agentwall_redis_up", 1)
    logging.info(
        "started mode=%s backend=%s window=%.0fs p_block=%.3f p_watch=%.3f "
        "human_floor=%.2f profile=%s ipv6_prefix=%d max_ips=%d",
        mode, args.backend, args.window, args.p_block, args.p_watch,
        args.human_floor, args.profile, args.ipv6_prefix, args.max_ips,
    )
    if args.use_xff:
        logging.info("--use-xff enabled with %d trusted proxy range(s): resolving the "
                     "right-most untrusted XFF hop (left-most is never trusted)",
                     len(trusted_proxies))
    else:
        logging.info("using the access log's first field as the client IP; this is correct "
                     "when nginx real_ip/mod_remoteip rewrites it")
    if act.enforce and not act.preflight():
        logging.critical("enforcement backend is unreachable; verdicts will be lost until it recovers")

    if args.metrics_port:
        try:
            start_metrics_server(metrics, args.metrics_bind, args.metrics_port)
            logging.info("metrics listening on http://%s:%d/metrics", args.metrics_bind, args.metrics_port)
        except OSError as e:
            logging.error("could not start metrics server on %s:%d: %s",
                          args.metrics_bind, args.metrics_port, e)

    def _term(signum, frame):  # noqa: ARG001 - signal handler signature
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _term)

    def _stream():
        if args.once:
            if not os.path.exists(args.log):
                raise SystemExit("--once requires the log file to exist: {}".format(args.log))
            return read_once(args.log)
        return tail(args.log, from_start=args.from_start or args.once)

    try:
        for line in _stream():
            ev = parse_line(line, use_xff=args.use_xff, trusted_proxies=trusted_proxies)
            metrics.inc("agentwall_events_total")
            parsed += 1
            if ev is None:
                metrics.inc("agentwall_parse_errors_total")
                continue
            if ev["xff"]:
                xff_seen += 1
            elif args.use_xff and not xff_warned and parsed >= 1000 and xff_seen == 0:
                xff_warned = True
                logging.error("--use-xff is set but no xff= field was found in the first 1000 "
                              "log lines: the log_format does not include "
                              'xff="$http_x_forwarded_for" -- client IPs are NOT being recovered')
                metrics.inc("agentwall_xff_missing_warnings_total")

            ip = ev["ip"]
            if allow.allows(ip):
                metrics.inc("agentwall_allowlisted_total")
                continue
            if verifier.is_good_bot(ip, ev["ua"]):
                metrics.inc("agentwall_goodbot_total")
                continue

            key = ip_key(ip, args.ipv6_prefix) or ip
            w = windows.get(key)
            if w is None:
                w = IPWindow()
                windows[key] = w
                if len(windows) > args.max_ips:
                    windows.popitem(last=False)
                    metrics.inc("agentwall_evicted_total")
            else:
                windows.move_to_end(key)
            w.add(ev, args.window)

            x, stats, hard = w.features()
            if x is None:
                continue

            anomaly_score = model.score_one(x)
            learned += 1
            metrics.inc("agentwall_learned_total")

            human = humanness(stats, args.profile)
            suspicion = compute_suspicion(x, human, anomaly_score)
            # Attack events must not poison the model or the population
            # percentile. Only human-like, non-hard keys update the HST and
            # P95/P99; the rest are still scored and can be blocked by hard
            # signals/absolute floors. Without this, an attacker can teach the
            # online model that its own traffic is normal (training poisoning).
            if population_eligible(human, hard, args.human_floor):
                model.learn_one(x)
                pop.update(suspicion)
            metrics.set("agentwall_tracked_ips", len(windows))
            metrics.set("agentwall_pop_size", len(pop.buf))
            if learned >= args.warmup and not metrics.value("agentwall_warmup_done"):
                metrics.set("agentwall_warmup_done", 1)
                logging.info("warmup complete after %d learned events", learned)

            last_save, last_evict = housekeep(windows, model, args, last_save, last_evict, metrics)

            if learned < args.warmup or len(w.events) < args.min_events:
                continue

            # Headless/automation marker written by the Lua human-verification
            # step: a solved PoW or a clearance cookie does not excuse it -- but
            # only in headless block mode. In mark mode (the shadow default) the
            # marker is counted/logged and the key goes through the normal
            # decision path, matching the edge's AGENTWALL_HEADLESS_MODE=mark.
            if act.enforce and w.challenged_at and act.is_headless(key):
                metrics.inc("agentwall_headless_total")
                if args.headless_mode == "block":
                    if ev["ts"] - w.last_block >= args.cooldown:
                        act.block(key, suspicion, "headless-automation-detected", raw_ip=ip)
                        w.last_block = ev["ts"]
                        w.challenged_at = 0.0
                        metrics.inc("agentwall_block_total")
                    continue
                if ev["ts"] - w.last_watch >= args.cooldown:
                    logging.warning("HEADLESS(mark) ip=%s key=%s suspicion=%.3f -- not blocked "
                                    "(--headless-mode=mark)", ip, key, suspicion)
                    w.last_watch = ev["ts"]
                    metrics.inc("agentwall_headless_marked_total")

            # A client that passed the verified JS challenge gets a pass unless
            # the hard signal says otherwise (a solved PoW does not excuse a probe).
            if act.enforce and w.challenged_at and act.is_cleared(key):
                if w.challenged_at:
                    w.challenged_at = 0.0
                    metrics.inc("agentwall_cleared_total")
                if not hard:
                    continue

            if pop.ready():
                p_block = pop.get(args.p_block)
                p_watch = pop.get(args.p_watch)
                block_cut = max(args.floor_block, p_block if p_block is not None else args.floor_block)
                watch_cut = max(args.floor_watch, p_watch if p_watch is not None else args.floor_watch)
            else:
                block_cut, watch_cut = args.floor_block, args.floor_watch
            metrics.set("agentwall_block_cut", block_cut)
            metrics.set("agentwall_watch_cut", watch_cut)

            action = decide(
                w,
                suspicion=suspicion,
                humanness_score=human,
                hard=hard,
                now=ev["ts"],
                cooldown=args.cooldown,
                grace=args.challenge_grace,
                block_cut=block_cut,
                watch_cut=watch_cut,
                human_floor=args.human_floor,
            )
            if action == "block":
                reason = "hard-signal(multistage/ua/probe)" if hard else \
                    "anomaly>=p{:.0f}".format(args.p_block * 100)
                act.block(key, suspicion, reason, raw_ip=ip)
                w.last_block = ev["ts"]
                w.challenged_at = 0.0
                metrics.inc("agentwall_block_total")
                if hard:
                    metrics.inc("agentwall_hard_block_total")
            elif action == "challenge":
                act.challenge(key, suspicion)
                w.last_challenge = ev["ts"]
                if not w.challenged_at:
                    w.challenged_at = ev["ts"]
                metrics.inc("agentwall_challenge_total")
            elif action == "watch":
                logging.info(
                    "WATCH ip=%s key=%s suspicion=%.3f human=%.2f miss=%.2f "
                    "probe=%.2f persist=%.2f",
                    ip, key, suspicion, human, x["miss_ratio"],
                    x["probe_ratio"], x["persistence"],
                )
                w.last_watch = ev["ts"]
                metrics.inc("agentwall_watch_total")
    except KeyboardInterrupt:
        pass
    finally:
        if args.once:
            logging.info("end of log reached (--once); processed=%d events learned=%d",
                         parsed, learned)
        if args.state:
            try:
                save_state(model, args.state)
                logging.info("saved model state on shutdown: %s", args.state)
            except Exception as e:  # noqa: BLE001
                logging.error("final state save failed: %s", e)


if __name__ == "__main__":
    main()
