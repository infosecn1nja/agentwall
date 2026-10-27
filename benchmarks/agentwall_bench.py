#!/usr/bin/env python3
"""AgentWall controlled evaluation.

Compares four detection strategies on a synthetic but reproducible access-log
stream with ground-truth labels:

  * waf-only         static UA/marker filter + per-IP rate/4xx threshold
  * anomaly-only     HalfSpaceTrees score with a fixed threshold (no human floor,
                     no population quantiles, no hard signals)
  * challenge-only   JS challenge served to every new key (JS-capable clients
                     pass; HTTP tools fail; headless reports are verified)
  * agentwall-full   the shipped pipeline: HST + human-ness + population
                     quantiles + hard signals + targeted challenge/headless
                     verification
  * union-naive      OR of waf-only / anomaly-only / challenge-only (the
                     "sum of parts" baseline)
  * ablations        full without human floor / without hard signals / without
                     headless verification

Outputs Markdown + JSON to benchmarks/ and prints a summary. Run with the real
river dependency:

    python3 -m venv .venv && . .venv/bin/activate
    pip install -r requirements.txt
    python benchmarks/agentwall_bench.py
"""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import random
import re
import statistics
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("agentwall_scorer", ROOT / "scorer" / "agentwall_scorer.py")
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)

SEED = int(os.environ.get("BENCH_SEED", "20261028"))
RNG = random.Random(SEED)              # evaluation stream
BASE_RNG = random.Random(SEED + 1000)  # model training stream (held out from eval)
WINDOW = 60.0
MIN_EVENTS = 12
BASE_TS = 1_800_000_000

BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
SCANNER_UA = "nuclei/v3.3.0"
ARTEX_UA = "norma/0.4"


def event(ip, ts, path, status=200, ua=BROWSER_UA, is_auth=False,
          is_static=False, is_probe=False, ua_flag=False, is_browser=True,
          is_tool=False, has_ref=True, probe_raw=None):
    return {
        "ip": ip, "ts": ts, "status": status, "path": path,
        "is_auth": is_auth, "is_static": is_static, "is_probe": is_probe,
        "ua_flag": ua_flag, "is_browser": is_browser, "is_tool": is_tool,
        "has_ref": has_ref,
        "probe_raw": probe_raw,
    }


# --------------------------------------------------------------------------
# Traffic generation
# --------------------------------------------------------------------------
def benign_baseline():
    out = []
    for k in range(300):
        ip = "10.10.{}.{}".format(k // 250, 1 + k % 250)
        t = BASE_TS + BASE_RNG.uniform(0, 600)
        for j in range(20):
            static = j % 3 == 0
            out.append(event(
                ip, t + j * RNG.uniform(2.0, 12.0),
                "/static/app.js" if static else "/page/{}".format(j % 5),
                200, is_static=static, has_ref=not static,
            ))
    return out


def benign_browser(prefix):
    out = []
    for k in range(250):
        ip = "192.0.2.{}".format(1 + k % 250)
        t = BASE_TS + 1_000 + RNG.uniform(0, 300)
        for j in range(12):
            static = j % 3 == 0
            out.append(event(
                ip, t + j * RNG.uniform(3.0, 15.0),
                "/static/x.js" if static else "/catalog/{}".format(j % 4),
                200, is_static=static, has_ref=not static,
            ))
    return out


def benign_flash_crowd():
    """High-volume but human-like: static assets, referers, normal pacing."""
    out = []
    for k in range(500):
        ip = "198.51.100.{}".format(1 + k % 250) if k < 250 else "198.51.101.{}".format(1 + k % 250)
        t = BASE_TS + 1_200 + RNG.uniform(0, 20)
        for j in range(60):
            static = j % 2 == 0
            out.append(event(
                ip, t + j * RNG.uniform(0.35, 0.8),
                "/static/hero.png" if static else "/sales",
                200, is_static=static, has_ref=not static,
            ))
    return out


def benign_power_users():
    """Legitimate power users: high rate, many unique pages, assets/referers."""
    out = []
    for k in range(120):
        ip = "198.18.3.{}".format(1 + k)
        t = BASE_TS + 1_350 + RNG.uniform(0, 30)
        for j in range(45):
            static = j % 3 == 0
            out.append(event(
                ip, t + j * RNG.uniform(0.6, 1.2),
                "/static/z.css" if static else "/orders/{}".format(j),
                200, is_static=static, has_ref=not static,
            ))
    return out


def benign_api():
    """Legitimate HTTP API clients: no JS, no browser markers, 10 requests."""
    out = []
    for k in range(100):
        ip = "172.20.{}.{}".format(k // 200, 1 + k % 200)
        t = BASE_TS + 1_380 + RNG.uniform(0, 60)
        for j in range(10):
            out.append(event(ip, t + j * RNG.uniform(2.0, 5.0),
                             "/api/v1/items/{}".format(j), 200,
                             "python-httpx/0.27.2", is_browser=False,
                             is_tool=False, has_ref=False))
    return out


def agentic_encoded_probe():
    """Encoded probes the raw WAF map cannot see; the scorer decodes them."""
    out = []
    for k in range(20):
        ip = "198.18.4.{}".format(10 + k)
        t = BASE_TS + 2_000 + RNG.uniform(0, 40)
        for j in range(20):
            if j < 10:
                path, status, probe = "/x{}".format(j), 404, False
            elif j < 16:
                path, status, probe = "/s?q=%27%20OR%201%3D1", 404, True
            else:
                path, status, probe = "/login", 401, True
            out.append(event(ip, t + j * RNG.uniform(1.5, 3.5), path, status,
                             "custom-agent/1.0", is_auth=j >= 16, is_probe=probe,
                             probe_raw=False, is_browser=False, is_tool=True,
                             has_ref=False))
    return out


def scanner_fast():
    out = []
    for k in range(20):
        ip = "203.0.113.{}".format(10 + k)
        t = BASE_TS + 1_500 + RNG.uniform(0, 30)
        for j in range(35):
            path = "/x{}".format(j)
            out.append(event(ip, t + j * 0.4, path, 404, SCANNER_UA,
                             is_browser=False, is_tool=True, has_ref=False,
                             is_probe=j % 5 == 0))
    return out


def agentic_http():
    """HTTP-only agent: enumerate -> probe -> auth, persistence past errors."""
    out = []
    for k in range(25):
        ip = "203.0.113.{}".format(60 + k)
        t = BASE_TS + 1_700 + RNG.uniform(0, 60)
        ua = ARTEX_UA if k % 2 else "custom-agent/1.0"
        for j in range(30):
            if j < 14:
                path, status, auth, probe = "/api/{}".format(j), 404, False, False
            elif j < 20:
                path, status, auth, probe = "/search?q=union+select", 404, False, True
            else:
                path, status, auth, probe = "/login", 401, True, False
            out.append(event(ip, t + j * RNG.uniform(1.5, 4.0), path, status, ua,
                             is_auth=auth, is_probe=probe, is_browser=False,
                             is_tool=True, has_ref=False))
    return out


def agentic_stealth():
    """Browser-like UA, slow, no probe markers: WAF misses; ML must catch."""
    out = []
    for k in range(25):
        ip = "198.18.{}.{}".format(k // 200, 10 + k)
        t = BASE_TS + 1_900 + RNG.uniform(0, 120)
        for j in range(25):
            if j < 16:
                path, status = "/admin/{}".format(j), 404
            else:
                path, status = "/api/session", 401
            out.append(event(ip, t + j * RNG.uniform(4.0, 9.0), path, status,
                             BROWSER_UA, is_auth=j >= 16, is_browser=True,
                             is_tool=False, has_ref=False))
    return out


def headless_enumeration(report, subnet):
    out = []
    for k in range(20):
        ip = "198.18.{}.{}".format(subnet, 10 + k)
        t = BASE_TS + 2_100 + RNG.uniform(0, 60)
        for j in range(15):
            if j == 0:
                out.append(event(ip, t, "/login", 401, BROWSER_UA,
                                 is_auth=True, is_browser=True,
                                 is_tool=False, has_ref=False))
            else:
                out.append(event(ip, t + j * RNG.uniform(1.0, 3.0),
                                 "/hidden/{}".format(j), 404, BROWSER_UA,
                                 is_browser=True, is_tool=False, has_ref=False))
    return out


def distributed_low_slow():
    """Four requests per IP, rotating origins: below every per-key threshold."""
    out = []
    for k in range(80):
        ip = "100.64.{}.{}".format(k // 200, 1 + k % 200)
        t = BASE_TS + 2_300 + RNG.uniform(0, 200)
        paths = [("/a", 404, False), ("/b?x=1%27%20or%201%3D1", 404, True),
                 ("/login", 401, True), ("/c", 404, False)]
        for j, (path, status, auth) in enumerate(paths):
            out.append(event(ip, t + j * 7.0, path, status, "agent/2.0",
                             is_auth=auth, is_probe=False,
                             is_browser=False, is_tool=True, has_ref=False))
    return out


# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------
class WafOnly:
    name = "waf-only"

    def __init__(self):
        self.per_ip = defaultdict(lambda: deque())

    def observe(self, ev):
        ip = ev["ip"]
        now = ev["ts"]
        q = self.per_ip[ip]
        q.append(ev)
        while q and q[0]["ts"] < now - 60:
            q.popleft()
        probe_visible = ev.get("probe_raw")
        if probe_visible is None:
            probe_visible = ev["is_probe"]
        if probe_visible or ev["ua_flag"]:
            return "block"
        if A.TOOL_UA_RE.search(ev.get("ua", "")) or \
                re.search(r"(nuclei|sqlmap|norma/|artex-|ffuf|nikto|dirsearch|wafw00f|katana|"
                          r"subfinder|naabu|gospider|interactsh|gobuster|feroxbuster|wpscan|"
                          r"masscan|zgrab)", ev.get("ua", ""), re.I):
            return "block"
        recent = [e for e in q if e["ts"] >= now - 1]
        if len(recent) > 30:      # nginx ~15 r/s + burst 30
            return "block"
        if sum(1 for e in q if e["status"] in (400, 401, 403, 404, 429)) >= 20:
            return "block"
        return False


class AnomalyOnly:
    name = "anomaly-only"

    def __init__(self):
        self.model = A.anomaly.HalfSpaceTrees(n_trees=10, height=8, window_size=250, seed=42)
        self.windows = {}
        self.learned = 0
        for ev in BASELINE:
            w = self.windows.setdefault(ev["ip"], A.IPWindow())
            w.add(ev, WINDOW)
            x, _, _ = w.features()
            if x:
                self.model.learn_one(x)

    def observe(self, ev):
        w = self.windows.setdefault(ev["ip"], A.IPWindow())
        w.add(ev, WINDOW)
        x, _, _ = w.features()
        if x is None:
            return False
        score = self.model.score_one(x)
        self.model.learn_one(x)
        self.learned += 1
        return "block" if len(w.events) >= MIN_EVENTS and score >= 0.80 else False


class ChallengeOnly:
    """Challenges every new key once; JS-capable clients can pass."""
    name = "challenge-only"

    def __init__(self, profiles):
        self.seen = set()
        self.profiles = profiles
        self.challenged = set()

    def observe(self, ev):
        ip = ev["ip"]
        if ip in self.seen:
            return False
        self.seen.add(ip)
        self.challenged.add(ip)
        p = self.profiles[ip]
        if not p["js"]:
            return "challenge"               # HTTP tool cannot solve JS
        return "block" if p["report"] == "automation" else False


class AgentWallFull:
    name = "agentwall-full"

    def __init__(self, profiles, human_floor=0.55, use_hard=True, headless=True,
                 use_waf=True, challenge_at_watch=False):
        self.model = A.anomaly.HalfSpaceTrees(n_trees=10, height=8, window_size=250, seed=42)
        self.windows = {}
        self.pop = A.PopulationQuantiles(window=4000, recompute_every=200)
        self.learned = 0
        self.human_floor = human_floor
        self.use_hard = use_hard
        self.headless = headless
        self.profiles = profiles
        self.challenged = set()
        self.challenge_friction = set()
        self.waf = WafOnly() if use_waf else None
        self.challenge_at_watch = challenge_at_watch
        for ev in BASELINE:
            w = self.windows.setdefault(ev["ip"], A.IPWindow())
            w.add(ev, WINDOW)
            x, _, _ = w.features()
            if x:
                self.model.learn_one(x)

    def observe(self, ev):
        if self.waf is not None:
            res = self.waf.observe(ev)
            if res:
                return res
        ip = ev["ip"]
        w = self.windows.setdefault(ip, A.IPWindow())
        w.add(ev, WINDOW)
        x, stats, raw_hard = w.features()
        if x is None:
            return False
        anomaly = self.model.score_one(x)
        self.learned += 1
        human = A.humanness(stats, "web")
        suspicion = A.compute_suspicion(x, human, anomaly)
        # Percentile poisoning fix: only human-like, non-hard events calibrate
        # the population. Attack events still get scored and can be challenged
        # by the absolute floors / hard signals.
        if A.population_eligible(human, raw_hard, self.human_floor):
            self.model.learn_one(x)
            self.pop.update(suspicion)
        hard = bool(raw_hard) and self.use_hard
        if len(w.events) < MIN_EVENTS:
            if os.environ.get("BENCH_TRACE_IP") == ip:
                print("TRACE", ip, "n=", len(w.events), "human=%.2f" % human,
                      "anom=%.2f" % anomaly, "susp=%.3f" % suspicion, "hard=", hard,
                      "reason=min_events")
            return False
        if ip in self.challenged:
            # A JS-capable client that passed the challenge is cleared for the
            # remainder of this synthetic session (mirrors agentwall:cleared).
            return False
        if hard:
            return "block"
        if human >= self.human_floor:
            return False
        if self.pop.ready():
            cut = max(0.55, self.pop.get(0.99) or 0.55)
            watch_cut = max(0.40, self.pop.get(0.95) or 0.40)
        else:
            cut = 0.55
            watch_cut = 0.40
        if os.environ.get("BENCH_TRACE_IP") == ip:
            print("TRACE", ip, "n=", len(w.events), "human=%.2f" % human,
                  "anom=%.2f" % anomaly, "susp=%.3f" % suspicion,
                  "cut=%.3f" % (watch_cut if self.challenge_at_watch else cut),
                  "hard=", hard, "pop=", len(self.pop.buf))
        if suspicion >= (watch_cut if self.challenge_at_watch else cut):
            self.challenged.add(ip)
            p = self.profiles[ip]
            if os.environ.get("BENCH_TRACE_IP") == ip:
                print("TRACE", ip, "action=challenge", "n=", len(w.events),
                      "report=", p["report"], "susp=%.3f" % suspicion)
            if not p["js"]:
                return "challenge"           # HTTP tool fails the JS challenge
            if p["report"] == "automation":
                if self.headless:
                    return "block"
                self.challenge_friction.add(ip)  # no verification: treated as pass
                return False
            self.challenge_friction.add(ip)  # passed challenge, not a detection
            return False
        return False


class NaiveUnion:
    name = "union-naive"

    def __init__(self, parts):
        self.parts = parts
        self.done = set()
        self.challenged = set()

    def observe(self, ev):
        ip = ev["ip"]
        if ip in self.done:
            return False
        results = [p.observe(ev) for p in self.parts]
        for p in self.parts:
            if hasattr(p, "challenged") and ip in p.challenged:
                self.challenged.add(ip)
        if any(results):
            self.done.add(ip)
            return "block" if "block" in results else "challenge"
        return False


# --------------------------------------------------------------------------
# Ground truth / profiles
# --------------------------------------------------------------------------
def build_stream():
    global BASELINE
    BASELINE = benign_baseline()
    specs = [
        ("benign-browser", benign_browser("b"), False, True, None, "Browser users"),
        ("benign-flash", benign_flash_crowd(), False, True, None, "High-volume human flash crowd"),
        ("benign-power", benign_power_users(), False, True, None, "Legitimate power users (high rate, unique pages)"),
        ("benign-api", benign_api(), False, False, None, "Legitimate non-JS API clients"),
        ("scanner-fast", scanner_fast(), True, False, None, "Nuclei-like HTTP scanner"),
        ("agentic-http", agentic_http(), True, False, None, "HTTP-only multi-stage agent (ARTEX-like)"),
        ("agentic-encoded", agentic_encoded_probe(), True, False, None,
         "Encoded probes: raw WAF sees nothing, scorer decodes"),
        ("agentic-stealth", agentic_stealth(), True, True, "human", "Slow browser-like agent, human report"),
        ("headless-enum", headless_enumeration("automation", 1), True, True, "automation", "Headless browser enumerating"),
        ("headless-stealth", headless_enumeration("human", 2), True, True, "human", "Headless browser with spoofed human report"),
        ("distributed-low-slow", distributed_low_slow(), True, False, None, "Rotating IPs, 4 requests each"),
    ]
    stream, profiles, scenario = [], {}, {}
    for label, events, attack, js, report, desc in specs:
        for ev in events:
            stream.append(ev)
            scenario[ev["ip"]] = label
            profiles[ev["ip"]] = {"attack": attack, "js": js, "report": report, "desc": desc}
    stream.sort(key=lambda e: (e["ts"], e["ip"]))
    return stream, profiles, scenario


def run_detector(detector, stream, profiles):
    actions = {}
    first_idx = {}
    seen_count = defaultdict(int)
    start = time.perf_counter()
    for ev in stream:
        seen_count[ev["ip"]] += 1
        if ev["ip"] in first_idx:
            continue
        res = detector.observe(ev)
        if res:
            actions[ev["ip"]] = res
            first_idx[ev["ip"]] = seen_count[ev["ip"]]
    elapsed = time.perf_counter() - start

    benign = [ip for ip, p in profiles.items() if not p["attack"]]
    attack = [ip for ip, p in profiles.items() if p["attack"]]
    benign_blocked = [ip for ip in benign if actions.get(ip) == "block"]
    challenged = set(getattr(detector, "challenged", set()))
    benign_challenged = sorted(challenged & set(benign))
    benign_failed = [ip for ip in benign_challenged if not profiles[ip]["js"]]
    benign_passed = [ip for ip in benign_challenged if profiles[ip]["js"]]
    detected = [ip for ip in attack if ip in actions]
    latency = [first_idx[ip] for ip in detected]

    return {
        "actions": actions,
        "benign_total": len(benign),
        "attack_total": len(attack),
        "benign_blocked": len(benign_blocked),
        "benign_block_rate": len(benign_blocked) / max(1, len(benign)),
        "benign_challenged": len(benign_challenged),
        "benign_challenge_rate": len(benign_challenged) / max(1, len(benign)),
        "benign_challenge_failed": len(benign_failed),
        "benign_challenge_failure_rate": len(benign_failed) / max(1, len(benign)),
        "benign_challenge_completion_rate": (
            len(benign_passed) / len(benign_challenged) if benign_challenged else None),
        "detected": len(detected),
        "missed": len(attack) - len(detected),
        "recall": len(detected) / max(1, len(attack)),
        "median_latency_detected": statistics.median(latency) if latency else None,
        "seconds": elapsed,
        "ms_per_10k": elapsed * 1e7 / max(1, len(stream)),
    }


def per_scenario(detector_result, profiles, scenario):
    out = {}
    for ip, p in profiles.items():
        if not p["attack"]:
            continue
        out.setdefault(scenario[ip], [0, 0])
        out[scenario[ip]][1] += 1
        if ip in detector_result["actions"]:
            out[scenario[ip]][0] += 1
    return {k: "{}/{}".format(v[0], v[1]) for k, v in sorted(out.items())}


def main():
    stream, profiles, scenario = build_stream()
    print("seed:", SEED, "| stream events:", len(stream), "| baseline:", len(BASELINE))

    waf = WafOnly()
    anomaly = AnomalyOnly()
    challenge = ChallengeOnly(profiles)
    full = AgentWallFull(profiles)
    union = NaiveUnion([WafOnly(), AnomalyOnly(), ChallengeOnly(profiles)])
    ablations = {
        "agentwall-full-challenge-at-watch": AgentWallFull(profiles, challenge_at_watch=True),
        "full-no-human-floor": AgentWallFull(profiles, human_floor=0.0),
        "full-no-hard-signals": AgentWallFull(profiles, use_hard=False),
        "full-no-headless": AgentWallFull(profiles, headless=False),
        "full-no-waf": AgentWallFull(profiles, use_waf=False),
    }

    results = {}
    entries = [
        ("waf-only", waf),
        ("anomaly-only", anomaly),
        ("challenge-only", challenge),
        ("agentwall-full", full),
        ("union-naive", union),
    ] + list(ablations.items())
    for label, det in entries:
        results[label] = run_detector(det, stream, profiles)

    # Marginal contribution after WAF: attack keys this strategy catches that
    # the WAF-only baseline does not.
    waf_actions = set(results["waf-only"]["actions"])
    for label, r in results.items():
        r["marginal_over_waf"] = len(set(r["actions"]) - waf_actions)

    # Recall achievable at the same benign challenge budget.
    budget_rows = []
    for budget in (0.0, 0.01, 0.05, 0.10):
        eligible = [(name, r) for name, r in results.items()
                    if r["benign_challenge_rate"] <= budget + 1e-12]
        best = max(eligible, key=lambda kv: kv[1]["recall"]) if eligible else None
        budget_rows.append((budget, best[0] if best else "-",
                            best[1]["recall"] if best else None))

    print("\n{:<36} {:>9} {:>10} {:>9} {:>8} {:>6} {:>8} {:>8} {:>9}".format(
        "strategy", "block-FP", "benign-ch", "ch-fail", "recall", "miss", "med.lat*",
        "margWAF", "ms/10k"))
    for name, r in results.items():
        print("{:<36} {:>9} {:>9.1f}% {:>8.1f}% {:>7.1f}% {:>6} {:>8} {:>8} {:>9.1f}".format(
            name,
            "{} ({:.1f}%)".format(r["benign_blocked"], r["benign_block_rate"] * 100),
            r["benign_challenge_rate"] * 100,
            r["benign_challenge_failure_rate"] * 100,
            r["recall"] * 100,
            r["missed"],
            "-" if r["median_latency_detected"] is None else int(r["median_latency_detected"]),
            r["marginal_over_waf"],
            r["ms_per_10k"]))

    print("\nRecall at equal benign-challenge budget:")
    for budget, name, recall in budget_rows:
        print("  <= {:.0f}%: {:<28} {:>6}".format(
            budget * 100, name,
            "-" if recall is None else "{:.1f}%".format(recall * 100)))

    print("\nDetection by attack family (detected/total):")
    order = [s for s in sorted(set(scenario.values())) if not s.startswith("benign")]
    header = "{:<36}".format("strategy") + "".join("{:>18}".format(s) for s in order)
    print(header)
    for name in ("waf-only", "anomaly-only", "challenge-only", "agentwall-full",
                 "agentwall-full-challenge-at-watch"):
        sc = per_scenario(results[name], profiles, scenario)
        print("{:<36}".format(name) + "".join("{:>18}".format(sc.get(s, "0/0")) for s in order))

    outdir = ROOT / "benchmarks"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": SEED,
        "python": sys.version.split()[0],
        "events": len(stream),
        "baseline_events": len(BASELINE),
        "benign_keys": results["waf-only"]["benign_total"],
        "attack_keys": results["waf-only"]["attack_total"],
        "recall_at_budget": [
            {"benign_challenge_budget": b, "best_strategy": n,
             "recall": None if r is None else r} for b, n, r in budget_rows],
        "results": {k: {kk: vv for kk, vv in v.items() if kk != "actions"}
                    for k, v in results.items()},
        "per_scenario": {k: per_scenario(v, profiles, scenario) for k, v in results.items()},
    }
    (outdir / "results.json").write_text(json.dumps(payload, indent=2) + "\n")

    md = ["# AgentWall benchmark results", "",
          "Generated: {}".format(payload["generated_at"]),
          "Seed: {} — events: {} (baseline {}), Python {}, synthetic ground truth.".format(
              SEED, len(stream), len(BASELINE), payload["python"]), "",
          "Benign keys: {}, attack keys: {}. `med.lat*` is computed only over detected attacks.".format(
              payload["benign_keys"], payload["attack_keys"]), "",
          "| strategy | benign blocked (false block) | benign challenged | challenge failure | challenge completion | recall | missed | median events-to-action* | marginal over WAF | ms / 10k |",
          "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name, r in results.items():
        completion = ("-" if r["benign_challenge_completion_rate"] is None
                      else "{:.1f}%".format(r["benign_challenge_completion_rate"] * 100))
        md.append("| {} | {} ({:.1f}%) | {:.1f}% | {:.1f}% | {} | {:.1f}% | {} | {} | {} | {:.1f} |".format(
            name, r["benign_blocked"], r["benign_block_rate"] * 100,
            r["benign_challenge_rate"] * 100,
            r["benign_challenge_failure_rate"] * 100, completion,
            r["recall"] * 100, r["missed"],
            "-" if r["median_latency_detected"] is None else int(r["median_latency_detected"]),
            r["marginal_over_waf"], r["ms_per_10k"]))
    md += ["", "## Recall at equal benign-challenge budget", "",
           "| benign challenge budget | best strategy | recall |", "|---|---|---:|"]
    for budget, name, recall in budget_rows:
        md.append("| <= {:.0f}% | {} | {} |".format(
            budget * 100, name, "-" if recall is None else "{:.1f}%".format(recall * 100)))
    md += ["", "## Detections by attack family", "",
           "| strategy | " + " | ".join(order) + " |",
           "|---|" + "---|" * len(order)]
    for name in ("waf-only", "anomaly-only", "challenge-only", "agentwall-full",
                 "agentwall-full-challenge-at-watch"):
        sc = per_scenario(results[name], profiles, scenario)
        md.append("| {} | {} |".format(name, " | ".join(sc.get(s, "0/0") for s in order)))
    (outdir / "RESULTS.md").write_text("\n".join(md) + "\n")
    print("\nwrote", outdir / "RESULTS.md", "and", outdir / "results.json")


if __name__ == "__main__":
    main()
