#!/usr/bin/env python3
"""Benign false-positive stress test for the full AgentWall decision pipeline.

Generates only benign traffic families that *look* suspicious to cheap
heuristics (direct navigation with no referer, stale/broken links, privacy
browsers, slow mobile, long non-JS API clients, health checks, and a
high-volume shared corporate IP). Runs the production-default full stack and
fails if any benign key receives a block or cannot complete a challenge.

This is a synthetic guardrail, not a production FP measurement. Use it as a
pre-deployment gate plus shadow traffic review.

    python benchmarks/fp_stress.py
    BENCH_SEEDS=20261028,7,42 python benchmarks/fp_stress.py
"""
import json
import os
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import agentwall_bench as B  # noqa: E402

FAMILIES = ["direct-navigation", "broken-links-404", "privacy-browser", "slow-mobile",
            "long-api-client", "health-check", "shared-corporate-ip"]


def build(seed):
    B.RNG = random.Random(seed)
    B.BASE_RNG = random.Random(seed + 1000)
    B.BASELINE = B.benign_baseline()
    stream, profiles, family = [], {}, {}
    base = B.BASE_TS + 3000

    def add(ip, evs, fam):
        stream.extend(evs)
        profiles[ip] = {"attack": False, "js": True, "report": None,
                        "family": fam}
        family[ip] = fam

    # 1) direct navigation: landing page has no referer, then assets/pages
    for k in range(150):
        ip = "10.20.{}.{}".format(k // 200, 1 + k % 200)
        t = base + random.uniform(0, 300)
        evs = []
        for j in range(18):
            static = j % 3 != 0
            evs.append(B.event(ip, t + j * random.uniform(3, 10),
                               "/static/a.js" if static else "/landing", 200,
                               is_static=static, has_ref=(j > 0 and not static)))
        add(ip, evs, "direct-navigation")

    # 2) stale/broken links produce 404s but with browser/referer/static signals
    for k in range(150):
        ip = "10.21.{}.{}".format(k // 200, 1 + k % 200)
        t = base + 100 + random.uniform(0, 300)
        evs = []
        for j in range(18):
            static = j % 4 == 0
            evs.append(B.event(ip, t + j * random.uniform(3, 10),
                               "/static/b.png" if static else "/old/{}".format(j),
                               200 if static else 404, is_static=static,
                               has_ref=not static))
        add(ip, evs, "broken-links-404")

    # 3) privacy browser: referer stripped, assets still fetched
    for k in range(150):
        ip = "10.22.{}.{}".format(k // 200, 1 + k % 200)
        t = base + 200 + random.uniform(0, 300)
        evs = []
        for j in range(18):
            static = j % 2 == 0
            evs.append(B.event(ip, t + j * random.uniform(3, 10),
                               "/static/c.css" if static else "/docs", 200,
                               is_static=static, has_ref=False))
        add(ip, evs, "privacy-browser")

    # 4) slow mobile users
    for k in range(150):
        ip = "10.23.{}.{}".format(k // 200, 1 + k % 200)
        t = base + 300 + random.uniform(0, 300)
        evs = []
        for j in range(18):
            static = j % 3 == 0
            evs.append(B.event(ip, t + j * random.uniform(8, 25),
                               "/static/m.js" if static else "/m", 200,
                               is_static=static, has_ref=not static))
        add(ip, evs, "slow-mobile")

    # 5) legitimate non-JS API clients, longer than min-events
    for k in range(150):
        ip = "10.24.{}.{}".format(k // 200, 1 + k % 200)
        t = base + 400 + random.uniform(0, 300)
        evs = [B.event(ip, t + j * random.uniform(2, 5),
                       "/api/v1/items/{}".format(j), 200, "python-httpx/0.27.2",
                       is_browser=False, is_tool=False, has_ref=False)
               for j in range(30)]
        add(ip, evs, "long-api-client")
        profiles[ip]["js"] = False

    # 6) health checks / monitoring (non-browser; should be allowlisted in prod)
    for k in range(100):
        ip = "10.25.{}.{}".format(k // 200, 1 + k % 200)
        t = base + 500 + random.uniform(0, 300)
        evs = [B.event(ip, t + j * 30, "/health", 200, "curl/8.4.0",
                       is_browser=False, is_tool=False, has_ref=False)
               for j in range(20)]
        add(ip, evs, "health-check")
        profiles[ip]["js"] = False

    # 7) shared corporate/NAT IP: many users behind one key, human signals
    for k in range(20):
        ip = "10.26.0.{}".format(1 + k)
        t = base + 600 + random.uniform(0, 100)
        evs = []
        for j in range(100):
            static = j % 3 == 0
            evs.append(B.event(ip, t + j * random.uniform(0.8, 1.6),
                               "/static/s.js" if static else "/team/{}".format(j % 20),
                               200, is_static=static, has_ref=not static))
        add(ip, evs, "shared-corporate-ip")

    stream.sort(key=lambda e: (e["ts"], e["ip"]))
    return stream, profiles


def run(seed):
    stream, profiles = build(seed)
    full = B.AgentWallFull(profiles)
    blocked, challenged = set(), set()
    for ev in stream:
        ip = ev["ip"]
        if ip in blocked or ip in challenged:
            continue
        res = full.observe(ev)
        if res == "block":
            blocked.add(ip)
        elif res == "challenge" or ip in full.challenged:
            challenged.add(ip)
    rows = {}
    for fam in FAMILIES:
        ips = [ip for ip in profiles if profiles[ip]["family"] == fam]
        rows[fam] = {
            "keys": len(ips),
            "blocked": sum(1 for ip in ips if ip in blocked),
            "challenged": sum(1 for ip in ips if ip in challenged and ip not in blocked),
            "challenge_failed": sum(1 for ip in ips
                                    if ip in challenged and ip not in blocked
                                    and not profiles[ip]["js"]),
        }
    return rows, len(profiles)


def main():
    seeds = [int(x) for x in os.environ.get("BENCH_SEEDS", "20261028,7,42").split(",")]
    all_rows, totals = {}, {}
    failed = False
    for seed in seeds:
        rows, total = run(seed)
        all_rows[seed] = rows
        totals[seed] = total
        for fam, r in rows.items():
            if r["blocked"] or r["challenge_failed"]:
                failed = True
                print("FP GATE FAIL seed={} family={} {}".format(seed, fam, r))
    lines = ["# Benign false-positive stress test", "",
             "Synthetic guardrail; not a production FP measurement. "
             "Full stack, production defaults, seeds {}.".format(", ".join(map(str, seeds))), "",
             "| family | keys/seed | blocked | challenged | challenge-failed |",
             "|---|---:|---:|---:|---:|"]
    for fam in FAMILIES:
        keys = sum(all_rows[s][fam]["keys"] for s in seeds) // len(seeds)
        blocked = sum(all_rows[s][fam]["blocked"] for s in seeds)
        challenged = sum(all_rows[s][fam]["challenged"] for s in seeds)
        fail = sum(all_rows[s][fam]["challenge_failed"] for s in seeds)
        lines.append("| {} | {} | {} | {} | {} |".format(fam, keys, blocked, challenged, fail))
    total_keys = sum(totals.values())
    total_blocked = sum(r["blocked"] for s in seeds for r in all_rows[s].values())
    total_challenged = sum(r["challenged"] for s in seeds for r in all_rows[s].values())
    total_failed = sum(r["challenge_failed"] for s in seeds for r in all_rows[s].values())
    lines += ["", "**Totals:** {:.0f} benign key-seeds, {} false blocks, {} benign challenges, "
              "{} challenge failures.".format(total_keys, total_blocked, total_challenged, total_failed), "",
              "Gate: FAIL if any false block or benign challenge failure."]
    print("\n".join(lines))
    (ROOT / "FP-STRESS.md").write_text("\n".join(lines) + "\n")
    (ROOT / "fp-stress.json").write_text(json.dumps(
        {"seeds": seeds, "per_seed": all_rows, "totals": {
            "benign_key_seeds": total_keys, "false_blocks": total_blocked,
            "benign_challenges": total_challenged, "challenge_failures": total_failed}},
        indent=2) + "\n")
    if failed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
