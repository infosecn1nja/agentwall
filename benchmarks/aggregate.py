#!/usr/bin/env python3
"""Aggregate per-seed benchmark runs into benchmarks/RESULTS.md.

Usage: python benchmarks/agentwall_bench.py per seed, then this script.
"""
import glob
import json
import statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIELDS = ["benign_block_rate", "benign_challenge_rate", "benign_challenge_failure_rate",
          "recall", "missed", "median_latency_detected", "marginal_over_waf", "ms_per_10k"]


def agg(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return None, None, None
    return statistics.mean(vals), min(vals), max(vals)


def fmt(mean, lo, hi, pct=False, digits=1):
    if mean is None:
        return "-"
    f = "{:." + str(digits) + "f}"
    if pct:
        return (f + "% [{}-{}%]").format(mean * 100, f.format(lo * 100), f.format(hi * 100))
    return (f + " [{}-{}]").format(mean, f.format(lo), f.format(hi))


def main():
    files = sorted(glob.glob(str(ROOT / "results-*.json")))
    runs = [json.load(open(f)) for f in files]
    if not runs:
        raise SystemExit("no results-*.json files; run the benchmark per seed first")
    strategies = list(runs[0]["results"].keys())
    seeds = [r["seed"] for r in runs]

    lines = ["# AgentWall benchmark results", "",
             "Synthetic, labelled benchmark; **not production evidence**. "
             "Baseline/model-training and evaluation streams use different RNG seeds. "
             "Thresholds are production defaults (no test-set tuning).", "",
             "Seeds: {} — {} events/seed, baseline {} events. "
             "Benign keys: {}, attack keys: {} per seed.".format(
                 ", ".join(map(str, seeds)), runs[0]["events"], runs[0]["baseline_events"],
                 runs[0]["benign_keys"], runs[0]["attack_keys"]), "",
             "Values are mean [min-max] across seeds. `false block` counts benign keys "
             "with a block action; `challenge failure` counts benign keys that cannot "
             "solve the JS challenge; `med.lat*` is over detected attacks only.", "",
             "| strategy | false block | benign challenged | challenge failure | challenge completion | recall | missed | med.lat* | marginal over WAF | ms/10k |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name in strategies:
        rows = [r["results"][name] for r in runs]
        def a(k):
            return agg([r.get(k) for r in rows])
        bb = a("benign_block_rate")
        ch = a("benign_challenge_rate")
        cf = a("benign_challenge_failure_rate")
        comps = [r.get("benign_challenge_completion_rate") for r in rows if r.get("benign_challenge_completion_rate") is not None]
        comp = ("{:.1f}%".format(statistics.mean(comps) * 100) if comps else "-")
        rc = a("recall")
        ms = a("missed")
        lat = a("median_latency_detected")
        marg = a("marginal_over_waf")
        cpu = a("ms_per_10k")
        lines.append("| {} | {} | {} | {} | {} | {} | {:.0f} | {} | {:.0f} | {} |".format(
            name, fmt(*bb, pct=True), fmt(*ch, pct=True), fmt(*cf, pct=True), comp,
            fmt(*rc, pct=True), (ms[0] if ms[0] is not None else 0),
            "-" if lat[0] is None else "{:.0f}".format(lat[0]),
            (marg[0] if marg[0] is not None else 0), fmt(*cpu, digits=1)))

    lines += ["", "## Recall at equal benign-challenge budget", "",
              "| seed | <=0% | <=1% | <=5% | <=10% |", "|---|---:|---:|---:|---:|"]
    for r in runs:
        cells = []
        for b in (0.0, 0.01, 0.05, 0.10):
            best = max((x for x in r["results"].values()
                        if x["benign_challenge_rate"] <= b + 1e-12),
                       key=lambda x: x["recall"], default=None)
            cells.append("-" if best is None else "{:.1f}%".format(best["recall"] * 100))
        lines.append("| {} | {} |".format(r["seed"], " | ".join(cells)))

    attack_scenarios = sorted({s for s in runs[0]["per_scenario"]["agentwall-full"]
                               if not s.startswith("benign")})
    lines += ["", "## Detections by attack family (mean across seeds)", "",
              "| strategy | " + " | ".join(attack_scenarios) + " |",
              "|---|" + "---|" * len(attack_scenarios)]
    for name in strategies:
        cells = []
        for scen in attack_scenarios:
            nums = []
            for r in runs:
                a, b = r["per_scenario"][name].get(scen, "0/0").split("/")
                nums.append(int(a))
            cells.append("{:.0f}/{}".format(statistics.mean(nums), b))
        lines.append("| {} | {} |".format(name, " | ".join(cells)))

    lines += ["", "## Per-seed full vs WAF", "",
              "| seed | WAF recall | full recall | full false block | full benign challenge | full challenge failure |",
              "|---|---:|---:|---:|---:|---:|"]
    for r in runs:
        w = r["results"]["waf-only"]
        f = r["results"]["agentwall-full"]
        lines.append("| {} | {:.1f}% | {:.1f}% | {:.1f}% | {:.1f}% | {:.1f}% |".format(
            r["seed"], w["recall"] * 100, f["recall"] * 100,
            f["benign_block_rate"] * 100, f["benign_challenge_rate"] * 100,
            f["benign_challenge_failure_rate"] * 100))

    out = "\n".join(lines) + "\n"
    (ROOT / "RESULTS.md").write_text(out)
    (ROOT / "results.json").write_text(json.dumps({
        "seeds": seeds,
        "per_seed": runs,
        "generated_from": [Path(f).name for f in files],
    }, indent=2) + "\n")
    print(out)
    print("wrote", ROOT / "RESULTS.md")


if __name__ == "__main__":
    main()
