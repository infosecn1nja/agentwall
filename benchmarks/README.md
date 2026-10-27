# Controlled evaluation benchmark

This directory contains a **synthetic, reproducible** comparison of the shipped
pipeline against its individual layers. It is not a production measurement; it
exists to make claims falsifiable and to record honest negative results.

Read [`../docs/EVALUATION.md`](../docs/EVALUATION.md) first — it answers the
mechanism/effect/composition questions and documents the threats to validity.

## What it runs

`agentwall_bench.py` generates 41,395 labelled evaluation events (plus a 6,000
event baseline) across eight families:

- benign browser users, a high-volume human flash crowd, legitimate power users
  (high rate + many unique pages);
- fast HTTP scanner, HTTP-only multi-stage agent, slow browser-like agent;
- headless enumeration with the default (automation) report, and headless with a
  spoofed human report;
- distributed low-and-slow (4 requests per rotating IP).

It then runs six strategy groups over the same stream:

| Strategy | Purpose |
|---|---|
| `waf-only` | static signatures + nginx-like rate/4xx thresholds |
| `anomaly-only` | real HalfSpaceTrees score, fixed threshold, no gating |
| `challenge-only` | JS challenge every new key (high friction baseline) |
| `agentwall-full` | shipped pipeline (WAF + HST + human floor + population + hard signals + targeted challenge/headless) |
| `union-naive` | OR of WAF/anomaly/challenge ("sum of parts") |
| ablations | full without human floor / hard signals / headless verification / WAF |

## Metrics

- **FP keys / FP rate** on labelled-benign keys.
- **Recall** on labelled-attack keys.
- **Median events-to-action** (detection latency in requests, not wall time).
- **Benign keys challenged** (user friction of the challenge policy).
- **ms / 10k evaluation events** for the detection loop (model training is
  measured separately by construction; Redis/network excluded).

## Run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python benchmarks/agentwall_bench.py
```

Outputs:

- `benchmarks/RESULTS.md` — table for humans.
- `benchmarks/results.json` — machine-readable results + per-scenario counts.

## Honest limitations

Single seed, hand-written traffic, simplified WAF, modelled challenge outcomes,
attack-heavy population (which poisons rolling percentiles), no TLS/browser
execution, no real Strix/ARTEX campaign, no confidence intervals, no temporal
split. Treat the numbers as a **sanity/ablation harness**, not marketing. Real
validation requires benign-dominant production traffic and authorized red-team
runs; see §2.4 of the evaluation document.
