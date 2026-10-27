# Controlled evaluation benchmark

Synthetic, multi-seed comparison of the shipped pipeline against its individual
layers. It is **not** production evidence; it exists to make claims falsifiable
and to record both positive and negative results.

Read [`../docs/EVALUATION.md`](../docs/EVALUATION.md) for the full analysis,
formulas, state/transition rules, traces, and threats to validity.

## What it runs

42,795 evaluation events + 6,000 baseline events per seed, with **different RNG
seeds for model training and evaluation** and three evaluation seeds. There are
970 benign keys (including 100 legitimate non-JS API clients) and 210 attack
keys across:

- benign browser users, flash crowd, legitimate power users, non-JS API clients;
- fast HTTP scanner, HTTP-only multi-stage agent, slow browser-like agent;
- headless enumeration (default automation report), spoofed-human headless;
- encoded probes the raw WAF map cannot see;
- distributed low-and-slow (4 requests per rotating IP).

Strategies:

| Strategy | Purpose |
|---|---|
| `waf-only` | static signatures + nginx-like rate/4xx thresholds |
| `anomaly-only` | real HST, fixed threshold, online-learns every event, no gating |
| `challenge-only` | JS challenge every new key (max-friction baseline) |
| `agentwall-full` | WAF + HST + human floor + benign-only learning/population + hard signals + targeted challenge/headless |
| `union-naive` | OR of WAF/anomaly/challenge ("sum of parts") |
| ablations | full without human floor / hard signals / headless verification / WAF |

Detectors do **not** read ground-truth labels. Labels are used only for metrics;
the JS-capability/report outcome is a modelled environment response after the
detector acts.

## Metrics

- **False block rate**: benign keys with a block action / all 970 benign keys.
- **Benign challenge rate**: benign keys challenged / all 970 benign keys.
- **Challenge failure rate**: benign keys that cannot solve the JS challenge /
  all benign keys. **Challenge completion**: passed / challenged.
- **Recall**, plus **missed** attack keys (the denominator behind `med.*`).
- **Median events-to-action**, computed only over detected attacks.
- **Marginal over WAF**: attack keys this strategy catches that WAF-only misses.
- **ms / 10k events**: detection-loop CPU only; model training and end-to-end
  browser challenge costs are not included.
- **Recall at equal benign-challenge budget** (0/1/5/10%).

## Run

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
bash benchmarks/run.sh              # 3 seeds + aggregate -> RESULTS.md
# single seed:
BENCH_SEED=7 python benchmarks/agentwall_bench.py
# decision trace for one key:
BENCH_TRACE_IP=198.18.1.10 python benchmarks/agentwall_bench.py
```

Outputs:

- `benchmarks/RESULTS.md` — aggregated multi-seed table.
- `benchmarks/results.json` — combined per-seed data.
- `benchmarks/results-<seed>.json` — raw per-seed results.

## Headline (see RESULTS.md for ranges)

At a **0% benign-challenge budget**, full-stack recall is **40.5%** vs **28.1%**
for WAF-only, with **0 false blocks** and **0 benign challenges**. Challenge-only
and naive union reach 78.6%/81.9% recall only by challenging **100%** of benign
keys and failing **10.3%** of them (non-JS API clients). Full costs ~25× WAF CPU,
is not faster, and still misses distributed low-and-slow and spoofed-human
headless agents.

## Honest limitations

Synthetic traffic, simplified WAF, modelled challenge outcomes, no real
browser/TLS/network or end-to-end challenge cost, no temporal drift/confidence
intervals, attack-heavy population, no real Strix/ARTEX campaign. Treat this as
a sanity/ablation harness, not marketing. Real validation requires
benign-dominant production traffic, authorized lab agents, and end-to-end cost
measurement; see §2.5 of the evaluation document.
