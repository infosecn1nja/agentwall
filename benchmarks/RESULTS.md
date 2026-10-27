# AgentWall benchmark results

Synthetic, labelled benchmark; **not production evidence**. Baseline/model-training and evaluation streams use different RNG seeds. Thresholds are production defaults (no test-set tuning).

Seeds: 20261028, 42, 7 — 42795 events/seed, baseline 6000 events. Benign keys: 970, attack keys: 210 per seed.

Values are mean [min-max] across seeds. `false block` counts benign keys with a block action; `challenge failure` counts benign keys that cannot solve the JS challenge; `med.lat*` is over detected attacks only.

| strategy | false block | benign challenged | challenge failure | challenge completion | recall | missed | med.lat* | marginal over WAF | ms/10k |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| waf-only | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | - | 28.1% [27.6-28.6%] | 151 | 12 | 0 | 37.6 [36.6-38.7] |
| anomaly-only | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | - | 22.9% [21.0-23.8%] | 162 | 24 | 11 | 961.4 [933.9-1013.1] |
| challenge-only | 0.0% [0.0-0.0%] | 100.0% [100.0-100.0%] | 10.3% [10.3-10.3%] | 89.7% | 78.6% [78.6-78.6%] | 45 | 1 | 206 | 2.4 [2.3-2.5] |
| agentwall-full | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | - | 40.5% [40.5-40.5%] | 125 | 12 | 26 | 945.3 [936.0-951.2] |
| union-naive | 0.0% [0.0-0.0%] | 100.0% [100.0-100.0%] | 10.3% [10.3-10.3%] | 89.7% | 81.9% [81.4-82.4%] | 38 | 1 | 213 | 929.9 [884.7-986.7] |
| agentwall-full-challenge-at-watch | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | - | 40.5% [40.5-40.5%] | 125 | 12 | 26 | 951.4 [918.0-997.1] |
| full-no-human-floor | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | - | 31.0% [31.0-31.0%] | 145 | 12 | 6 | 983.2 [965.4-1011.7] |
| full-no-hard-signals | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | - | 40.5% [40.5-40.5%] | 125 | 12 | 26 | 964.0 [929.4-984.8] |
| full-no-headless | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | - | 31.0% [31.0-31.0%] | 145 | 12 | 6 | 947.6 [910.4-991.3] |
| full-no-waf | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | 0.0% [0.0-0.0%] | - | 40.5% [40.5-40.5%] | 125 | 12 | 26 | 901.0 [894.9-912.8] |

## Recall at equal benign-challenge budget

| seed | <=0% | <=1% | <=5% | <=10% |
|---|---:|---:|---:|---:|
| 20261028 | 40.5% | 40.5% | 40.5% | 40.5% |
| 42 | 40.5% | 40.5% | 40.5% | 40.5% |
| 7 | 40.5% | 40.5% | 40.5% | 40.5% |

## Detections by attack family (mean across seeds)

| strategy | agentic-encoded | agentic-http | agentic-stealth | distributed-low-slow | headless-enum | headless-stealth | scanner-fast |
|---|---|---|---|---|---|---|---|
| waf-only | 14/20 | 25/25 | 0/25 | 0/80 | 0/20 | 0/20 | 20/20 |
| anomaly-only | 18/20 | 25/25 | 5/25 | 0/80 | 0/20 | 0/20 | 0/20 |
| challenge-only | 20/20 | 25/25 | 0/25 | 80/80 | 20/20 | 0/20 | 20/20 |
| agentwall-full | 20/20 | 25/25 | 0/25 | 0/80 | 20/20 | 0/20 | 20/20 |
| union-naive | 20/20 | 25/25 | 7/25 | 80/80 | 20/20 | 0/20 | 20/20 |
| agentwall-full-challenge-at-watch | 20/20 | 25/25 | 0/25 | 0/80 | 20/20 | 0/20 | 20/20 |
| full-no-human-floor | 20/20 | 25/25 | 0/25 | 0/80 | 0/20 | 0/20 | 20/20 |
| full-no-hard-signals | 20/20 | 25/25 | 0/25 | 0/80 | 20/20 | 0/20 | 20/20 |
| full-no-headless | 20/20 | 25/25 | 0/25 | 0/80 | 0/20 | 0/20 | 20/20 |
| full-no-waf | 20/20 | 25/25 | 0/25 | 0/80 | 20/20 | 0/20 | 20/20 |

## Per-seed full vs WAF

| seed | WAF recall | full recall | full false block | full benign challenge | full challenge failure |
|---|---:|---:|---:|---:|---:|
| 20261028 | 28.1% | 40.5% | 0.0% | 0.0% | 0.0% |
| 42 | 27.6% | 40.5% | 0.0% | 0.0% | 0.0% |
| 7 | 28.6% | 40.5% | 0.0% | 0.0% | 0.0% |
