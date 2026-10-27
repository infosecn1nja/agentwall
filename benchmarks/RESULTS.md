# AgentWall benchmark results

Generated: 2026-10-27T22:59:12.518578+00:00
Events: 41395 (baseline 6000), Python 3.9.6, synthetic ground truth.

| detector | FP keys | FP rate | recall | median events-to-action | benign keys challenged | ms / 10k events |
|---|---:|---:|---:|---:|---:|---:|
| waf-only | 0 | 0.0% | 23.7% | 9 | 0 | 37.6 |
| anomaly-only | 0 | 0.0% | 18.9% | 25 | 0 | 921.8 |
| challenge-only | 0 | 0.0% | 76.3% | 1 | 870 | 2.1 |
| agentwall-full | 0 | 0.0% | 23.7% | 9 | 0 | 942.9 |
| agentwall-full-challenge-at-watch | 0 | 0.0% | 24.2% | 9 | 0 | 920.4 |
| union-naive | 0 | 0.0% | 80.0% | 1 | 870 | 913.0 |
| full-no-human-floor | 0 | 0.0% | 23.7% | 9 | 0 | 952.4 |
| full-no-hard-signals | 0 | 0.0% | 23.7% | 9 | 0 | 1001.3 |
| full-no-headless | 0 | 0.0% | 23.7% | 9 | 0 | 1068.2 |
| full-no-waf | 0 | 0.0% | 16.8% | 16 | 0 | 1014.3 |

## Detections by scenario

| detector | agentic-http | agentic-stealth | distributed-low-slow | headless-enum | headless-stealth | scanner-fast |
|---|---|---|---|---|---|---|
| waf-only | 25/25 | 0/25 | 0/80 | 0/20 | 0/20 | 20/20 |
| anomaly-only | 25/25 | 4/25 | 0/80 | 0/20 | 0/20 | 7/20 |
| challenge-only | 25/25 | 0/25 | 80/80 | 20/20 | 0/20 | 20/20 |
| agentwall-full | 25/25 | 0/25 | 0/80 | 0/20 | 0/20 | 20/20 |
| agentwall-full-challenge-at-watch | 25/25 | 0/25 | 0/80 | 1/20 | 0/20 | 20/20 |
