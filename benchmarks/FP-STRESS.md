# Benign false-positive stress test

Synthetic guardrail; not a production FP measurement. Full stack, production defaults, seeds 20261028, 7, 42.

| family | keys/seed | blocked | challenged | challenge-failed |
|---|---:|---:|---:|---:|
| direct-navigation | 150 | 0 | 0 | 0 |
| broken-links-404 | 150 | 0 | 0 | 0 |
| privacy-browser | 150 | 0 | 0 | 0 |
| slow-mobile | 150 | 0 | 0 | 0 |
| long-api-client | 150 | 0 | 0 | 0 |
| health-check | 100 | 0 | 0 | 0 |
| shared-corporate-ip | 20 | 0 | 0 | 0 |

**Totals:** 2610 benign key-seeds, 0 false blocks, 0 benign challenges, 0 challenge failures.

Gate: FAIL if any false block or benign challenge failure.
