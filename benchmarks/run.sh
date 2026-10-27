#!/usr/bin/env bash
# Run the benchmark across the seeds used in docs/EVALUATION.md, then aggregate.
# Requires the real river/redis venv.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
for seed in 20261028 7 42; do
  echo "=== seed $seed ==="
  BENCH_SEED="$seed" "$PY" benchmarks/agentwall_bench.py >/dev/null
  cp benchmarks/results.json "benchmarks/results-$seed.json"
done
"$PY" benchmarks/aggregate.py
