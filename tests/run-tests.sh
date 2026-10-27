#!/usr/bin/env bash
# Full local verification for agentwall: Python scorer, config regressions,
# Lua enforcement logic, and shell syntax. No live nginx/Redis/fail2ban needed.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== [1/4] python sources compile =="
python3 - <<'PY'
from pathlib import Path
import sys

bad = 0
for path in sorted(Path("scorer").glob("*.py")):
    try:
        compile(path.read_text(), str(path), "exec")
        print("  ok   {}".format(path))
    except SyntaxError as exc:
        print("  FAIL {}: {}".format(path, exc))
        bad = 1
sys.exit(bad)
PY

echo
echo "== [2/4] python unit + config tests =="
python3 -m unittest discover -s tests -p 'test_*.py' -v

echo
echo "== [3/4] lua enforcement unit tests =="
if command -v lua >/dev/null 2>&1; then
    lua tests/lua/test_agentwall_common.lua
else
    echo "  skip: lua binary not found"
fi

echo
echo "== [4/4] shell syntax =="
if [ -f deploy/preflight.sh ]; then
    bash -n deploy/preflight.sh
    echo "  ok   deploy/preflight.sh"
fi
if command -v shellcheck >/dev/null 2>&1 && [ -f deploy/preflight.sh ]; then
    shellcheck deploy/preflight.sh
    echo "  ok   shellcheck deploy/preflight.sh"
fi

echo
echo "ALL CHECKS PASSED"
