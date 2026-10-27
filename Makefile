# AgentWall — common tasks
#
# Everything here is safe to run locally; Docker targets use throwaway
# containers with ephemeral credentials.

SHELL := /bin/bash
PY    ?= python3

.PHONY: help test e2e linux-config preflight bench lint docker-config clean

help:
	@echo "AgentWall targets:"
	@echo "  make test              # offline suite (Python + Lua + config regressions)"
	@echo "  make e2e               # real Redis+OpenResty+scorer test (Docker)"
	@echo "  make linux-config      # systemd/fail2ban/Apache/OpenResty validation (Docker)"
	@echo "  make preflight         # go-live self-test (defaults to repo config checks)"
	@echo "  make bench             # controlled synthetic evaluation (WAF/anomaly/challenge/full)"
	@echo "  make lint              # shell syntax + Python compile check"
	@echo "  make docker-config     # validate docker-compose.yml"
	@echo "  make clean             # remove __pycache__ / .pyc"

test:
	bash tests/run-tests.sh

e2e:
	bash tests/e2e-real/run.sh

linux-config:
	bash deploy/validate-linux.sh

preflight:
	bash deploy/preflight.sh --help

bench:
	$(PY) benchmarks/agentwall_bench.py

lint:
	bash -n deploy/preflight.sh deploy/validate-linux.sh deploy/gen-secrets.sh \
	        tests/run-tests.sh tests/e2e-real/run.sh
	$(PY) -c "import ast,pathlib,sys; [ast.parse(f.read_text()) for f in list(pathlib.Path('scorer').glob('*.py'))+list(pathlib.Path('tests').glob('*.py'))]; print('python: syntax ok')"
	@if command -v lua >/dev/null 2>&1; then \
	  for f in nginx-lua/*.lua; do lua -e "assert(loadfile('$$f'))" || exit 1; done; \
	  echo "lua: all files load"; \
	else echo "lua: skipped (not installed)"; fi

docker-config:
	@if command -v docker >/dev/null 2>&1; then \
	  docker compose -f deploy/docker-compose.yml config -q && echo "compose: OK"; \
	else echo "docker: skipped (not installed)"; fi

clean:
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
	find . -name "*.pyc" -delete
	@echo "clean: done"
