# Contributing to AgentWall

Thanks for helping improve AgentWall. This project targets a hostile,
fast-moving adversary (autonomous AI/agentic pentest tooling), so changes are
evaluated on evidence, honest failure modes, and safety of the rollout path.

## Ground rules

- **Be honest about limits.** New detection/enforcement must document false
  positives and evasion paths, not just the happy path. "Unbypassable" claims
  are rejected.
- **Fail open, log loudly.** Enforcement paths must never turn a Redis/scorer
  outage into site downtime; configuration errors must be CRIT-visible, not
  silent.
- **No secrets or customer data** in issues, PRs, tests, or logs. Redact IPs,
  hostnames, cookies and keys.
- **Authorized testing only.** Never run the e2e/preflight tooling against
  systems you do not own or have permission to test.

## Development setup

```bash
git clone <your-fork> && cd agentwall

# Fast, offline suite (no Redis/OpenResty/Docker needed):
bash tests/run-tests.sh

# Config linting of the shipped deploy files:
bash deploy/preflight.sh --help
bash deploy/validate-linux.sh --skip-systemd --skip-fail2ban \
     --skip-apache --skip-redis       # OpenResty config only, Docker required

# Real end-to-end (Docker: Redis + OpenResty + real scorer):
bash tests/e2e-real/run.sh
```

Requirements for the full suite: Python 3.9+, Docker (with a reachable daemon),
and network access on first run (images + `river`/`redis` into a temp venv).
`lua` (5.1–5.4) enables the Lua unit tests; they are skipped otherwise.

## Gates a PR must pass

1. `bash tests/run-tests.sh` — Python unit/config tests + Lua assertions + shell syntax.
2. `bash tests/e2e-real/run.sh` — real block/challenge/headless + behaviour + agent-profile flow (72 assertions).
3. `bash deploy/validate-linux.sh` — systemd/fail2ban/Apache/OpenResty checks (Docker).
4. `promtool check rules deploy/prometheus/agentwall.rules.yml` if you touched metrics/rules.
5. `bash -n` on any shell script you edited; `lua -e 'assert(loadfile(...))'` on Lua files.
6. If you change the Redis key/cookie/env contract: update
   `docs/ARCHITECTURE.md`, `nginx-lua/README.md`, the scorer, the Lua layer,
   and the e2e harness together. Contracts are tested intentionally.

CI (`.github/workflows/ci.yml`) runs the same gates on push/PR; a red pipeline
must be fixed before review.

## Style

- **Python**: standard library where practical; keep compatibility with Python
  3.9+; no new runtime dependency without a strong reason; type hints optional
  but keep functions small and testable. Prefer extracted pure functions
  (`decide`, `features`, `humanness`) so logic is unit-tested, not just I/O.
- **Lua**: must run on OpenResty/LuaJIT (Lua 5.1) — no `//`, bit operators,
  `goto`, or 5.2+ APIs. Keep `agentwall_common.lua` free of `ngx`/`cjson` so it
  stays unit-testable with stock `lua`.
- **Config**: comments explain *why*; never put a `#` comment on a fail2ban
  option line (the parser only treats `;` as inline). Keep Docker Compose
  `command:` as a YAML list — comments inside scalars become argv.
- **Docs**: update the runbook/threat model when behavior changes; keep the
  "honest limits" sections current.

## Pull requests

- One logical change per PR; describe the threat/behavior it addresses.
- Include the exact commands and output tail you used to verify it.
- Call out breaking changes (Redis key prefix, cookie name, env vars, CLI
  flags, log format) explicitly; they break mixed-version deployments.
- Update `CHANGELOG.md` under `Unreleased`.

## Security reports

Do **not** open a public issue for a suspected vulnerability. Use the process in
[SECURITY.md](SECURITY.md). Design-limit reports (e.g. "rotating IPs evade
per-IP limits") are covered in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) —
open a discussion instead if you have a concrete improvement.

## License

By contributing you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
