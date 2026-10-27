## Summary

<!-- What behavior/threat does this change address? Link the issue. -->

## Type

- [ ] Bug fix
- [ ] Detection / hardening
- [ ] New feature
- [ ] Docs / tooling
- [ ] Breaking change (contract: env, Redis key, cookie, CLI flag, log format)

## Threat-model impact

<!-- New detections: false positives, evasion paths, rollout mode. New enforcement: fail-open behavior. -->

## Verification (paste the commands + tail)

- [ ] `bash tests/run-tests.sh`
- [ ] `bash tests/e2e-real/run.sh` (if the challenge/scorer/contract changed)
- [ ] `bash deploy/validate-linux.sh` (if config/systemd/fail2ban changed)
- [ ] `promtool check rules deploy/prometheus/agentwall.rules.yml` (if metrics changed)
- [ ] `bash deploy/preflight.sh` / `bash -n` / `lua -e 'assert(loadfile(...))'` as applicable
- [ ] No secrets, customer data, or real client IPs in the diff/tests

## Checklist

- [ ] One logical change; docs updated (`docs/ARCHITECTURE.md`, `docs/THREAT-MODEL.md`, runbook, component README).
- [ ] `CHANGELOG.md` updated under `Unreleased`.
- [ ] Contract changes are reflected in scorer + Lua + nginx `env` + e2e tests.
- [ ] Fail-open behavior preserved on infrastructure faults; config faults are CRIT-visible.
