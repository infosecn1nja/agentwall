# Changelog

All notable changes to AgentWall are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Security fixes

- **XFF keying mismatch (H-1):** the scorer no longer trusts the left-most
  `X-Forwarded-For` hop. `--use-xff` now **requires** `--trust-proxies` and
  resolves right-to-left skipping trusted hops; shipped compose/Dockerfile/
  systemd defaults no longer enable `--use-xff` (with real_ip the first log
  field is authoritative). Tests cover spoofed left-most values, allowlist
  poisoning and an end-to-end spoofed-XFF log line.
- **FCrDNS queue bound (M-1):** good-bot verification now sheds lookups when its
  in-flight queue is saturated instead of growing unbounded (new
  `agentwall_dns_shed_total` metric).
- **State-file hardening (M-2):** checkpoint files are written 0600, symlinks
  are refused, and group/other-accessible state paths trigger warnings; the
  pickle-as-code-execution risk is documented.
- **Open-redirect hardening (L-1):** the server validates `next` as a
  same-origin path (rejects `//`, `\`, control characters) before returning it.
- **GET-fallback bounds (L-2):** challenge id/nonce are length/format-checked
  before any Redis lookup.
- The deprecated v1 scorer is no longer copied into the container image (L-3);
  the sudoers wildcard trade-off is documented (L-4).

### Added

- README now documents the detection model explicitly: `river`'s
  **HalfSpaceTrees** (Half-Space Trees) — why it is unsupervised/streaming, the
  score-then-learn pipeline, geometry flags (`--hst-trees/--hst-height/--hst-window`),
  warmup/drift/checkpoint caveats, `--once` batch replay, and measured capacity.
- Source-derived default profiles for **Strix** and **ARTEX** in the real e2e
  suite (`F1–F22`, `B16–B17`): agent/scanner UAs are denied immediately, the
  Strix sandbox browser's correlated headless surfaces are blocked, and generic
  `curl`/`python-httpx` remain allowed (false-positive controls).
- Headless scoring now correlates an empty plugin/MIME surface with a software
  rasterizer and a disabled PDF viewer, and checks Client-Hints/UA consistency
  server-side (a common UA-only stealth shortcut).
- Known agent/scanner default UAs are tagged in the nginx/Apache maps and the
  scorer's automation-UA regex. They are documented as **supporting signals**
  (operators can rotate UAs); behaviour scoring remains primary.
- `docs/AGENT-VALIDATION.md` with source links, mapping tables, reproduction
  commands and explicit limits. Linux config validation + full test suite pass.

## [0.1.0] — 2026-10-27

First public release. AgentWall is a vendor-agnostic defense stack against
autonomous AI/LLM penetration agents: edge rate limiting/WAF, behavioural
fail2ban jails, a streaming ML scorer, and an OpenResty verification layer.

### Added

- Streaming scorer (`scorer/agentwall_scorer.py`) with population-relative
  scoring, human-ness gating (`web`/`api` profiles), IPv6 /64 aggregation,
  bounded LRU state, atomic checkpoints, Prometheus metrics, `--once` batch
  replay mode, and configurable HalfSpaceTrees geometry.
- OpenResty enforcement (`nginx-lua/`): hard 403 from Redis verdicts, signed
  IP-bound clearance cookies, and a verified JS proof-of-work challenge with
  **headless/automation detection** (webdriver, CDP, WebGL/SwiftShader, plugin
  surfaces, timing) writing the `agentwall:headless` marker.
- nginx + Apache edge configs (`waf/`), complete production OpenResty config
  (`deploy/nginx.conf.example`), Docker Compose, hardened systemd unit, and a
  least-privilege sudoers entry for optional fail2ban bans.
- Behavioural fail2ban jails with real-IP guidance and a manual-ban jail for the
  scorer.
- Prometheus scrape example + 23 alert rules (`deploy/prometheus/`).
- Secret generation (`deploy/gen-secrets.sh`), log rotation
  (`deploy/logrotate/agentwall`), preflight checks, and a Linux-native validator
  (`deploy/validate-linux.sh`: systemd, fail2ban 1.0/0.11, Apache, OpenResty,
  Redis contract).
- Test suites at release: 70 Python unit/config tests, 206 Lua assertions, and
  a real Docker end-to-end test (Redis + OpenResty + real scorer, 36 assertions).
  Unreleased adds the source-derived Strix/ARTEX profiles (64 assertions).
- GitHub-ready docs: architecture, threat model, contributing, security policy,
  code of conduct, issue/PR templates, CI workflow, Makefile.

### Fixed (security/robustness)

- Docker Compose scorer command no longer swallows YAML comments into argv
  (previously crashed at startup with argparse exit 2).
- systemd unit ships dry-run by default instead of enforcing on install.
- Redis auth is now real for the Lua layer; missing password/NOAUTH fails open
  with a CRIT log instead of silently disabling enforcement.
- The challenge clearance cookie is now HMAC-signed and IP-bound; the old
  client-set `agentwall_clr=1` scheme was forgeable and reusable across IPs.
- Challenge escalation now honours the grace window independently of cooldown;
  hard-signal blocks no longer bypass the block cooldown (subprocess storm).
- IPv6 sources are aggregated to /64 for detection and verdict keys.
- fail2ban option lines no longer carry trailing `#` comments (the parser read
  them as values, silently resetting thresholds and breaking the auth jail).
- Model checkpoints are written atomically and corrupt state no longer
  crash-loops the service.
- Default HalfSpaceTrees geometry changed from 25 trees/height 15 (~1.6M nodes,
  ~500MB, <500 events/s) to river's 10/8/250 (~7,300 events/s, 158MB).
- `--use-xff` now warns when the access log lacks the `xff=` field.
- Each `AGENTWALL_*` env var read by Lua is validated against the shipped nginx
  config by a regression test (a missing `env NAME;` silently falls back to
  defaults).
