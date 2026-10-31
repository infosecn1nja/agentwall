# Changelog

All notable changes to AgentWall are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Added — edge behavioural prevention (inline, model-free)

- **New `nginx-lua/agentwall_behavior_log.lua`** (wired via `log_by_lua_file`):
  the edge now acts on an autonomous agent's *behaviour* within one short
  window, without waiting for the out-of-band scorer and without relying on the
  User-Agent. Per-key fixed-window Redis counters drive:
  - **out-of-band interaction callbacks** (interactsh / `oast.*` / Burp
    Collaborator / `oastify.com` / `dnslog.cn` / `ceye.io` / canarytokens / …,
    extensible via `AGENTWALL_OOB_EXTRA`) in the URI, query or Referer → block;
  - **injection/traversal probe payloads** → block on a short burst;
  - **4xx enumeration bursts** and **credential-stuffing bursts** on auth paths
    → JS challenge (a human solves it once; a script loop cannot);
  - **browser-header inconsistency** (a modern-Chrome/Firefox UA over HTTPS with
    no `Sec-Fetch-*` / `Accept-Language` / client hints — the scripted-client
    tell) counted as a soft signal.
  The log phase cannot open sockets, so Redis work is handed to a detached
  `ngx.timer.at(0,…)`; the layer adds no response latency and fails open. It
  writes the same `agentwall:block` / `agentwall:challenge` keys the scorer
  writes, so the access-phase script enforces them on the next request.
  **Ships in shadow** (`AGENTWALL_BEHAVIOR_MODE=mark`): it logs the would-be
  verdict and writes nothing until an operator sets `challenge`.
- **Out-of-band callback signatures in every layer**: `OOB_RE` in the scorer
  (a single OOB hit is now a hard signal), the `$agentwall_probe` nginx map, and
  `agentwall_common.is_oob_callback` in Lua.
- Pure, unit-tested helpers in `agentwall_common`: `is_oob_callback`,
  `is_probe_payload`, `is_static_path`, `is_auth_path`,
  `browser_header_inconsistency`, `behavior_decision`, `load_behavior_config`.
- Validation extended: 10 new config knobs (`AGENTWALL_BEHAVIOR_*`,
  `AGENTWALL_OOB_EXTRA`) in `gen-secrets.sh` / `nginx.conf.example` / the e2e
  harness; 6 new real end-to-end assertions (`G1–G6`) covering OOB block, probe
  block, 4xx-burst challenge, and a normal-browser false-positive guard;
  CyberStrikeAI default UAs added to the agent-validation profiles.

### Production hardening (false positives and safe defaults)

- **Self-inflicted fail2ban bans (critical):** the general per-IP limiter
  (`15r/s burst=30`) also counted static assets, so one cold page view of a
  typical site produced 429s that pushed real visitors over the
  `agentwall-behavior` threshold (40 4xx/429 in 60s → firewall ban up to 1 day).
  Static assets are now exempt from the limiter (`$agentwall_rl_key`), burst is
  60, and the behaviour filter no longer counts 429 (AgentWall's own rate-limit
  *and* challenge status) or 404s for static assets. The behavioural jails ship
  `enabled = false` for the shadow phase.
- **Headless `mark` mode was not shadow (critical):** with `--enforce` the scorer
  hard-blocked every challenged key carrying `agentwall:headless`, whatever
  `AGENTWALL_HEADLESS_MODE` said. New `--headless-mode mark|block` (default from
  `AGENTWALL_HEADLESS_MODE`, else `mark`); in `mark` the marker is logged
  (`HEADLESS(mark)`) and counted (`agentwall_headless_marked_total`) only.
- **Headless false positives on real browsers (critical):** `ANGLE` and `Mesa`
  were treated as software WebGL, but they are the normal hardware renderer
  strings of Chrome/Edge on Windows/macOS and of Linux Intel/AMD drivers.
  Plugin/MIME, `window.chrome`, PDF-viewer and window-geometry checks are now
  desktop-only: Android WebView in-app browsers (Instagram, Facebook, TikTok,
  LINE) scored exactly the 0.60 block threshold. SwiftShader + empty plugins is
  still caught behind a spoofed phone UA.
- **Scorer crash loop after log rotation (critical):** logrotate recreates the
  log `0640 root adm`; the compose scorer (uid 10001) lost read access and
  crash-looped on `PermissionError`, silently ending enforcement. Compose now
  adds the log group (`group_add`, `AGENTWALL_LOG_GID`, default 4), and the
  scorer waits and logs instead of crashing while the log is unreadable.
- **Edge 403s ignored the dry-run phase:** `if ($agentwall_bad_ua|probe) return
  403` now goes through `$agentwall_edge_deny`, gated by
  `$agentwall_edge_enforce` (default 0 = log only).
- **`Electron/` removed from the blocking UA markers** (nginx, Apache, Lua):
  Slack/Teams/Discord/VS Code and in-house desktop apps embed sites in Electron.
- **Auth path regexes anchored to a path segment** (nginx locations, Apache,
  scorer `AUTH_RE`, fail2ban auth filter): `/authors/...`, `/tokenomics`,
  `/verify-email-preview` no longer get the 5 req/min login limit or count as
  auth traffic.
- **`set_real_ip_from` no longer ships `10.0.0.0/8` / `172.16.0.0/12` active** in
  `deploy/nginx.conf.example`: behind Docker's published ports every client is
  the bridge gateway, which made X-Forwarded-For client-controlled.
- **GET fallback cannot bypass headless detection in block mode:** new
  `AGENTWALL_GET_FALLBACK=auto|on|off` (`auto` = off in `block` mode).
- HTTPS requirement for the JS challenge is documented next to the listener.

### Fixed (tooling)

- Restored `.github/workflows/ci.yml` (unit/config/Lua, preflight, real e2e,
  Linux validation); the config tests and docs referenced it but it was missing.
- `tests/e2e-real/run.sh` failed on native Linux Docker: the `mktemp -d` (0700)
  workdir was unreadable by the OpenResty `nobody` workers. Permissions are now
  set explicitly.

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
- **Online training poisoning fixed:** HST and the population percentiles now
  learn only from human-like, non-hard events. Previously every event was learned,
  so repeated attack traffic (e.g. headless enumeration) became "normal" within
  one session and stopped triggering the challenge; high-scoring attacks also
  raised P99 above quieter families. Tracing showed anomaly dropping 0.92→0.35
  and P99 rising to 0.648 while the headless suspicion was 0.59. Old
  checkpoints may already contain attack-trained state: delete `--state` once
  after upgrading (cold start + warmup).

### Added

- **Multi-seed evaluation harness** (`benchmarks/`, `docs/EVALUATION.md`):
  compares WAF-only, anomaly-only, challenge-only, the full pipeline, a naive
  union and ablations on a labelled synthetic stream, with separate
  training/evaluation seeds. It reports false-block, benign-challenge,
  challenge failure/completion, missed attacks, marginal-over-WAF and
  equal-disruption comparisons. Headline: at 0% benign-challenge budget the full
  stack reaches 40.5% recall vs 28.1% for WAF-only (0 false blocks), but costs
  ~25× WAF CPU, is not faster, has no measured false-positive advantage, and
  still misses distributed low-and-slow and spoofed-human headless agents. A
  benign false-positive guardrail (`benchmarks/fp_stress.py`) adds seven
  adversarial-benign families: 2,610 benign key-seeds across 3 seeds measured
  0 false blocks, 0 benign challenges, 0 challenge failures at production
  defaults. The document specifies formulas, state, transition rules, traces,
  threats to validity and the experiments needed to make production claims.
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
  Unreleased adds the source-derived Strix/ARTEX/CyberStrikeAI profiles (72 assertions).
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
