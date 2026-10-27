# Architecture

This document describes the moving parts of AgentWall and the contracts that
couple them. If you change a key, cookie, env var, log field or verdict format,
update this file and the tests that pin the contract.

## Design goals

1. **Never be in the request path for decisions.** The scorer tails logs
   out-of-band and publishes verdicts; the edge only reads them.
2. **Fail open on infrastructure faults, loudly on configuration faults.**
   Redis down → allow + rate-limited ERR. Redis NOAUTH / missing secret →
   fail open + CRIT. A config typo must be visible in logs and metrics.
3. **Per-key shape, not volume.** Population-relative scoring + human-ness
   gating so a flash crowd is not flagged just for size.
4. **Bounded resources.** LRU caps on per-IP state, bounded DNS verification,
   atomic checkpoints, configurable model geometry.
5. **Reversible enforcement.** Verdicts are TTL keys; rollback is dropping
   `--enforce` or deleting keys, not editing firewall rules.

## Components

| Component | Process | Responsibility |
|-----------|---------|----------------|
| Edge proxy | OpenResty/nginx | real_ip, rate/conn limits, marker maps, log_format, inline Lua enforcement |
| WAF (optional) | ModSecurity + CRS | signature/anomaly rules, body inspection |
| Verdict store | Redis 7 | block/challenge/cleared/headless markers, challenge ids |
| Scorer | Python 3.9+ | parse log → per-key features → ML score → verdicts → fail2ban (optional) |
| fail2ban | host daemon | behavioural jails, optional packet-level bans driven by the scorer |
| Observability | Prometheus | scrape `/metrics`, 23 alert rules |
| Validators | shell + Docker | preflight, Linux config validation, real e2e |

Trust boundary: the edge trusts `real_ip` ranges only; the scorer trusts the
access log and Redis; the application is *not* trusted to enforce this stack.

## Request path

```
real_ip            post-read      $remote_addr becomes the true client
limit_req/conn     preaccess      cheapest rejection (429)
access_by_lua      access         block / verify challenge / allow
WAF (optional)     access         ModSecurity phase
proxy_pass/root    content        app or static
access_log         log phase      agentwall format with xff/ua_flag/probe
```

Important: a location that finishes in the **rewrite phase** (`return 200/301`,
some `rewrite ... last`) never reaches the access phase, so the Lua layer is not
enforced there. Protect content with `proxy_pass`, `root`/static,
`content_by_lua*` or `error_page`.

## Verdict store contract

All keys are prefixed and use the normalized `ip_key`:
IPv4 = dotted quad; IPv6 = canonical /64 network address (configurable
`AGENTWALL_IPV6_PREFIX`); IPv4-mapped → IPv4.

| Key | Value | TTL | Writer | Reader |
|-----|-------|-----|--------|--------|
| `agentwall:block:<ip_key>` | `"1"` | scorer `--block-ttl` (1800s) | scorer | Lua |
| `agentwall:challenge:<ip_key>` | `"1"` | scorer `--challenge-ttl` (600s) | scorer | Lua |
| `agentwall:cleared:<ip_key>` | `"1"` | `AGENTWALL_CLR_TTL` (600s) | Lua | scorer |
| `agentwall:headless:<ip_key>` | `"1"` | `AGENTWALL_HEADLESS_TTL` (3600s) | Lua | Lua, scorer |
| `agentwall:chal:<id>` | `<ip_key>\|<issued_ms>` | 180s | Lua | Lua |

Precedence at the edge: **block > headless marker (block mode) > valid
clearance cookie > challenge > allow**.

`ip_key` parity between Python and Lua is mandatory; it is unit-tested and
`deploy/validate-linux.sh` re-checks the Redis contract. A mismatch silently
disables enforcement.

## Verified challenge protocol (v3)

1. Challenged request → **429** HTML interstitial (no external assets).
2. Client solves a SHA-1 proof-of-work over `id:nonce` with `diff` leading zero
   hex chars (difficulty `AGENTWALL_POW_DIFF`, default 4).
3. Client collects an environment report (`navigator.webdriver`, CDP artifacts,
   plugins/MIME, `window.chrome`, WebGL vendor/renderer, languages, geometry,
   timezone, `pdfViewer`, `hardwareConcurrency`, timing) and
   `POST /__agentwall_verify` with `{id, nonce, report}` (≤4096 bytes).
4. Server: block check → single-use id + IP binding → PoW → headless score
   (`AGENTWALL_HEADLESS_BLOCK` 0.60, suspect 0.35). The score uses the JS
   environment report plus server-side signals (Client-Hints vs UA consistency)
   and correlates weak surfaces (empty plugin list + software rasterizer + no
   PDF viewer) so a UA-only stealth shortcut does not pass. Decision:
   - human / suspect → `200 {ok:true,next}` + signed IP-bound clearance cookie
     + `agentwall:cleared`, challenge key removed.
   - automation in `block` mode → `403 {ok:false,reason:"automation"}` +
     `agentwall:headless` marker, no clearance.
   - invalid/replayed/bad body → `429 {ok:false,reason:"retry"}`.
   - infra fault → fail open (`200` without cookie), CRIT/ERR rate-limited.
5. Legacy `GET ?agentwall_id&agentwall_pow` fallback verifies id+PoW and issues
   the cookie without a report; it never marks headless on its own.

Clearance cookie: `agentwall_clr=v1:<exp>:<hex(hmac_sha1(secret,
ip_key|exp))>`, `HttpOnly; Secure; SameSite=Lax; Path=/`, capped by
`AGENTWALL_CLR_TTL`; bound to the `ip_key` and replay-tested.

Headless signals are advisory: a stealth-patched browser (or a bot that posts
the report itself) can spoof them. The marker is a hard signal for the scorer
but is not proof of humanity.

## Scorer pipeline

```
line → parse (combined + agentwall tails) → per-ip_key sliding window
     → features (rate, miss/deny/auth ratios, entropy, regularity,
                 persistence, probe, UA flag, multistage, human-ness inputs)
     → river HalfSpaceTrees (HST) score (score-then-learn)
     → humanness (web|api profile) → suspicion
     → population quantiles P95/P99 with absolute floors
     → decide(): hard signal | human floor | block/challenge/watch
     → action: Redis verdicts / fail2ban (debounced) / logs + metrics
```

The anomaly model is `river.anomaly.HalfSpaceTrees` (Half-Space Trees,
`river~=0.21.0`). Default geometry is river's `n_trees=10, height=8,
window_size=250` (O(trees·2^height)); the old 25/15 defaults were ~1.6M nodes. Options:
`--hst-trees/--hst-height/--hst-window`. Changing geometry requires deleting
`--state` (a warning is logged). `--once` replays a log for backfill/benchmarks.

Hard signals (block immediately, subject to cooldown): multistage
(enumeration + probe + auth in one window), explicit automation UA flag,
`probe>=2 and persistence>0.5`, and the Lua headless marker for challenged keys.

## Configuration surface

| Namespace | Examples |
|-----------|----------|
| Scorer CLI | `--enforce`, `--backend`, `--profile`, `--human-floor`, `--p-block`, `--hst-*`, `--metrics-port`, `--state`, `--once` |
| Scorer env | `REDIS_URL`, `AGENTWALL_FAIL2BAN_CMD` |
| Lua env | `AGENTWALL_REDIS_HOST/PORT/PASS/DB/TIMEOUT_MS`, `AGENTWALL_CHAL_SECRET`, `AGENTWALL_POW_DIFF`, `AGENTWALL_CHAL_TTL`, `AGENTWALL_CLR_TTL`, `AGENTWALL_IPV6_PREFIX`, `AGENTWALL_HEADLESS_MODE/TTL/BLOCK/SUSPECT`, `AGENTWALL_MIN_SOLVE_MS` |
| Log format | `agentwall`: combined prefix + `rt= urt= ua_flag= probe= xff="..."` |
| Metrics | `agentwall_events_total`, `agentwall_parse_errors_total`, `agentwall_block_total`, `agentwall_challenge_total`, `agentwall_headless_total`, … |

Every `AGENTWALL_*` the Lua reads **must** be declared with `env NAME;` in the
nginx main context; `tests/test_configs.py` pins this (a missing declaration
silently falls back to defaults, e.g. headless `mark` instead of `block`).

## Fail-open matrix

| Fault | Edge behaviour | Scorer behaviour |
|-------|----------------|------------------|
| Redis unreachable | allow + ERR (1/5s) | log CRIT, keep running, verdicts lost |
| Redis NOAUTH/WRONGPASS | allow + CRIT | CRIT, fail open |
| Missing `AGENTWALL_CHAL_SECRET` | allow + CRIT; block keys still enforced | n/a |
| Scorer down | last TTL keys enforced until expiry | n/a |
| Corrupt checkpoint | n/a | ignored, fresh model, metric increment |
| Unknown/app error | normal request handling | n/a |

## Performance & sizing

~7,300 events/s per scorer process (100k realistic events in 13.7s, 158MB RSS);
~2KB per tracked IP key (100k keys → +191MB). Bound with `--max-ips`, size for
peak log line rate, shard by client-IP hash for scale. Full numbers in the
[scorer README](../scorer/README.md) and
[deployment runbook](../deploy/DEPLOYMENT-production.md).

## Changing the contract

When adding a key/cookie/env/field, update in one change:

1. `scorer/agentwall_scorer.py` (writer/reader + metrics)
2. `nginx-lua/agentwall_common.lua` / `agentwall_challenge_block.lua`
3. `deploy/nginx.conf.example` (`env` declaration), `deploy/gen-secrets.sh`
4. `tests/` (unit + env-contract) and `tests/e2e-real/`
5. This file + `nginx-lua/README.md` + the runbook
