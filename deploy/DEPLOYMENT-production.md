# Production deployment runbook — AgentWall defense stack

How and where to run the pieces, safely, in production. Rollout is staged and
everything fails **open**: a broken scorer or an unreachable Redis degrades to
"no new verdicts", never to downtime.

| Component | Role | Where it runs |
|-----------|------|---------------|
| [`waf/nginx-agentwall.conf`](../waf/nginx-agentwall.conf) / [`waf/apache-agentwall.conf`](../waf/apache-agentwall.conf) | rate/conn limits, UA + marker filter, `agentwall` log format (incl. `xff=`) | reverse proxy / web tier |
| ModSecurity v3 + OWASP CRS | signature + anomaly-scoring WAF, body inspection | same proxy (module) |
| [`fail2ban/`](../fail2ban/) jails | behavioural bans from logs (persistence past 403/429) | proxy host(s) |
| [`scorer/agentwall_scorer.py`](../scorer/agentwall_scorer.py) | streaming per-IP scorer → challenge/block verdicts | worker service (own host/container) |
| Redis | shared verdict store + challenge state | small dedicated instance |
| [`nginx-lua/agentwall_challenge_block.lua`](../nginx-lua/agentwall_challenge_block.lua) (+ [`agentwall_common.lua`](../nginx-lua/agentwall_common.lua)) | inline 403 + verified JS proof-of-work challenge | OpenResty on the proxy |
| [`deploy/nginx.conf.example`](nginx.conf.example) | complete OpenResty edge config (real_ip, limits, log format, Lua hook, proxy) | proxy host |
| [`deploy/gen-secrets.sh`](gen-secrets.sh) + [`deploy/logrotate/agentwall`](logrotate/agentwall) | matching 0600 secrets for all components; rotate the agentwall access log | operator workstation / proxy host |
| [`deploy/prometheus/`](prometheus/) | scrape config + 23 alert rules for the scorer metrics | Prometheus |
| [`deploy/preflight.sh`](preflight.sh) · [`deploy/validate-linux.sh`](validate-linux.sh) · [`tests/run-tests.sh`](../tests/run-tests.sh) · [`tests/e2e-real`](../tests/e2e-real/) · [CI](../.github/workflows/ci.yml) | go-live checks, Linux config validation, unit/config tests, real 403/challenge test, pipeline gate | CI / operator workstation |

**Golden rule:** the ML scorer is a *detection and response aid*, not a wall. It
is never inline; it tails logs and writes verdicts. Roll out shadow →
challenge-only → enforce, and never enforce on day one.

---

## 1. Request path and phase order

Put real-IP recovery FIRST, so limits, logs, bans and scores all key on the true
client rather than your CDN/LB.

```
Client
  │
  ▼
CDN / L7 LB            (optional; sets X-Forwarded-For)
  │
  ▼
OpenResty / nginx  ──►  real_ip / mod_remoteip          (post-read phase: $remote_addr = client)
  │                     limit_req / limit_conn          (preaccess phase)
  │                     access_by_lua_file ───────────► Redis GET block/challenge (access phase)
  │                       └─ 403 hard block / 429 + PoW interstitial / allow
  │                     ModSecurity + CRS               (WAF)
  │                     access_log agentwall format         (includes ua_flag=, probe=, xff=)
  ▼
App backend
```

Out-of-band (reads the log, writes Redis / fail2ban — NOT in the hot path):

```
access_log ──► agentwall_scorer.py ──► Redis   agentwall:block:/challenge:/cleared:
                                       └──► fail2ban-client banip ──► iptables/nftables
```

Notes that matter in production:

- nginx runs `limit_req`/`limit_conn` in the **preaccess** phase, i.e. *before*
  `access_by_lua_file`. A rate-limited request gets nginx's plain 429 and never
  reaches the challenge/block Lua. Size `burst` so one challenged browser can
  load the interstitial and follow its redirect.
- `real_ip` is not optional behind a CDN: fail2ban reads the **first log field**
  (`$remote_addr`/`%a`) and cannot see the `xff=` tail. With real_ip configured,
  run the scorer **without** `--use-xff` (the first field is already the client).
  Do not parse the raw XFF tail in that topology: the left-most hop is
  attacker-controlled, and a mismatch between the scorer's key and the Lua's
  `$remote_addr` key silently disables enforcement. If real_ip is unavailable,
  `--use-xff` requires `--trust-proxies <proxy CIDRs>` (right-to-left,
  skipping trusted hops) and fail2ban remains unsafe behind a CDN.
- The Lua layer needs OpenResty (or nginx + lua-nginx-module + lua-resty-redis)
  and a Redis password supplied through nginx `env` declarations. See
  [`nginx-lua/README.md`](../nginx-lua/README.md) §2.

---

## 2. Single-node / small deploy

[`deploy/docker-compose.yml`](docker-compose.yml) is the source of truth; it runs
Redis + the scorer on the proxy host. OpenResty/nginx and fail2ban run on the
host, reading the same log/Redis.

```bash
# REDIS_PASS must exist: compose loads deploy/.env (not the repo-root .env)
echo "REDIS_PASS=$(openssl rand -hex 24)" > deploy/.env
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs -f scorer
```

What the file guarantees (and a regression test enforces — see
[`tests/test_configs.py`](../tests/test_configs.py)):

- the scorer `command:` is a **YAML list**, not a `>` scalar. A `# comment`
  inside a folded/literal scalar becomes literal argv and makes argparse exit 2
  → crash-loop. Never put comments inside `command:`.
- Redis runs with `--requirepass`, a healthcheck, and a loopback-only port;
  the scorer waits for `condition: service_healthy` and gets `REDIS_URL`
  (with the password) from the environment.
- the scorer defaults to **dry-run** (no `--enforce`/`--backend`) and its
  metrics/health endpoint is published only on `127.0.0.1:9101`.

Phase 3 adds three list items to the scorer command — `"--enforce"`,
`"--backend"`, `"redis"` — then `up -d --force-recreate scorer`. Keep the
comments above the service, never inside the list.

Bare metal: use [`deploy/agentwall-scorer.service`](agentwall-scorer.service). It also
ships **dry-run** by default, loads `REDIS_URL` from
`/etc/agentwall-scorer.env` (`EnvironmentFile=`), joins the `adm` group to read
`root:adm 0640` nginx logs, and is hardened (`ProtectSystem=strict`,
`NoNewPrivileges=true`, `RestrictAddressFamilies`, …). The `agentwall` service
account must exist (`useradd --system --no-create-home --shell /usr/sbin/nologin agentwall`).

Install [`deploy/logrotate/agentwall`](logrotate/agentwall) as `/etc/logrotate.d/agentwall`.
It reopens nginx with `USR1` after rotation so the scorer/fail2ban never follow
a renamed inode (Apache variant included in the same file). Keep fail2ban
`backend = auto`.

Generate the secrets (one Redis password shared by Redis, the scorer and the Lua
layer, plus a challenge-signing secret) with:

```bash
bash deploy/gen-secrets.sh --out /root/agentwall-secrets
#   compose.env   -> cp to deploy/.env
#   agentwall-scorer.env  -> /etc/agentwall-scorer.env (root:agentwall 0600) for the scorer unit
#   nginx.env     -> EnvironmentFile for the nginx/OpenResty service
```

Secrets belong in the environment, never in unit files or the repo:

| Secret | Consumed by | Where to put it |
|--------|-------------|-----------------|
| `REDIS_URL` (incl. password) | scorer | `EnvironmentFile=/etc/agentwall-scorer.env`, compose `environment`, or `--redis-url` |
| `AGENTWALL_REDIS_PASS` | nginx Lua | systemd environment for nginx (declared via `env AGENTWALL_REDIS_PASS;` in nginx.conf main) |
| `AGENTWALL_CHAL_SECRET` | nginx Lua | same; a long random value (`openssl rand -hex 32`) |
| `REDIS_PASS` | compose Redis | `deploy/.env` (never committed) |

---

## 3. Phased rollout — do not skip this

### Phase 0 — prerequisites (still no enforcement)

- [ ] `real_ip` / `mod_remoteip` configured; the access log's first field is the
      real client IP.
- [ ] `agentwall` log format applied, including `xff="$http_x_forwarded_for"`.
- [ ] Redis has `requirepass`; `AGENTWALL_REDIS_PASS` is declared in nginx.conf.
- [ ] OpenResty/Lua files installed, `AGENTWALL_CHAL_SECRET` set (required for
      phase 2+; without it the Lua layer fails **open with a CRIT log**).
- [ ] Edge config installed from [`deploy/nginx.conf.example`](nginx.conf.example)
      (edit every `<-- EDIT`) and `openresty -t` passes; or the `waf/` snippet
      merged into an existing config with `real_ip` configured.
- [ ] `bash deploy/preflight.sh` → no FAIL.
- [ ] `bash deploy/validate-linux.sh` → 0 FAIL (systemd unit, fail2ban
      `-t`/`fail2ban-regex`, Apache `-t`, OpenResty `-t`).
- [ ] `bash tests/run-tests.sh` → ALL CHECKS PASSED.
- [ ] Secrets generated with `deploy/gen-secrets.sh`, installed 0600, and not in
      the repo; logrotate installed.
- [ ] CI green (unit + preflight + linux-config + e2e-real).
- [ ] Optional but recommended: `bash tests/e2e-real/run.sh` (Docker; real
      403/challenge/headless + agent profiles against real Redis + OpenResty + the real scorer) → 64/64 PASS.
- [ ] **Upgrading?** Delete the old `/var/lib/agentwall/model.pkl` before
      starting this build: the learning policy changed (only human-like,
      non-hard events update HST/P99), and an old checkpoint may already have
      learned attack traffic. Cold start + warmup is expected.
- [ ] Run the scorer with `--enforce` **off** for at least a full weekly cycle,
      including a traffic peak.

### Phase 1 — shadow (days)

Scorer in dry-run (`--backend` unset). Only `WATCH` / `CHALLENGE(dry-run)` /
`BLOCK(dry-run)` log lines and metrics. Tune `--human-floor`, `--p-block`,
`--floor-block`, `--profile`, allowlist. Success = near-zero would-be blocks on
known-good traffic across the weekly cycle, and a clean
`agentwall_parse_errors_total` (log-format drift) / `agentwall_xff_missing_warnings_total`.

### Phase 2 — challenge-only

- Set `"AGENTWALL_CHAL_SECRET"` in the nginx environment and reload.
- Keep `AGENTWALL_HEADLESS_MODE=mark` (default): headless/automation detections are
  recorded (`agentwall:headless:*`, WARN log, `agentwall_headless_total`) but not blocked
  yet. Switch to `block` in phase 3.
- Enable the scorer with `--enforce --backend redis`, but keep `--p-block` high
  (e.g. `0.995`) so almost nothing hard-blocks; suspects get the JS PoW challenge.
- Watch the challenge-pass ratio, `agentwall_cleared_total`, and support tickets.
  A human solves a `diff=4` PoW in ~a second; browsers without WebCrypto (plain
  HTTP) cannot, so TLS is required.

### Phase 3 — enforce

Lower `--p-block` back to ~0.99. Hard signal and persist-after-challenge now
escalate to real blocks. Flip `AGENTWALL_HEADLESS_MODE=block` once the `mark`-mode
telemetry (`agentwall_headless_total`, `AgentWallHeadlessDetected`, WARN lines) has been
reviewed for false positives. Keep the behavioural fail2ban jails enabled if desired
(see §7 for their privilege caveat). Verify rollback (§4) before you need it.

### Phase 4 — automate response

Wire scorer blocks into alerting/session invalidation. Autonomous attacks are
fast; a human approval loop cannot keep up. Blocking already fires
automatically — make sure someone is paged by the metrics, not by the next
incident review.

---

## 4. Rollback

Enforcement state is only Redis keys with TTLs, so rollback is instant:

```bash
# 1. stop producing new verdicts (keep the service running in dry-run)
#    systemd: uncomment the dry-run ExecStart; compose: remove the three phase-3 items
docker compose -f deploy/docker-compose.yml up -d --force-recreate scorer

# 2. clear current verdicts (keys expire by themselves; this is immediate)
redis-cli -u "$REDIS_URL" --scan --pattern 'agentwall:block:*'      | xargs -r redis-cli -u "$REDIS_URL" DEL
redis-cli -u "$REDIS_URL" --scan --pattern 'agentwall:challenge:*'  | xargs -r redis-cli -u "$REDIS_URL" DEL
```

The Lua challenge layer fails open on Redis errors, so taking Redis down is also
a rollback (with an ERR/CRIT log line per 5s, not a site outage).

---

## 5. Scaling out (many proxies / high volume)

### 5.1 Shared verdict store

One Redis (or a small HA pair) read by every proxy; a block decided from any
proxy's log applies everywhere within the TTL. Private network, `requirepass`,
TLS if off-box, `maxmemory volatile-ttl` (evicting verdict keys is fail-open).

### 5.2 Shard scorers by client-IP hash

```
proxies ──► Vector / Fluent Bit ──► Kafka (topic: access, key = client_ip hash)
                                       │
                 ┌─────────────────────┼─────────────────────┐
                 ▼                     ▼                     ▼
            scorer-0              scorer-1              scorer-N
            (partitions 0..k)     (k..2k)               ...
                 └──────────────── all write ───────────────┘
                                       ▼
                              Redis (shared block/challenge keys)
```

Key Kafka by client-IP hash so an IP's whole session stays on one scorer and its
per-key window and population quantiles remain coherent. Replace `tail()` with a
Kafka consumer; the feature/scoring/action code is unchanged.

### 5.3 Tier-1 pre-filter first

Do not score traffic you already trust. Drop allowlisted CIDRs,
forward-confirmed good bots, and obvious-normal sessions (static ratio high,
referer present, browser UA, no 4xx) before the ML tier. Feed only the
*suspicious residue*.

### 5.4 IPv6 and IP correctness

The scorer aggregates IPv6 verdicts to a /64 by default (`--ipv6-prefix 64`) and
the Lua layer computes the identical key, so rotating inside one /64 does not
reset suspicion. Two caveats:

- `--ipv6-prefix 128` disables aggregation (more precise, easier to evade); a
  shared hosting/mobile /64 can be blocked as a unit at 64.
- **fail2ban bans one raw address**, not a /64 (the scorer deliberately passes
  the raw client IP). For IPv6 enforcement prefer `--backend redis` or an
  explicit nftables/ipset prefix rule. Documented in `fail2ban/README.md`.

The default topology uses real_ip and the scorer reads the log's first field;
do **not** enable `--use-xff` there. If you must parse XFF (no real_ip), pass
`--trust-proxies <proxy CIDRs>`; the scorer walks the chain right-to-left and
skips trusted hops, so a spoofed left-most value cannot poison allowlists or
verdict keys. A trusted proxy that does not append/strip XFF is still a
configuration risk outside the scorer's control.

---

### 5.5 Scorer sizing (measured)

Single scorer process, one core, no Redis verdict writes, default HST geometry
(10 trees / height 8 / window 250) — measured on Apple Silicon + Python 3.9:

| Workload | Wall time | Throughput | Max RSS |
|----------|-----------|------------|---------|
| 100k events, 3k IPs (realistic mix) | 13.7 s | ~7,300 events/s | 158 MB |
| 100k events, 100k IPs | 14.7 s | ~6,800 events/s | 349 MB |

Rules of thumb: ~150 MB base + **~2 KB per tracked IP** (at `/64`//`/32` keying),
so `--max-ips 200000` ≈ 400 MB + base (the unit caps at `MemoryMax=1G`). Size the
scorer for the *peak access-log line rate* and shard by client-IP hash (§5.2)
before raising model complexity. The previously shipped 25/15 geometry took
261 s / 503 MB for the same 100k events (~380 events/s); it is now configurable
via `--hst-trees/--hst-height/--hst-window`, and changing it requires deleting
`--state` (the scorer warns on geometry mismatch). Use `--once` to replay a log
into a fresh baseline/checkpoint offline.

## 6. Observability

The scorer exposes Prometheus text at `--metrics-bind:--metrics-port` (`/metrics`,
plus `/healthz`). Keep it loopback/private. Ready-made assets:

- [`deploy/prometheus/scrape.example.yml`](prometheus/scrape.example.yml) — scrape
  job `agentwall-scorer` (`127.0.0.1:9101`).
- [`deploy/prometheus/agentwall.rules.yml`](prometheus/agentwall.rules.yml) — 22 alert
  rules (availability, ingest, dependencies, detection), validated with
  `promtool check rules`; every rule documents its operational meaning and
  severity. Thresholds assume the shipped defaults (`--max-ips 200000`,
  `--warmup 800`, floors 0.55/0.40).

`deploy/validate-linux.sh`, `tests/e2e-real/run.sh`, and the CI workflow are the
verification gates for config and enforcement changes.

Key series and what to alert on:

| Series | Meaning | Alert idea |
|--------|---------|-----------|
| `agentwall_events_total` / `agentwall_learned_total` | throughput / model updates | sudden drop = log or scorer stall |
| `agentwall_parse_errors_total` | log lines the parser rejected | ratio spike = log_format drift |
| `agentwall_xff_missing_warnings_total` | `--use-xff` but the log has no `xff=` | >0 = XFF mode misconfigured (prefer real_ip + no `--use-xff`) |
| `agentwall_block_total` / `agentwall_hard_block_total` | blocks (all vs hard-signal) | rate spike = attack or FP storm |
| `agentwall_challenge_total` / `agentwall_cleared_total` | challenge issued vs passed | pass ratio collapse = challenge broken |
| `agentwall_headless_total` | challenged clients marked headless/automation (reads `agentwall:headless:*`) | sustained detections = automated pentest/scanner wave; alert rule `AgentWallHeadlessDetected` |
| `agentwall_redis_errors_total` / `AGENTWALL_REDIS...` CRIT logs | verdict store broken | page on any sustained rate |
| `agentwall_state_load_failures_total` | corrupt/incompatible checkpoint | >0 = model restarted cold |
| `agentwall_tracked_ips`, `agentwall_pop_size` | memory pressure | near `--max-ips` = raise or shard |
| `agentwall_block_cut`, `agentwall_watch_cut` | dynamic percentiles | weird values = baseline drift |
| `agentwall_warmup_done` | model warmup | 0 after the warmup window = problem |

Dashboards: challenge issued vs passed, top flagged ASNs, the human-ness
distribution of *blocked* keys (if blocked keys skew high human-ness, back off
`--human-floor`/`--p-block`), and `preflight`/`tests` status from CI.

Keep the logs the operations guidance calls for (auth, access, egress, DNS) with
retention decided in advance — autonomous attacks are fast, reconstruction is
post-hoc.

---

## 7. Control-plane hardening

- **Redis** decides who is blocked: private/loopback only, `requirepass`, TLS if
  off-box, `maxmemory volatile-ttl`. Never expose it.
- **Lua secrets**: pass `AGENTWALL_REDIS_PASS`/`AGENTWALL_CHAL_SECRET` through nginx
  `env` declarations backed by the service environment or a secrets file. A
  missing password previously produced a *silent* NOAUTH fail-open; now it is a
  rate-limited `CRIT` (`grep CRIT` your `error_log` during rollout). Rotating
  `AGENTWALL_CHAL_SECRET` invalidates all outstanding clearance cookies and
  challenge ids — harmless (clients re-solve), but do it deliberately.
- **fail2ban config parsing**: never put a `#` comment on the same line as an
  option in `jail.d`/`filter.d` — fail2ban only treats `;` as an inline comment,
  so the comment becomes part of the value (silent defaults, or a jail that
  fails to start). Keep comments on their own line; `deploy/validate-linux.sh`
  asserts the effective `maxretry/findtime/bantime` and that all three jails load.
- **fail2ban + sudo**: the scorer's `--backend fail2ban --fail2ban-sudo` runs
  `sudo -n /usr/bin/fail2ban-client set <jail> banip <ip>`; install
  [`deploy/sudoers.d-agentwall`](sudoers.d-agentwall) (one binary, one jail, one
  action) and validate with `visudo -cf`. Note the conflict: systemd's
  `NoNewPrivileges=true` blocks setuid `sudo`. Either keep NNP and use
  `--backend redis` (recommended), or set `NoNewPrivileges=false` and rely on the
  narrow sudoers rule as the only privilege boundary.
- **Scorer host**: no inbound exposure except the loopback metrics port. It only
  reads logs and writes Redis. State checkpoints are written atomically and a
  corrupt checkpoint is ignored (cold start) instead of crash-looping; keep
  `/var/lib/agentwall` (or the compose volume) owner-only.
- **Dependencies**: `requirements.txt` pins `river~=0.21.0` / `redis~=5.0`; rebuild
  and re-run `tests/run-tests.sh` on upgrades.
- **Secrets & logs**: use `deploy/gen-secrets.sh` (never hand-copied passwords),
  install `/etc/logrotate.d/agentwall`, and rotate the challenge secret deliberately
  (it invalidates outstanding clearance cookies only). The generated `secrets/`
  directory is git-ignored; keep it off shared storage.

---

## 8. Failure modes & safety

| Failure | Behaviour | Why it's safe |
|---------|-----------|---------------|
| Scorer crashes/lags | no new verdicts; existing TTLs expire | site serves normally |
| Redis down (Lua) | `return` → allow; ERR logged 1/5s | no downtime; WAF/rate-limit still on |
| Redis auth misconfigured | allow; **CRIT** logged 1/5s | loud, not silent (the old bug) |
| `AGENTWALL_CHAL_SECRET` missing | allow; CRIT logged 1/5s; no challenge | block keys still enforced (checked first) |
| Bad threshold / FP storm | drop `--enforce` or delete `agentwall:block:*` | instant rollback |
| Stealth headless browser / patched CDP | JS report can be spoofed; marker may not fire | detection is advisory; rely on app-layer + behavior/SIEM |
| `log_format` changed | parse errors / `xff` warnings → metrics alert | no silent mis-bans |
| Model drift (attack learned as normal) | review; delete `--state` to retrain | caught by review, not catastrophic |
| Corrupt state file | ignored, fresh model, `state_load_failures` +1 | no crash-loop |
| XFF spoofing through a lying edge | possible evasion/mis-ban | prevent with `real_ip` + trusted ranges; monitored by the xff metric |

Never make the request path depend on the scorer or Redis being up. The hot path
degrades to "rate-limit + WAF + fail2ban only".

---

## 9. Go-live checklist

- [ ] real_ip configured; the log's first field is the true client IP
      (`sudo -u agentwall head -1 /var/log/nginx/agentwall_access.log`).
- [ ] `agentwall` log format includes `ua_flag=`, `probe=`, `xff=`.
- [ ] Topology decision recorded: real_ip + scorer **without** `--use-xff`
      (default), or no real_ip + `--use-xff --trust-proxies <CIDRs>`.
- [ ] Good-bot FCrDNS verification on; CDN/monitoring/scanner CIDRs allowlisted.
- [ ] Redis private + `requirepass`; `AGENTWALL_REDIS_PASS` and `AGENTWALL_CHAL_SECRET`
      declared in nginx.conf and present in the environment.
- [ ] `bash deploy/preflight.sh` → 0 FAIL (add `--backend redis`
      and, at phase 3, `--phase 3`).
- [ ] `bash tests/run-tests.sh` → ALL CHECKS PASSED (CI gate).
- [ ] Phase 1 shadow ran across a full weekly cycle incl. a traffic peak;
      near-zero would-be blocks on legit traffic.
- [ ] Phase 2 challenge-only trialled; pass ratio and tickets acceptable;
      HTTPS-only verified.
- [ ] fail2ban (if used) runs least-privileged; `agentwall-ml` jail exists; the
      NNP-vs-sudo decision is recorded.
- [ ] `AGENTWALL_HEADLESS_MODE=mark` observed during shadow; switch to `block` for
      phase 3 and confirm `agentwall_headless_total` + `AgentWallHeadlessDetected` behave.
- [ ] Prometheus scraping the scorer (`deploy/prometheus/scrape.example.yml`) and
      the 23 rules loaded (`agentwall.rules.yml`) with alert routing tested.
- [ ] Rollback tested: dropping `--enforce` / deleting `agentwall:block:*` restores
      normal instantly.
- [ ] Tier-1 pre-filter in place before scoring (if volume is high).
- [ ] Paired with the real closers: MFA, fast n-day patching, server-side authz
      (anti-IDOR), reduced attack surface.

---

## 10. What this stack still does not close

Low-and-slow, low-volume traffic spread across many rotating source IPs stays
under per-key windows. That belongs at the SIEM layer with same-source
multi-stage correlation (enumerate → probe → auth within one window), not at the
reverse proxy. Every layer here raises cost; none of them is a wall.
