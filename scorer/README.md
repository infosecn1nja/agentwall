# AgentWall ML scorer — setup

Streaming, unsupervised anomaly scoring over nginx/Apache access logs, with
graduated action (log → watch → verified challenge → block). The model is
**`river.anomaly.HalfSpaceTrees`** (Half-Space Trees, `river~=0.21.0`): online,
label-free, and bounded in memory. It catches the adaptive multi-stage behaviour
that static WAF signatures miss. **Not** an unbypassable wall — a
scoring/response aid. Run dry-run first, baseline, then enforce.

Two implementations live here:

| File | Use it for |
|------|------------|
| `agentwall_scorer.py` (v2) | **production** — population-relative cutoffs, human-ness gating, FCrDNS good-bot checks, challenge feedback, IPv6 /64 aggregation, bounded LRU state, atomic checkpoints, Prometheus metrics |
| `agentwall_scorer_v1.py` (v1) | reference/rollback only — fixed thresholds, deprecated |

## 1. Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

Make nginx/Apache log the fields the scorer reads — use the `agentwall` log_format
from `waf/nginx-agentwall.conf` (it appends `ua_flag=`, `probe=` and
`xff="$http_x_forwarded_for"`). Standard combined format still parses, but the
three extra features then stay 0.

**Client IP:** run the scorer **without** `--use-xff` when nginx `real_ip` /
Apache `mod_remoteip` is configured — the log's first field is already the real
client, and the raw `xff=` tail is attacker-controlled. Only if real_ip is
unavailable may you use `--use-xff`, and then you **must** pass
`--trust-proxies <your proxy CIDRs>`: the scorer walks XFF right-to-left and
skips trusted proxy hops (the left-most value is never trusted).

## 2. Baseline in dry-run (no blocking, the default)

```bash
python3 agentwall_scorer.py \
    --log /var/log/nginx/agentwall_access.log \
    --profile web \
    --metrics-port 9101 --metrics-bind 127.0.0.1 \
    --state /var/lib/agentwall/model.pkl
```

Watch `WATCH` / `CHALLENGE(dry-run)` / `BLOCK(dry-run)` lines and
`http://127.0.0.1:9101/metrics` for a day or two of normal traffic, including a
peak day. If legit clients trip it: raise `--human-floor`/`--floor-block`, lower
`--p-block`, or use `--allowlist` / `--allowlist-file`. Enforce only when the
would-be block rate on known-good traffic is ~zero.

## 3. Enforce

Verdicts are published to Redis (read by `nginx-lua/`), to fail2ban (iptables
ban), or both. Redis is the recommended path: TTL-based, instant rollback,
and it supports the verified challenge.

```bash
# Redis (fail-open, self-expiring):
REDIS_URL='redis://:PASSWORD@127.0.0.1:6379/0' \
python3 agentwall_scorer.py --log /var/log/nginx/agentwall_access.log \
    --enforce --backend redis

# fail2ban manual-ban jail (needs the sudoers entry + --fail2ban-sudo
# because the scorer must not run as root):
python3 agentwall_scorer.py --log /var/log/nginx/agentwall_access.log \
    --enforce --backend fail2ban --fail2ban-sudo --jail agentwall-ml
```

Redis keys written by the scorer (per normalized key; IPv6 is aggregated to a
/64 by default via `--ipv6-prefix`):

| Key | Meaning |
|-----|---------|
| `agentwall:block:<key>` | hard 403 while it exists (`--block-ttl`, default 1800 s) |
| `agentwall:challenge:<key>` | serve the verified JS challenge (`--challenge-ttl`, 600 s) |
| `agentwall:cleared:<key>` | written by `agentwall_challenge_block.lua` after a valid PoW; the scorer then suppresses non-hard blocks for that key |
| `agentwall:headless:<key>` | written by `agentwall_challenge_block.lua` when the human-verification JS report/timing says headless/automation; read by the scorer as a **hard signal** (blocks the key even if it solved the PoW) |

Challenge flow: suspicious → challenge key → OpenResty serves a JS proof-of-work
page → the client returns a valid nonce → the Lua layer sets a signed, IP-bound
clearance cookie and `agentwall:cleared` → the scorer leaves that key alone unless
the **hard** signal (multi-stage / bad UA / repeated probe) fires. The scorer
escalates to a block only if the key is still suspicious after
`--challenge-grace` seconds.

## 4. Run as a service

Use `deploy/agentwall-scorer.service` (systemd) or `deploy/docker-compose.yml`.
The shipped defaults are **dry-run** by design; the Phase-3 `--enforce` line is
commented in both files. Put secrets in `/etc/agentwall-scorer.env`
(`REDIS_URL=...`) or `.env` for compose; never in the unit/compose file.

## 5. Flags that matter

| flag | meaning |
|------|---------|
| `--enforce` / `--dry-run` | act for real / log only (dry-run is the default; they are mutually exclusive) |
| `--profile web\|api` | human-ness weighting: browser page-loading site vs JSON-only API |
| `--window` / `--min-events` | per-key feature window (60 s) / minimum requests before action (12) |
| `--warmup` | events learned before any action (800) |
| `--hst-trees` / `--hst-height` / `--hst-window` | HalfSpaceTrees geometry (defaults 10 / 8 / 250 = river defaults). Cost and memory scale with `trees × 2^height`; the old 25/15 defaults were ~1.6M nodes, ~500 MB and <500 events/s. Changing them requires deleting `--state` (the scorer warns if the checkpoint geometry differs). |
| `--once` | batch mode: read the whole log from the beginning to EOF and exit (baseline backfill / benchmarking; implies `--from-start`) |
| `--p-block` / `--p-watch` | population percentiles for block/challenge (0.99/0.95); only human-like, non-hard events update the population/model |
| `--floor-block` / `--floor-watch` | absolute suspicion floors (0.55/0.40) |
| `--human-floor` | never block a key at/above this human-ness (0.55) |
| `--challenge-grace` | seconds after the first challenge before escalating to block (120) |
| `--cooldown` | seconds between challenge/block/watch actions per key (120) |
| `--ipv6-prefix` | IPv6 aggregation for windows and bans (64; 128 = exact) |
| `--max-ips` / `--idle-evict` | LRU cap (200k) and idle eviction (600 s) |
| `--state` | model checkpoint path (atomic write, corrupt state is ignored) |
| `--metrics-port` / `--metrics-bind` | Prometheus `/metrics` + `/healthz` (0 = off) |
| `--use-xff` | resolve the client from XFF (right-most untrusted hop). **Requires** `--trust-proxies`; do **not** use it when real_ip/mod_remoteip already rewrites the first log field |
| `--trust-proxies` | comma CIDRs of your own edge proxies for `--use-xff` (env `AGENTWALL_TRUSTED_PROXIES`); the left-most XFF hop is never trusted |
| `--dns-timeout` | FCrDNS budget per lookup (0.8 s; spoofed-bot floods cannot stall the loop) |
| `--allowlist` / `--allowlist-file` | CIDRs never scored or blocked |
| `--fail2ban-sudo` / `--fail2ban-cmd` | run the ban through `sudo -n` / custom client path |
| `--redis-url` | default: `$REDIS_URL` or `redis://127.0.0.1:6379/0` |
| `--backend none\|fail2ban\|redis\|both` | where verdicts go |

Environment: `REDIS_URL` (default Redis URL), `AGENTWALL_FAIL2BAN_CMD` (default
`fail2ban-client`).

## 6. Verify before trusting it

```bash
bash deploy/preflight.sh               # config + connectivity + filters
bash tests/run-tests.sh                # unit + config regression tests
```

Before a rollout: `fail2ban-regex` your real log against the filters, check
`/metrics` for `agentwall_parse_errors_total` (log format drift),
`agentwall_redis_errors_total` (NOAUTH/down), and `agentwall_state_load_failures_total`.

## Capacity / sizing (measured)

Single process, 1 core, no Redis verdict writes, Apple Silicon + Python 3.9
(`river` 0.21.2, default HST geometry 10/8/250):

| Workload | Wall time | Throughput | Max RSS |
|----------|-----------|------------|---------|
| 100k events, 3k IPs (realistic mix) | 13.7 s | ~7,300 events/s | 158 MB |
| 100k events, 100k distinct IPs | 14.7 s | ~6,800 events/s | 349 MB |

Rough model: ~150 MB fixed (Python + numpy + model) plus **~2 KB per tracked
IP** at `/64`/`/32` keying. Size the scorer for your *peak* access-log line rate
(not requests/s if a CDN or access log fan-out multiplies lines), then add
headroom for Redis round-trips on the (rare) verdict path. `--max-ips` bounds
memory: 200k keys ≈ 400 MB + base, which fits the systemd unit's `MemoryMax=1G`.
If one process cannot keep up, shard by client-IP hash (see
`deploy/DEPLOYMENT-production.md` §5.2) — do not raise `--hst-height` to "make it
smarter"; that only multiplies cost.

For comparison, the previously shipped 25-trees/height-15 geometry took
**261 s** for the same 100k events (≈380 events/s) at **503 MB** — the defaults
were fixed for production and are now configurable.

## Honest limits

- **Evasion:** low-and-slow across rotating IPs stays under per-key windows;
  close that at the SIEM layer with same-source multi-stage correlation.
- **IPv6 /64 aggregation** (default) trades precision for catch rate: a shared
  hosting/mobile /64 can be blocked as a unit. Use `--ipv6-prefix 128` if that
  risk outweighs rotation evasion for you.
- **Baseline drift:** a sustained attack can slowly be learned as "normal" — a
  streaming trade-off. Review weekly; delete `--state` to retrain from clean.
- **False positives block real users.** Keep the allowlist current, run the
  shadow phase across a full weekly cycle, and prefer challenge over block.
- **Learning poisoning is blocked by policy:** only human-like, non-hard events
  update HST/P95/P99; attack traffic is scored but cannot normalise itself. This
  is measured in `docs/EVALUATION.md` (removing the floor drops recall).
- **Headless detection is advisory.** The `agentwall:headless:*` marker comes from
  a JS environment report + timing, so a stealth-patched browser (or a bot that
  posts the report itself) can spoof it. It reliably catches *default*
  Playwright/Puppeteer/headless Chromium; do not treat it as proof of humanity.
- **XFF is only as trustworthy as your edge.** Preferred setup: real_ip, scorer
  without `--use-xff`. If you must parse XFF, `--trust-proxies` is mandatory and
  parsing is right-to-left (skipping trusted hops); a client-supplied left-most
  value is never used. A trusted proxy that does not append/strip XFF remains a
  configuration risk outside the scorer's control.
- **Pickle state = code execution.** The `--state` checkpoint is a pickle; if an
  attacker can write to the state path, they can run code as the scorer. The
  scorer writes 0600, warns on group/other-accessible directories, and refuses
  symlinks, but the directory itself must be 0700 and owned by the service user.
- This complements — never replaces — MFA, fast patching, server-side authz.
