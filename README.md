# AgentWall

**Vendor-agnostic, layered defense against autonomous AI/LLM penetration agents.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![OpenResty](https://img.shields.io/badge/edge-OpenResty%20%7C%20nginx-009639)
![Redis 7](https://img.shields.io/badge/verdict%20store-Redis%207-DC382D)
![status](https://img.shields.io/badge/status-v0.1.0-orange)

Agentic pentest tools (LLM-driven scanners and autonomous agents) behave unlike
classic scanners: they enumerate → probe → authenticate, **keep going after
403/404/429**, rotate source IPs, mutate payloads, and increasingly drive a real
headless browser. Static signatures catch only the noisy legs.

AgentWall is a complete, self-hostable defense stack that raises cost and gives
you the signal to respond:

- **Edge WAF + rate/connection limits** with a structured access log
- **Behavioural fail2ban jails** (enumeration bursts, credential stuffing, persistence)
- **Streaming unsupervised ML scorer — HalfSpaceTrees** (Half-Space Trees via
  [`river`](https://riverml.xyz/), `river~=0.21.0`) over per-key rolling
  features, with population-relative scoring, human-ness gating, IPv6 /64
  aggregation, and a measured ~7k events/s per process
- **Verified JS challenge** with **headless/automation detection**
  (webdriver, CDP, correlated plugin/WebGL/PDF surfaces, Client-Hints consistency,
  timing) and signed IP-bound clearances
- **Source-derived validation against real agents**: Strix's default sandbox
  browser and Kali toolchain, and ARTEX's enrichment/WebFetch/scanner defaults,
  are blocked in the shipped end-to-end test (see
  [docs/AGENT-VALIDATION.md](docs/AGENT-VALIDATION.md))
- **Prometheus metrics + 23 alert rules**, dry-run defaults, staged rollout, instant rollback
- **Tests you can trust**: unit/config suites, a real Docker end-to-end
  (Redis + OpenResty + real scorer), and Linux-native config validation

> **Honest framing — read this first:** no proxy/WAF layer can "block all AI
> pentests". AgentWall is a *cost, detection and response* layer. The durable
> closers remain application security: MFA, server-side authorization, fast
> n-day patching and reduced attack surface. See [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).
> Every enforcement path fails **open** and is rolled out in stages.

---

## Architecture

```
                         ┌──────────────────────────────────────────────┐
 client / agent ────────►│  CDN / L7 LB (optional; sets X-Forwarded-For) │
                         └───────────────────┬──────────────────────────┘
                                             ▼
                 ┌───────────────────────────────────────────────────────┐
                 │  OpenResty / nginx edge                               │
                 │  1. real_ip            (trusted CDN ranges only)      │
                 │  2. limit_req/conn     (preaccess, cheapest filter)   │
                 │  3. access_by_lua      ──► Redis GET verdicts          │
                 │       ├─ 403 hard block                                │
                 │       ├─ 429 verified JS challenge + headless report   │
                 │       └─ allow                                         │
                 │  4. WAF (ModSecurity/CRS optional)                    │
                 │  5. access_log agentwall (xff, ua_flag, probe)         │
                 └───────────────────┬───────────────────────────────────┘
                                     ▼
                                app backend

 out-of-band (never inline):
 access_log ──► scorer/agentwall_scorer.py ──► Redis  agentwall:block/challenge/cleared/headless
                                     └───────► fail2ban-client banip (optional)
```

A scorer crash or Redis outage degrades to "no new verdicts", never downtime.

## Defense layers

| Layer | What it does | Where |
|-------|--------------|-------|
| [`waf/`](waf/) | rate/conn limits, marker maps, automation-UA tagging, structured log | reverse proxy |
| [`fail2ban/`](fail2ban/) | behavioural + auth jails, manual-ban jail for the scorer | proxy host |
| [`scorer/`](scorer/) | streaming anomaly scorer → graduated verdicts | worker service |
| [`nginx-lua/`](nginx-lua/) | inline 403 + verified PoW + **headless detection** | OpenResty |
| [`deploy/`](deploy/) | Docker Compose, systemd unit, secrets, logrotate, Prometheus rules, preflight/Linux validators | ops / CI |
| [`tests/`](tests/) | unit, config-regression, Lua, and **real** end-to-end tests | CI |

## Quick start (single node)

```bash
# 1. Secrets (matching 0600 files for compose / systemd / nginx)
./deploy/gen-secrets.sh --out /root/agentwall-secrets
cp /root/agentwall-secrets/compose.env deploy/.env

# 2. Edge: install OpenResty + the Lua layer, then the complete config
install -d /etc/nginx/lua && install -m 0644 nginx-lua/agentwall_*.lua /etc/nginx/lua/
install -m 0644 deploy/nginx.conf.example /etc/nginx/nginx.conf   # edit <-- EDIT markers
openresty -t && systemctl reload openresty

# 3. Scorer (dry-run by default) + Redis
docker compose -f deploy/docker-compose.yml up -d
docker compose -f deploy/docker-compose.yml logs -f scorer
```

Verify before traffic:

```bash
./deploy/preflight.sh --use-xff --backend redis   # log format, secrets, config regressions
./deploy/validate-linux.sh                        # systemd/fail2ban/Apache/OpenResty in Docker
./tests/run-tests.sh                              # 82 Python + 219 Lua assertions
./tests/e2e-real/run.sh                           # real 403/challenge/headless/agent profiles (64 assertions)
```

Then roll out in stages — shadow (dry-run) → challenge-only → enforce. Do not
skip the shadow phase: thresholds and the ML baseline must fit **your** traffic.
Full runbook: [deploy/DEPLOYMENT-production.md](deploy/DEPLOYMENT-production.md).

## Headless-browser detection

The challenge is no longer just "solve a PoW": the client reports
`navigator.webdriver`, CDP artifacts, plugin/MIME surfaces, `window.chrome`,
WebGL renderer (SwiftShader/software), languages, screen/outer geometry and
solve timing. A positive verdict writes `agentwall:headless:<key>`, which:

- the Lua layer denies on challenged requests when `AGENTWALL_HEADLESS_MODE=block`, and
- the scorer treats as a **hard block** (even if the client solved the PoW).

Start in `AGENTWALL_HEADLESS_MODE=mark` (default): detect, log, mark — no block.
Switch to `block` after reviewing false positives. This reliably catches default
Playwright/Puppeteer/headless Chromium; stealth-patched browsers can spoof these
surfaces, so treat it as advisory signal (details:
[nginx-lua/README.md](nginx-lua/README.md), [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)).

## Detection model: Half-Space Trees (HST)

The scorer's anomaly model is **`river.anomaly.HalfSpaceTrees`**
([Half-Space Trees](https://riverml.xyz/latest/api/anomaly/HalfSpaceTrees/)),
pinned via `river~=0.21.0`. It is **streaming and unsupervised**: no labelled
attack dataset is needed; it learns your traffic baseline online and scores how
unusual a key's current session shape is relative to that baseline.

Per event the scorer:

1. updates a per-key sliding-window feature vector (rate, miss/deny/auth ratios,
   path entropy, timing regularity, persistence, probe/multistage, human-ness inputs);
2. calls `score_one(x)` then `learn_one(x)` (score-then-learn, so the point is
   not judged against itself);
3. combines the HST score with human-ness and behavioural boosts, compares it
   with population percentiles (P95/P99) and absolute floors;
4. publishes a watch/challenge/block verdict to Redis; the edge enforces it.

Operationally important details:

- **Geometry** is configurable: `--hst-trees` (default 10), `--hst-height`
  (8), `--hst-window` (250) — river's defaults. Cost and memory scale with
  `trees × 2^height`. The previously shipped 25 trees / height 15 geometry was
  ~1.6M nodes (~500 MB, <500 events/s); after measurement the defaults were
  changed (see [Performance](#performance)).
- **Bounded state**: HST memory is fixed; per-key windows are LRU-capped with
  `--max-ips` and evicted after `--idle-evict`.
- **Warmup and drift**: no action before `--warmup` (800 events). Streaming
  models can slowly learn a sustained attack as "normal"; review weekly, delete
  `--state` to retrain, and keep the behavioural hard signals as the anchor.
- **Checkpoints**: atomic `--state` file; corrupt checkpoints are ignored
  (cold start, metric increment). Changing HST geometry requires deleting the
  checkpoint (the scorer warns on mismatch).
- **Batch replay**: `--once` processes a log from start to EOF for baseline
  backfill or benchmarking.

HST is one signal, not a classifier: enforcement also depends on population
percentiles, human-ness, hard behavioural signals, and the Lua headless marker.
Flags and capacity: [scorer/README.md](scorer/README.md); full pipeline:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Performance

Measured single-process, one core, real `HalfSpaceTrees` (`river`) model, no
Redis verdict writes
(Apple Silicon, Python 3.9):

| Workload | Wall time | Throughput | Max RSS |
|----------|-----------|------------|---------|
| 100k events, 3k IPs | 13.7 s | ~7,300 events/s | 158 MB |
| 100k events, 100k IPs | 14.7 s | ~6,800 events/s | 349 MB |

Size for peak access-log line rate and shard by client-IP hash before raising
model complexity. `--once` replays a log once (baseline backfill/benchmarks).

**Controlled evaluation (multi-seed, with limitations):**
[docs/EVALUATION.md](docs/EVALUATION.md) + [`benchmarks/`](benchmarks/). At a
0% benign-challenge budget the full stack reaches 40.5% recall vs 28.1% for
WAF-only with 0 false blocks; it is **not** faster or cheaper (~25x WAF CPU), has
no measured false-positive advantage, and still misses distributed low-and-slow
and spoofed-human headless agents. A benign stress gate (7 adversarial-benign
families, 2,610 key-seeds across 3 seeds) measured **0 false blocks / 0 benign
challenges** with production defaults. Read the limitations before quoting
numbers.

---

Licensed under the [MIT License](LICENSE) © 2026 AgentWall contributors.
