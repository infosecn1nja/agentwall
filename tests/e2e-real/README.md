# `tests/e2e-real/` — real end-to-end enforcement test

This is the "does it actually block?" test: **no stubs, no dry-run**. It starts
isolated, loopback-only Docker containers and proves the whole chain:

```
synthetic access log ──► REAL scorer (river model + redis-py)
                            ├── agentwall:block:<ip>      ──► OpenResty/Lua ──► HTTP 403
                            ├── agentwall:headless:<ip>   ──► REAL scorer hard-block ──► HTTP 403
                            └── agentwall:challenge:<ip>  ──► OpenResty/Lua ──► HTTP 429
                                                          └─ PoW + human report ──► 200/302 + signed cookie ──► HTTP 200
                                                          └─ headless report ──► 403 + marker
```

## Requirements

- Docker (daemon reachable) — the test starts `redis:7-alpine` and
  `openresty/openresty:alpine`, then removes them.
- `curl`, `python3` (with `venv` support).
- Network on the first run (pull images, `pip install river redis`).
- Free loopback ports **18080** and **6390** (override with env vars below).

## Run

```bash
bash tests/e2e-real/run.sh

# custom ports / reuse an existing venv with river+redis installed
AGENTWALL_E2E_HTTP_PORT=18081 AGENTWALL_E2E_REDIS_PORT=6391 bash tests/e2e-real/run.sh
AGENTWALL_E2E_VENV=/path/to/venv bash tests/e2e-real/run.sh
```

Exit code 0 = every check passed. Logs and the served challenge pages are kept
in the printed work directory (`$TMPDIR/agentwall-e2e.*`).

## What it checks (72 assertions)

| Group | Proves |
|-------|--------|
| A | a Redis `agentwall:block:<ip>` key makes OpenResty return **403**; other IPs stay **200**; TTL is honoured |
| B | challenged IP gets **429** interstitial; a solved SHA-1 PoW + human environment report POSTed to `/__agentwall_verify` returns **200** + signed `agentwall_clr` cookie; cookie passes (**200**); `agentwall:cleared` written and challenge deleted; forged legacy cookie rejected (**429**); cookie is **IP-bound**; **default Playwright/Puppeteer headless report → 403 + `agentwall:headless` marker**; the marker denies the next challenged request; automation User-Agent is marked; legacy GET `?agentwall_id&agentwall_pow` fallback still works |
| C | IPv6 aggregation: blocking `2001:db8::/64` rejects `2001:db8::1` and allows `2001:db8:1::1` |
| D | the **REAL scorer** (real `river` model, real Redis client) reads a log line and writes `agentwall:block` → OpenResty returns **403**; a non-hard suspicious IP gets `agentwall:challenge` → **429**; solving that scorer-issued challenge gives **302 → 200** and `agentwall:cleared`; and the scorer converts the Lua `agentwall:headless` marker into a hard block (**D9–D11**) |
| F | **source-derived agent/scanner profiles**: ARTEX `artex-enrich/1.0` / `norma/0.4` / `artex-selfupdate`, and Strix's Kali toolchain defaults (nuclei, sqlmap, ffuf, nmap, dirsearch, wafw00f, arjun, katana, subfinder, naabu, gospider, interactsh, nikto, gobuster, feroxbuster, wpscan, masscan, zgrab, httpx) are denied **403**, while a normal browser UA and generic `curl` / `python-httpx` are allowed (false-positive controls). See [docs/AGENT-VALIDATION.md](../../docs/AGENT-VALIDATION.md). |
| E | no `[error]`/`[crit]` lines in the OpenResty error log during the whole run |

## Test-only settings (not production recommendations)

- `set_real_ip_from 0.0.0.0/0` + `real_ip_header X-Forwarded-For`: the only way
  to act as many client IPs from one host. **Never** do this in production.
  The scorer in the test reads the log's first field (already the test client)
  and runs **without** `--use-xff`; production uses the same default with a
  narrow real_ip trust range.
- Plain HTTP inside the test: the `Secure` clearance cookie still works because
  we replay it manually; browsers need HTTPS for `crypto.subtle`.
- `AGENTWALL_POW_DIFF=3`: faster PoW so the test finishes in seconds.
- `AGENTWALL_HEADLESS_MODE=block`: the test asserts blocking; production starts with
  the default `mark` (detect + marker + WARN, no block) until phase 3.
- `--floor-block 0.15`: the `river` model is cold in a 17-event test, so its
  anomaly score is 0; the lowered floor exercises the *challenge action path*.
  Detection quality itself needs the shadow/baseline phase (real traffic, warmup).
- Ephemeral credentials (`testpass-e2e`, random-ish secret) inside throwaway
  containers.

## Caveat found by running this test

A location that answers from the **rewrite phase** (`location / { return 200; }`,
`return 301`, some `rewrite ... last;`) never reaches the **access phase**, so
`access_by_lua_file` is skipped and neither the block nor the challenge is
enforced. Protect real assets with `proxy_pass`, `root`/static, `content_by_lua*`
or `error_page` — see `nginx-lua/README.md` §2. The test harness itself uses
`content_by_lua_block` for the origin for exactly this reason.

## Why this is not in `tests/run-tests.sh`

The default suite must stay fast, offline and dependency-free (no Docker). Run
this test before a rollout, after changing the Lua layer, the Redis key contract,
or the scoring/action code.
