# `nginx-lua/` — inline enforcement for the AgentWall defense stack

Two OpenResty/`lua-nginx-module` scripts that sit in the nginx **access phase** and
turn the out-of-band ML scorer's verdicts into request-path enforcement:

| File | What it does |
| --- | --- |
| `agentwall_challenge_block.lua` | **Full enforcement (v3)**: hard 403 from `agentwall:block:*`, a signed JS proof-of-work challenge from `agentwall:challenge:*`, plus browser-environment reporting to `/__agentwall_verify` for headless/automation detection. Use this one. |
| `agentwall_redis_block.lua` | **Block-only** variant: just the 403 check. For deployments that do not want a challenge. |
| `agentwall_common.lua` | Pure-Lua helpers: `ip_key` normalization, hex, HMAC, clearance cookie, PoW check, env config. Has no `ngx` dependency and is unit-tested by `tests/lua/test_agentwall_common.lua`. |

Wire **one** of the two (they both do the block GET; stacking them just doubles
Redis round-trips). Point `access_by_lua_file` at
`agentwall_challenge_block.lua` unless you have a reason not to.

This layer is an **impedance/cost layer, not a wall**: a determined agent can
solve the PoW, spoof or avoid the headless signals, and rotate IPs. It exists to
make cheap scanners expensive, to give real browsers a way to prove themselves
so the scorer does not have to ban a flash crowd, and to surface an *advisory*
automation signal (v3, marker-first by default) for the scorer/SIEM.

---

## 1. Requirements

* OpenResty (or nginx + `lua-nginx-module` + `lua-resty-redis`).
  Needs `ngx.hmac_sha1`, `ngx.sha1_bin`, `ngx.md5`, `ngx.req.get_uri_args`,
  `ngx.encode_args`, `ngx.req.read_body`/`get_body_data` and `ngx.shared`.
* `lua-cjson` (`require "cjson.safe"`), bundled with OpenResty, is used only by
  the `/__agentwall_verify` handler. If it is missing the handler fails open
  (200 without clearance) and logs CRIT instead of 5xx.
* HTTPS. The clearance cookie is `Secure`; over plain HTTP browsers drop it,
  which would loop every visitor through the challenge. HTTP-only deployments
  must terminate TLS in front.
* Redis reachable from the nginx worker (loopback/private), with the same
  password the scorer uses.
* The Python scorer must normalize keys with the **exact same** `ip_key`
  algorithm (see §4) and must honour the same TTLs.

---

The repository also ships a complete, `openresty -t`-validated edge config:
[`deploy/nginx.conf.example`](../deploy/nginx.conf.example) (main + http + server
contexts, real_ip, limits, log format, this Lua hook, proxy timeouts). Start from
that instead of assembling the snippet below.

## 2. nginx.conf

`env` directives are only valid in the **main** context (outside `http {}`).
nginx strips undeclared environment variables from worker processes, so
`os.getenv()` returns `nil` for anything not declared here — that is the #1
cause of NOAUTH / "secret missing" surprises. See §10.

```nginx
# /etc/nginx/nginx.conf — MAIN CONTEXT (outside http {})
# Pass the operator's environment through to workers. Use `env NAME;` to
# inherit the value from systemd/the shell, or `env NAME=value;` to hard-code
# it in this file (then `reload` is enough; an inherited value needs a restart).
env AGENTWALL_REDIS_HOST;
env AGENTWALL_REDIS_PORT;
env AGENTWALL_REDIS_PASS;
env AGENTWALL_REDIS_DB;
env AGENTWALL_REDIS_TIMEOUT_MS;
env AGENTWALL_IPV6_PREFIX;
env AGENTWALL_CHAL_SECRET;
env AGENTWALL_POW_DIFF;
env AGENTWALL_CHAL_TTL;
env AGENTWALL_CLR_TTL;
env AGENTWALL_HEADLESS_MODE;
env AGENTWALL_HEADLESS_TTL;
env AGENTWALL_HEADLESS_BLOCK;
env AGENTWALL_HEADLESS_SUSPECT;
env AGENTWALL_MIN_SOLVE_MS;

http {
    # Both scripts load agentwall_common.lua from this path.
    lua_package_path "/etc/nginx/lua/?.lua;;";

    # Optional but recommended: short local cache for block/challenge lookups
    # and rate-limited error logging. 2m holds tens of thousands of keys.
    lua_shared_dict agentwall_cache 2m;

    server {
        listen 443 ssl;
        server_name example.com;

        # --- 1. recover the REAL client IP, FIRST -------------------------
        # ngx_http_realip_module runs at the post-read phase, so $remote_addr
        # is already corrected for the preaccess/access phases below.
        # Only trust ranges that actually strip client-supplied XFF.
        # set_real_ip_from 10.0.0.0/8;
        # real_ip_header   X-Forwarded-For;
        # real_ip_recursive on;

        # --- 2. enforcement in the ACCESS phase ---------------------------
        access_by_lua_file /etc/nginx/lua/agentwall_challenge_block.lua;

        # --- 3. rate/connection limits ------------------------------------
        # limit_req/limit_conn run in the PREACCESS phase, i.e. BEFORE
        # access_by_lua_file, regardless of the order they appear in this
        # file. Phase order is:
        #   rewrite -> preaccess (limit_req/limit_conn) -> access (Lua) -> content
        # So a request that exceeds limit_req gets nginx's plain 429 and never
        # reaches the challenge. Size the burst so a legitimate challenged
        # visitor can load the interstitial once and follow its redirect.
        # limit_req zone=agentwall_general burst=30 nodelay;
        # limit_conn agentwall_conn 25;

        error_log /var/log/nginx/agentwall_error.log warn;
        # `warn` shows CRIT/ERR from these scripts; use `info` to also see
        # clearance-cookie rejection reasons (rate-limited to 1 line/5s).
    }
}
```

One more phase gotcha (found by `tests/e2e-real/run.sh`): a location that
answers from the **rewrite phase** — `return 200;`, `return 301;`, some
`rewrite ... last;` rules — finishes the request before the access phase, so
`access_by_lua_file` never runs and neither the block nor the challenge is
enforced there. Serve protected content with `proxy_pass`, static `root`,
`content_by_lua*` or `error_page`; do not protect assets with a bare `return`.

Client IP caveat: if `real_ip` is not configured, `$remote_addr` is the
proxy/CDN address and every client shares one ban/challenge. Configure
`set_real_ip_from` for exactly your trusted proxies.

---

## 3. Redis key contract

All keys use the normalized `ip_key` (§4). The Lua layer never writes
`agentwall:block:*` or `agentwall:challenge:*`; the scorer owns those.

| Key | Value | TTL | Written by | Read by |
| --- | --- | --- | --- | --- |
| `agentwall:block:<ip_key>` | `"1"` | `block_ttl` (scorer, default 1800s) | scorer | Lua |
| `agentwall:challenge:<ip_key>` | `"1"` | scorer `--challenge-ttl` (default 600s; keep `AGENTWALL_CHAL_TTL` equal for clarity) | scorer | Lua |
| `agentwall:cleared:<ip_key>` | `"1"` | `AGENTWALL_CLR_TTL` | **Lua**, after a valid PoW or clearance cookie | scorer |
| `agentwall:chal:<id>` | `<ip_key>\|<issued_ms>` (ms, `ngx.now()*1000`) | **180s** (fixed) | **Lua**, one per interstitial | Lua (verify) |
| `agentwall:headless:<ip_key>` | `"1"` | `AGENTWALL_HEADLESS_TTL` (default 3600) | **Lua**, on automation detection | scorer (hard signal) + Lua (mode=block on challenged requests) |

* The Lua code **deletes `agentwall:chal:<id>` on the first verification attempt**
  (right after reading it), whether the PoW is correct or not. A challenge id
  is server-minted random, bound to one `ip_key`, and single-use, so a PoW
  cannot be precomputed, replayed, or moved to another IP. Since v3 the value
  also carries the issue time (`<ip_key>|<issued_ms>`) for the server-side
  solve-time signal; split on the first `|` only.
* `agentwall:cleared:*` is what stops the scorer from hard-blocking a human who
  already solved the challenge: when the challenge key later expires, the
  scorer should treat `cleared` as "non-hard block suppressed" for
  `AGENTWALL_CLR_TTL` seconds.
* `AGENTWALL_CHAL_TTL` is read by the Lua config loader for parity/documentation;
  the scorer is the one that must apply it as the TTL of
  `agentwall:challenge:<ip_key>`, exactly as `AGENTWALL_CLR_TTL` is applied to
  `agentwall:cleared:<ip_key>`.
* `agentwall:headless:*` is written by Lua only, never cleared by Lua; the scorer
  reads it as a hard signal and it expires on its own. It is written in both
  modes: `mark` (shadow, default) and `block`.

Quick manual check:

```bash
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning \
  SET 'agentwall:block:203.0.113.10' 1 EX 60      # then request from that IP -> 403
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning \
  SET 'agentwall:challenge:203.0.113.10' 1 EX 60  # -> 429 + PoW page
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning \
  GET 'agentwall:cleared:203.0.113.10'            # -> "1" after a browser passes
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning \
  --scan --pattern 'agentwall:chal:*'             # issued ids, 180s lifetime
```

---

## Known agent/scanner signatures (supporting)

In `block` mode, a request whose UA matches the automation/scanner list
(`agentwall_common.is_automation_ua`: headless markers, **ARTEX**
`artex-enrich/1.0` / `norma/` / `artex-selfupdate`, and the default UAs of the
Kali scanner toolchain used by Strix) is denied **immediately** with 403, and an
`agentwall:headless` marker is written. In `mark` mode only the marker + WARN is
written. These are supporting signals: an operator can rotate UAs, so the
behavioural scorer remains primary. Generic clients (`curl`, `python-httpx`) are
deliberately **not** UA-blocked; allowlist your own monitoring/scanners if you
need them to reach the app.

## 4. `ip_key` normalization (Lua and Python must agree)

Rules implemented by `agentwall_common.ip_key(ip, ipv6_prefix)`:

| Input | `ip_key` |
| --- | --- |
| `1.2.3.4` | `1.2.3.4` |
| IPv4-mapped IPv6, e.g. `::ffff:1.2.3.4` | `1.2.3.4` (prefix ignored) |
| `2001:0DB8:0:0:1:0:0:1`, prefix 64 | `2001:db8::` |
| `2a00:1450:4001:82b::200e`, prefix 64 | `2a00:1450:4001:82b::` |
| `::1`, prefix 64 | `::` |
| `2001:db8:0:0:8000::1`, prefix 65 | `2001:db8:0:0:8000::` |
| `::` | `::` |
| invalid IP | `nil` — callers fall back to the raw `$remote_addr` as the key |

IPv6 is masked to the network address for `AGENTWALL_IPV6_PREFIX` (default **64**,
arbitrary bits including `/65` supported) and rendered in canonical lowercase
compressed form matching Python's `str(ipaddress.ip_network(...).network_address)`:
leading zeros stripped, longest run of ≥2 zero groups replaced by `::` (leftmost
on ties). Consequences:

* A `/64` ban covers the whole subscriber prefix, not just one `/128`. Rotating
  the interface identifier inside the same `/64` does **not** evade a block.
* `AGENTWALL_IPV6_PREFIX` **must match** the scorer's `--ipv6-prefix`. If they
  differ, Lua and Python write/read different keys and nothing is enforced.

Reference Python implementation (use this in the scorer):

```python
import ipaddress

def ip_key(ip: str, ipv6_prefix: int = 64):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.version == 4:
        return str(addr)
    mapped = addr.ipv4_mapped
    if mapped is not None:
        return str(mapped)
    return str(ipaddress.ip_network(f"{addr}/{ipv6_prefix}", strict=False).network_address)
```

Note: both implementations reject IPv4 with leading zeros (`01.2.3.4`) — modern
Python does too, so the scorer will never write such a key.

---

## 5. Clearance cookie, proof-of-work, and `/__agentwall_verify`

`agentwall_clr` cookie value:

```
v1:<exp_epoch>:<hex(hmac_sha1(AGENTWALL_CHAL_SECRET, ip_key .. "|" .. exp_epoch))>
```

Attributes: `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=<AGENTWALL_CLR_TTL>`.

Verification (`cookie_verify`) is strict:

* exact `v1:<digits>:<hex>` shape, canonical (no leading zeros) expiry text;
* `now < exp <= now + AGENTWALL_CLR_TTL` (no immortal cookies);
* signature compared in constant-ish time to
  `hmac_sha1(secret, ip_key .. "|" .. exp)`;
* bound to the current request's `ip_key`, so a cookie cannot be forged or
  shipped from another IP — the old unsigned `agentwall_clr=1` scheme is gone.

Ordinary request flow in `agentwall_challenge_block.lua`:

1. `agentwall:block:<ip_key>` present → **403** (hard block always wins).
2. URI is `/__agentwall_verify` → JSON verify handler (§5.1); no interstitial.
3. Automation User-Agent (server-side `$http_user_agent`, e.g.
   `HeadlessChrome`, `Electron/`, Playwright/Puppeteer/Selenium markers) →
   write `agentwall:headless`, WARN, and continue. This is never a direct response:
   the first challenged request still gets the interstitial (so the browser can
   reach `/__agentwall_verify`); in `AGENTWALL_HEADLESS_MODE=block` the marker then
   denies *subsequent* challenged requests via step 5, and the verify score can
   deny the current one (§8).
4. `agentwall:challenge:<ip_key>` absent → allow.
5. `AGENTWALL_HEADLESS_MODE=block` and `agentwall:headless:<ip_key>` present → **403**
   (a previously-detected automation client cannot re-enter the challenge).
   The marker is read before step 3 writes it, so the first interstitial is
   still served. In `mark` mode the marker never blocks.
6. Valid clearance cookie for this `ip_key` → `SET agentwall:cleared:<ip_key> 1 EX
   <clr_ttl>` then `DEL agentwall:challenge:<ip_key>` (in that order, so a failed
   cleared-write leaves the challenge in place and the next request retries),
   allow.
7. **GET fallback** `?agentwall_id=...&agentwall_pow=...` (legacy/no-report path) →
   `GET agentwall:chal:<id>`, `DEL` it (single use), verify id binding + PoW; on
   success `SET agentwall:cleared`, `DEL agentwall:challenge`, `Set-Cookie`, **302** to
   the same URI without the two args. A missing report does **not** itself
   create a headless signal.
8. Otherwise → mint random id, `SET agentwall:chal:<id> "<ip_key>|<issued_ms>" EX
   180`, serve **429** with the self-contained HTML page (no external assets).

The interstitial runs `crypto.subtle.digest("SHA-1", TextEncoder(id+":"+nonce))`
in JS until the hex digest starts with `AGENTWALL_POW_DIFF` (default 4, clamped
3..6) zero characters. The server never brute-forces: it does one SHA-1 of the
submitted nonce. The server-side solve time is `now_ms - issued_ms` from the
challenge value; a solve faster than `AGENTWALL_MIN_SOLVE_MS` adds `+0.30` to the
headless score (one signal, never sufficient alone). `crypto.subtle` only exists
in secure contexts, so on plain HTTP the page shows a static "use HTTPS / a
modern browser" message instead of hanging.

### 5.1 Verify endpoint (v3)

`POST /__agentwall_verify`, request `Content-Type: application/json`, body
**≤ 4096 bytes** (default `client_max_body_size` is fine; the handler also
rejects larger bodies). Parsed with `require "cjson.safe"` inside the request
script only (the pure module has no JSON/cjson dependency).

Request body:

```json
{"id":"<chal_id>","nonce":"<decimal>","report":{ ... }}
```

`report` fields (camelCase exactly as implemented):

| Field | Type | Notes |
| --- | --- | --- |
| `webdriver` | bool | `navigator.webdriver` |
| `ua` | string | overwritten server-side with `$http_user_agent` before scoring |
| `languages` | array of strings | `navigator.languages` |
| `plugins` / `mimeTypes` | int | `navigator.plugins.length` / `mimeTypes.length` |
| `chrome` | bool | `typeof window.chrome === "object"` |
| `webglVendor` / `webglRenderer` | string | `WEBGL_debug_renderer_info` when available, else `VENDOR`/`RENDERER` |
| `hardwareConcurrency` | int or null | |
| `deviceMemory` | number or null | |
| `screenW` / `screenH` | int | |
| `outerW` / `outerH` | int | |
| `timezoneOffset` | int | `new Date().getTimezoneOffset()` |
| `notification` | string | `Notification.permission` or `"unavailable"` |
| `pdfViewer` | bool | `navigator.pdfViewerEnabled` |
| `touchPoints` | int | `navigator.maxTouchPoints` |
| `cdp` | bool | any of `navigator.webdriver`, `window.cdc_*`, `window.__playwright*`, `window.__puppeteer*` |

Responses are **always** JSON (`Content-Type: application/json; charset=utf-8`,
`Cache-Control: no-store`):

| Status | Body | When |
| --- | --- | --- |
| `200` | `{"ok":true,"next":"/<page uri without agentwall_id/agentwall_pow>"}` + `Set-Cookie` clearance | id+PoW valid and either human / suspect / (automation in `mark` mode); also `agentwall:cleared` and `DEL agentwall:challenge` are written |
| `403` | `{"ok":false,"reason":"automation"}` | automation score ≥ `AGENTWALL_HEADLESS_BLOCK` and mode=`block`: marker written, challenge key deleted, **never** clearance |
| `403` | `{"ok":false,"reason":"blocked"}` | `agentwall:block:<ip_key>` exists (hard block always wins) |
| `429` | `{"ok":false,"reason":"retry"}` | missing/invalid body, bad JSON, unknown/expired/reused id, id bound to another `ip_key`, bad PoW, missing/invalid `report` |
| `200` | `{"ok":true,"next":...}` **without** cookie | Redis/infra failure: fail open, log CRIT/ERR rate-limited, never 5xx |

`next` is derived from the request's `Referer` (the interstitial page URL), with
`agentwall_id`/`agentwall_pow` stripped. A same-origin `fetch()` sends it by default; if
`Referer` is absent the handler returns `/`. The response is a same-origin path
only (scheme/host stripped), and the page JS additionally refuses anything that
does not start with `/` (and not `//`).

The page then calls `location.replace(next)` on `200 {ok:true}`, shows a plain
"automation detected" message (no reload loop) on `403`, and reloads **at most
once** on `429`/other to obtain a fresh challenge.

Ordering notes:

* The interstitial id is rendered as hex and the nonce must be decimal digits
  1..10 — both are validated before use, and neither is user-controlled HTML,
  so the page needs no HTML/JS escaping user input.
* Precomputation/replay is useless: the id is random per server response and
  consumed on first use; the server verifies the first `|`-split value against
  the current `ip_key`.
* A `429` (or `/__agentwall_verify` retry) is **not** fail-open: a wrong/replayed
  PoW is answered with another challenge, not with access.

---

## 6. Failure modes

Fail open **only** when infrastructure is unavailable; configuration errors are
loud (`ngx.CRIT`) but still fail open (the site stays up). Every log line is
rate-limited through `lua_shared_dict agentwall_cache` to one line per reason per 5
seconds, so a persistent fault cannot flood the error log.

| Situation | Request | Log |
| --- | --- | --- |
| Redis connect/timeout/read error, `GET` I/O error | allow (fail open) | `ngx.ERR`, 1/5s |
| `NOAUTH`, `WRONGPASS`, AUTH sent to a passwordless server | allow (fail open) | **`ngx.CRIT`**, 1/5s |
| `AGENTWALL_CHAL_SECRET` unset/empty (challenge would be unverifiable) | allow (fail open) | **`ngx.CRIT`**, 1/5s |
| `ngx.hmac_sha1` / `ngx.sha1_bin` unavailable | allow (fail open) | **`ngx.CRIT`** |
| `lua_shared_dict agentwall_cache` not configured | works, no caching | — |
| `$remote_addr` unparsable as an IP | allow/fail-safe with raw IP fallback key | — |
| Invalid/expired/foreign cookie | treated as no cookie → challenge | `ngx.INFO` (needs `info` log level), 1/5s |
| Invalid/replayed PoW, unknown/foreign id | fresh challenge, **429** | — (attacker drives their own rate) |
| Redis `SET agentwall:chal:<id>` fails | allow (a challenge that cannot be verified would loop forever) | `ngx.ERR`, 1/5s |
| `SET agentwall:cleared` / `DEL agentwall:challenge` fails after a *valid* PoW | allow; cookie still set so a later request can retry the writes | `ngx.ERR`, 1/5s |
| `DEL agentwall:chal:<id>` returns 0 (race / expired between GET and DEL) | fresh challenge, never clearance | — |
| Block key present | **403** | — |
| Challenge without valid clearance/PoW | **429** + interstitial | — |
| Automation User-Agent on any ordinary request | marker + WARN only (no direct response); first challenged request still gets the 429 interstitial; in `block` mode the marker **403s the next challenged request** | `ngx.WARN`, 1/5s |
| `mode=block` + `agentwall:headless` marker on a challenged request | **403** (challenge key kept) | `ngx.WARN`, 1/5s |
| `/__agentwall_verify` automation, `mode=block` | **403 JSON** `reason=automation`, marker written, challenge deleted, no clearance | `ngx.WARN` |
| `/__agentwall_verify` Redis error | **200 JSON** `ok:true,next:...` **without** cookie (fail open) | `ngx.CRIT` for config / `ngx.ERR` otherwise, 1/5s |
| `/__agentwall_verify` missing/bad JSON body, unknown id, bad PoW, foreign id | **429 JSON** `reason=retry` | — |
| `agentwall:headless` marker write fails | allow (log only), never blocks on the write failure | `ngx.ERR`, 1/5s |

---

## 7. Environment variables

| Variable | Default | Notes |
| --- | --- | --- |
| `AGENTWALL_REDIS_HOST` | `127.0.0.1` | loopback/private only |
| `AGENTWALL_REDIS_PORT` | `6379` | |
| `AGENTWALL_REDIS_PASS` | unset | must match Redis `requirepass`; unset with a protected Redis → NOAUTH CRIT + fail open |
| `AGENTWALL_REDIS_DB` | `0` | selected alongside AUTH |
| `AGENTWALL_REDIS_TIMEOUT_MS` | `100` | connect/read timeout; keep tight so Redis cannot stall requests |
| `AGENTWALL_IPV6_PREFIX` | `64` | must match scorer's `--ipv6-prefix` |
| `AGENTWALL_CHAL_SECRET` | unset | **required**; random 32+ bytes, e.g. `openssl rand -hex 32` |
| `AGENTWALL_POW_DIFF` | `4` | leading zero hex chars; clamped to 3..6. 6 is very slow in JS |
| `AGENTWALL_CHAL_TTL` | `600` | scorer's `agentwall:challenge:` TTL; read by Lua for parity |
| `AGENTWALL_CLR_TTL` | `600` | `agentwall:cleared:` TTL **and** cookie `Max-Age`/verify window |
| `AGENTWALL_HEADLESS_MODE` | `mark` | `mark` = write marker + WARN but still allow (shadow); `block` = marker + deny automation (`403 JSON` at `/__agentwall_verify`, plain `403` on subsequent challenged requests). Unknown values fall back to `mark` |
| `AGENTWALL_HEADLESS_TTL` | `3600` | `agentwall:headless:` TTL seconds; clamped 60..604800 (7 days) |
| `AGENTWALL_HEADLESS_BLOCK` | `0.60` | headless score ≥ this = automation; clamped 0..1 |
| `AGENTWALL_HEADLESS_SUSPECT` | `0.35` | score in [suspect, block) = log-only INFO, **no** marker, normal flow; clamped 0..1 |
| `AGENTWALL_MIN_SOLVE_MS` | `250` | server-measured solve time under this adds `+0.30` to the score (one signal only) |

---

## 8. Headless / automation detection (v3)

**What it is:** an advisory score in `[0,1]` computed in two places:

1. **Every ordinary request, cheaply:** `is_automation_ua($http_user_agent)`
   (case-insensitive: `HeadlessChrome`, `Electron/`, `PhantomJS`, `SlimerJS`,
   `playwright`, `puppeteer`, `selenium`, `webdriver`, `HtmlUnit`, `jsdom`,
   `Cypress`). On a match Lua writes `agentwall:headless:<ip_key> 1 EX
   AGENTWALL_HEADLESS_TTL` (debounced to ~1 write/60s) and logs WARN; behavior then
   depends on `AGENTWALL_HEADLESS_MODE`.
2. **On `POST /__agentwall_verify`:** `headless_score(report, {min_solve_ms,
   solve_ms})` combines the browser report surfaces and the server-measured
   solve time. The server-side `$http_user_agent` overwrites `report.ua` before
   scoring, so a spoofed report cannot hide an automation UA.

Weights (implemented in `agentwall_common.headless_score`, clamped to `[0,1]`):

| Signal | Weight |
| --- | --- |
| `webdriver` true | +0.50 |
| CDP artifact (`cdp`) true | +0.50 |
| UA contains `HeadlessChrome` | +0.60 |
| UA matches another automation marker | +0.40 |
| `plugins == 0 && mimeTypes == 0` and UA looks Chrome/Firefox | +0.20 |
| `chrome == false` while UA contains `Chrome/` | +0.25 |
| software WebGL (SwiftShader/llvmpipe/Mesa/ANGLE/Microsoft Basic Render/SwANGLE) | +0.20 |
| `languages` missing/empty | +0.15 |
| `outerW == 0` or `outerH == 0` or `outerW > screenW` | +0.20 |
| `screenW == 0` | +0.15 |
| `hardwareConcurrency` missing or ≤ 1 | +0.05 |
| report not a table, or fewer than 5 expected keys present | +0.40 |
| `solve_ms` missing or < `AGENTWALL_MIN_SOLVE_MS` | +0.30 |

Decision: score ≥ `AGENTWALL_HEADLESS_BLOCK` → automation (marker; 403 in `block`
mode, allow in `mark` mode); `AGENTWALL_HEADLESS_SUSPECT` ≤ score < block → INFO log
only, no marker, normal flow.

### Rollout: marker first (default `mark`)

Keep `AGENTWALL_HEADLESS_MODE=mark` for at least a baseline period. In this mode the
marker + WARN lines are produced, but visitors are never blocked by them; the
scorer can consume `agentwall:headless:*` off the hot path and correlate it with its
own signals. Only after the false-positive rate is understood should `block` be
enabled. In `block` mode the first challenged request is still allowed to load
the interstitial (that is how the browser reaches `/__agentwall_verify` and gets the
authoritative automation decision); the UA marker then denies subsequent
challenged requests, and the verify endpoint itself returns
`403 reason=automation`.

### What it detects

* Default (unpatched) **Playwright / Puppeteer / headless Chromium**: `webdriver`,
  plugin/MIME surface of 0, `window.chrome` missing, SwiftShader WebGL, zero
  outer window, empty `navigator.languages`, CDP globals (`__playwright*`,
  `__puppeteer*`, `cdc_*`), and/or implausibly fast PoW solves.
* Other obvious automation launches that leak their UA (Selenium, HtmlUnit,
  PhantomJS, Electron shell apps, jsdom/Cypress harnesses).

### What it does NOT detect (honest limits — arms race)

* `playwright-extra` / `puppeteer-extra-plugin-stealth`, patched Chromium,
  hand-rolled CDP scripting that injects consistent surfaces.
* A **real browser** driven by a human (or by automation through the user's own
  browser) — it is genuinely a browser.
* Mobile emulation with plausible, populated surfaces, spoofed UA, software
  WebGL overridden, and a human-like delay before solving.

Treat this as **advisory, not proof of humanity**. Detection signatures are an
arms race: expect to retune weights/env thresholds, and never let a single
signal (especially solve timing or a UA substring) be the only basis for a hard
block. The default `mark` mode and `AGENTWALL_HEADLESS_SUSPECT` INFO channel exist so
you can measure before enforcing.

---

## 9. Secret rotation

`AGENTWALL_CHAL_SECRET` signs clearance cookies. Rotating it immediately invalidates
every outstanding clearance cookie (they fail verification and are re-challenged
once), which is the intended emergency action if the secret leaks.
`agentwall:cleared:*` keys are not secret-derived and remain valid for the scorer;
`agentwall:chal:*` ids are random and remain valid until used/expired.

How the new value reaches nginx depends on how it is declared:

* `env AGENTWALL_CHAL_SECRET;` (inherit from the process environment, e.g. systemd
  `Environment=`/`EnvironmentFile=`): the **master** process only reads its
  environment at start, so use `systemctl restart nginx` / `openresty`.
* `env AGENTWALL_CHAL_SECRET=...;` (value in `nginx.conf`): `nginx -t` then
  `systemctl reload nginx` is enough — the master re-reads the config and
  re-forks workers.

Rotate on every nginx node at the same time (otherwise a cookie minted with the
new secret is rejected by a node still running the old one). Never commit the
secret to git.

---

## 10. Troubleshooting

### `NOAUTH Authentication required.` at CRIT (enforcement never triggers)

Symptom: the error log shows

```
agentwall: redis GET agentwall:block:203.0.113.10 failed with a CONFIGURATION error:
NOAUTH Authentication required. (set AGENTWALL_REDIS_PASS and declare `env ...`; failing open)
```

and no request is ever blocked. Redis has `requirepass` but the Lua worker has
no/ wrong password. Checklist:

1. `nginx -T | grep -nE '^\s*env\s+AGENTWALL'` — every var must be declared in the
   **main** context (`env AGENTWALL_REDIS_PASS;`). A var set in the shell/systemd
   but not declared is invisible to workers.
2. `systemctl show nginx -p Environment` (or
   `systemctl show openresty -p Environment`) — confirm the variable is
   actually in the service environment, and restart after changing it.
3. Per-worker check:
   `sudo tr '\0' '\n' < /proc/$(pgrep -o nginx)/environ | grep AGENTWALL_` (the
   process may be named `openresty` instead of `nginx`).
4. Test the password directly:
   `redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning PING`.
5. `AGENTWALL_REDIS_DB` must match what the scorer uses; a wrong DB means keys are
   written and read in different databases.

### The interstitial never completes / `/__agentwall_verify` returns 429

* The page needs a **secure context** for `crypto.subtle`/`fetch`: serve HTTPS
  (or `http://localhost`). On plain HTTP you should see the static
  "WebCrypto/fetch is unavailable" message — that is expected.
* `429 {"ok":false,"reason":"retry"}` from `/__agentwall_verify` means the id was
  unknown/expired/reused, bound to another `ip_key`, or the PoW failed. The page
  reloads once for a fresh challenge; repeated 429s often mean the challenge TTL
  (scorer-owned) is shorter than the PoW difficulty (`AGENTWALL_POW_DIFF` too high),
  or multiple nginx nodes disagree on `AGENTWALL_CHAL_SECRET`/`AGENTWALL_IPV6_PREFIX`.
* If `next` comes back as `/`, the browser/fetch did not send a `Referer`; the
  page still redirects to the site root — harmless, just less precise.
* If the cookie is set but the visitor is challenged again: check the error log
  at `info` level for `ignoring clearance cookie`; common causes are a secret
  mismatch between nodes, a cookie minted for a different `ip_key` (real_ip
  config changed), or `AGENTWALL_CLR_TTL`/clock skew.
* If `redis-cli TTL agentwall:cleared:<ip_key>` is `-2`, the write path is failing —
  look for `cleared-set` ERR lines.

### `Set-Cookie` missing / no redirect after a valid PoW

Check the `200` `/__agentwall_verify` response headers in devtools: it must carry
`Set-Cookie: agentwall_clr=v1:...; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600`
(and the JSON body `{"ok":true,"next":"/..."}`). The legacy GET fallback uses a
`302` instead. If signing fails you will see `failed to sign clearance cookie`
at CRIT (missing secret). If you get `403 reason=automation` while testing a
normal browser, check `AGENTWALL_HEADLESS_BLOCK`/`AGENTWALL_HEADLESS_SUSPECT` and the
scorer-visible `agentwall:headless:<your-ip>` marker, then compare the
`automation detected ... score=` WARN lines.

---

## 11. Verification

```bash
# syntax check (OpenResty binary name may be `openresty` or `nginx`)
nginx -t

# unit tests for the pure module (stock Lua 5.1+; no OpenResty needed)
lua tests/lua/test_agentwall_common.lua          # exit 0, prints PASS/FAIL + summary

# is the layer live at all? (from the proxy host, against your own IP)
MYIP=$(curl -s https://ifconfig.me)
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/

# force a hard block for your test IP -> expect 403
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning SET "agentwall:block:$MYIP" 1 EX 60
curl -sS -o /dev/null -w '%{http_code}\n' https://example.com/
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning DEL "agentwall:block:$MYIP"

# force a challenge for your test IP -> expect 429 + HTML PoW page
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning SET "agentwall:challenge:$MYIP" 1 EX 120
curl -sS https://example.com/ | grep -o 'crypto.subtle'     # interstitial served

# now open https://example.com/ in a browser: it should solve the PoW, POST a
# report to /__agentwall_verify, receive 200 {"ok":true,"next":...} + agentwall_clr
# cookie, and then load normally. Then:
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning GET "agentwall:cleared:$MYIP"   # "1"
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning TTL "agentwall:cleared:$MYIP"   # <= 600

# challenge value must now be "<ip_key>|<issued_ms>"; list one and GET it:
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning --scan --pattern 'agentwall:chal:*' | head -1
# redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning GET '<key from above>'  # -> "1.2.3.4|1700000000123"

# headless detection smoke test (default mode=mark writes the marker but allows):
#   run Playwright/Puppeteer once against the site, then:
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning GET "agentwall:headless:$MYIP"  # "1"
redis-cli -a "$AGENTWALL_REDIS_PASS" --no-auth-warning TTL "agentwall:headless:$MYIP"  # <= 3600

# verify endpoint contract without a browser (id/nonce must be current):
curl -sS -i -X POST https://example.com/__agentwall_verify \
  -H 'Content-Type: application/json' \
  -H 'Referer: https://example.com/some/page?x=1' \
  -d '{"id":"<chal_id>","nonce":"<decimal>","report":{}}'
# expect 200 {"ok":true,"next":"/some/page?x=1"} + Set-Cookie (human-ish report),
# 403 {"ok":false,"reason":"automation"} in block mode for a headless report, or
# 429 {"ok":false,"reason":"retry"} for a stale/reused id.
```

Watch the scripts' own logs:

```bash
tail -f /var/log/nginx/agentwall_error.log | grep 'agentwall:'
```

To exercise failure modes deliberately: stop Redis (expect fail-open 200s and
rate-limited ERR lines), then start Redis with `requirepass` but unset
`AGENTWALL_REDIS_PASS` (expect NOAUTH CRIT + fail-open).
