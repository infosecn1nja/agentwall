#!/usr/bin/env bash
# =============================================================================
# tests/e2e-real/run.sh — REAL end-to-end enforcement test for agentwall
# -----------------------------------------------------------------------------
# Proves, against real components (no stubs, no dry-run):
#   * a real Redis block key makes OpenResty return HTTP 403;
#   * the verified proof-of-work challenge returns 429, accepts a solved nonce,
#     issues a signed IP-bound cookie, and lets that client through;
#   * forged/legacy cookies and cookie replay from another IP are rejected;
#   * IPv6 /64 aggregation works end to end;
#   * the REAL scorer (real `river` model + real `redis` client) turns a log line
#     into a Redis verdict, and OpenResty enforces that verdict (403 + 429).
#
# Requires: Docker (daemon reachable), curl, python3. First run downloads the
# redis/openresty images and installs river+redis into a throwaway venv (~1 min).
#
#   bash tests/e2e-real/run.sh
#   AGENTWALL_E2E_HTTP_PORT=18081 AGENTWALL_E2E_REDIS_PORT=6391 bash tests/e2e-real/run.sh
#   AGENTWALL_E2E_VENV=/path/to/venv bash tests/e2e-real/run.sh   # reuse river+redis
#
# This is an OPTIONAL integration test; `tests/run-tests.sh` stays fast and
# dependency-free. Everything runs in a temp dir with ephemeral credentials and
# loopback-only ports, and the containers are removed on exit.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E_DIR="$REPO_ROOT/tests/e2e-real"
WORK="${AGENTWALL_E2E_DIR:-$(mktemp -d /tmp/agentwall-e2e.XXXXXX)}"
HTTP_PORT="${AGENTWALL_E2E_HTTP_PORT:-18080}"
REDIS_PORT="${AGENTWALL_E2E_REDIS_PORT:-6390}"
REDIS_PASS="testpass-e2e"
CHAL_SECRET="e2e-secret-0123456789abcdef0123456789abcdef"
URL="http://127.0.0.1:${HTTP_PORT}"

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf 'PASS  %s\n' "$*"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL  %s\n' "$*"; }
check(){ local want=$1 got=$2 label=$3; if [ "$want" = "$got" ]; then ok "$label (HTTP $got)"; else bad "$label (want $want, got $got)"; fi; }
ts()   { date '+%d/%b/%Y:%H:%M:%S %z'; }

die() { printf 'FATAL: %s\n' "$*" >&2; exit 2; }

for tool in docker curl python3; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
docker info >/dev/null 2>&1 || die "Docker daemon is not reachable"

echo "workdir: $WORK"

# --- dependencies / venv -----------------------------------------------------
if [ -n "${AGENTWALL_E2E_VENV:-}" ]; then
    PY="$AGENTWALL_E2E_VENV/bin/python3"
    [ -x "$PY" ] || die "AGENTWALL_E2E_VENV does not contain bin/python3"
else
    if [ ! -x "$WORK/venv/bin/python3" ]; then
        python3 -m venv "$WORK/venv" || die "could not create a venv (install python3-venv?)"
    fi
    PY="$WORK/venv/bin/python3"
    if ! "$PY" -c 'import river, redis' >/dev/null 2>&1; then
        echo "installing river~=0.21.0 redis~=5.0 into $WORK/venv (network required once)..."
        "$PY" -m pip install -q --disable-pip-version-check 'river~=0.21.0' 'redis~=5.0' \
            || die "pip install failed (no network? set AGENTWALL_E2E_VENV to an existing venv)"
    fi
fi
"$PY" -c 'import river, redis' >/dev/null 2>&1 || die "the venv lacks river/redis"

# --- isolated workspace ------------------------------------------------------
mkdir -p "$WORK/lua" "$WORK/nginx/conf" "$WORK/nginx/logs" "$WORK/logs" "$WORK/state"
cp "$REPO_ROOT"/nginx-lua/*.lua "$WORK/lua/"
# mktemp -d is 0700: the OpenResty workers run as `nobody` inside the
# container and must be able to traverse the bind mount and read the Lua files
# (Docker Desktop hides this; native Linux Docker and CI do not).
chmod 0755 "$WORK" "$WORK/lua" "$WORK/nginx" "$WORK/nginx/conf"
chmod 0644 "$WORK"/lua/*.lua

cat > "$WORK/nginx/conf/nginx.conf" <<EOF
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
env AGENTWALL_GET_FALLBACK;

worker_processes 1;
error_log ${WORK}/nginx/logs/error.log warn;
pid ${WORK}/nginx/logs/nginx.pid;

events { worker_connections 64; }

http {
    access_log off;
    resolver 127.0.0.11 ipv6=off valid=10s;
    lua_package_path "${WORK}/lua/?.lua;;";
    lua_shared_dict agentwall_cache 2m;

    server {
        listen 8080;
        # TEST ONLY: trust XFF so the test can act as arbitrary client IPs.
        # In production this is nginx real_ip with the CDN/LB ranges only.
        set_real_ip_from 0.0.0.0/0;
        real_ip_header X-Forwarded-For;
        real_ip_recursive off;

        access_by_lua_file ${WORK}/lua/agentwall_challenge_block.lua;

        location = /whoami {
            default_type text/plain;
            content_by_lua_block { ngx.say("remote_addr=" .. ngx.var.remote_addr) }
        }
        # NOTE: content_by_lua (not a rewrite-phase return) so the request
        # reaches the access phase; a rewrite-phase return would bypass Lua.
        location / {
            default_type text/plain;
            content_by_lua_block { ngx.say("ORIGIN-OK") }
        }
    }
}
EOF

rdb() { AGENTWALL_E2E_REDIS_PORT="$REDIS_PORT" AGENTWALL_E2E_REDIS_PASS="$REDIS_PASS" "$PY" "$E2E_DIR/rdb.py" "$@"; }
code() { curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: $1" "$URL${2:-/}"; }
ua_code() { curl -s -o /dev/null -w '%{http_code}' -A "$1" -H "X-Forwarded-For: $2" "$URL/"; }
wait_key() { # wait_key <key> <timeout_s>
    local key=$1 deadline=$((SECONDS + $2))
    while [ "$SECONDS" -lt "$deadline" ]; do
        [ "$(rdb exists "$key")" = "1" ] && return 0
        "$PY" -c 'import time; time.sleep(0.15)'
    done
    return 1
}

scorer_pid=""
cleanup() {
    [ -n "$scorer_pid" ] && kill -TERM "$scorer_pid" 2>/dev/null
    [ -n "$scorer_pid" ] && wait "$scorer_pid" 2>/dev/null
    docker rm -f agentwall-e2e-openresty agentwall-e2e-redis >/dev/null 2>&1
    docker network rm agentwall-e2e-net >/dev/null 2>&1
}
trap cleanup EXIT

# --- stack -------------------------------------------------------------------
for image in redis:7-alpine openresty/openresty:alpine; do
    docker image inspect "$image" >/dev/null 2>&1 || docker pull -q "$image" >/dev/null || die "could not pull $image"
done
docker rm -f agentwall-e2e-openresty agentwall-e2e-redis >/dev/null 2>&1
docker network rm agentwall-e2e-net >/dev/null 2>&1
docker network create agentwall-e2e-net >/dev/null || die "could not create the docker network"
docker run -d --name agentwall-e2e-redis --network agentwall-e2e-net \
    -p "127.0.0.1:${REDIS_PORT}:6379" redis:7-alpine \
    redis-server --requirepass "$REDIS_PASS" --save '' --appendonly no >/dev/null || die "could not start Redis"
docker run -d --name agentwall-e2e-openresty --network agentwall-e2e-net \
    -p "127.0.0.1:${HTTP_PORT}:8080" \
    -e AGENTWALL_REDIS_HOST=agentwall-e2e-redis -e AGENTWALL_REDIS_PORT=6379 \
    -e AGENTWALL_REDIS_PASS="$REDIS_PASS" -e AGENTWALL_REDIS_DB=0 \
    -e AGENTWALL_REDIS_TIMEOUT_MS=100 -e AGENTWALL_IPV6_PREFIX=64 \
    -e AGENTWALL_CHAL_SECRET="$CHAL_SECRET" -e AGENTWALL_POW_DIFF=3 \
    -e AGENTWALL_CHAL_TTL=300 -e AGENTWALL_CLR_TTL=300 \
    -e AGENTWALL_HEADLESS_MODE=block -e AGENTWALL_HEADLESS_TTL=300 -e AGENTWALL_MIN_SOLVE_MS=250 \
    -e AGENTWALL_GET_FALLBACK=on \
    -v "$WORK:$WORK" openresty/openresty:alpine \
    /usr/local/openresty/bin/openresty -g 'daemon off;' -c "$WORK/nginx/conf/nginx.conf" >/dev/null \
    || die "could not start OpenResty"

for _ in $(seq 1 100); do
    [ "$(code 203.0.113.99)" = "200" ] && break
    "$PY" -c 'import time; time.sleep(0.1)'
done
[ "$(code 203.0.113.99)" = "200" ] || die "OpenResty did not become ready"
: > "$WORK/nginx/logs/error.log"
rdb flush >/dev/null

echo
echo "=== A. Hard block via Redis (the exact contract the scorer writes) ==="
check 200 "$(code 203.0.113.10)" "A0 clean IP allowed"
rdb set agentwall:block:203.0.113.10 1 60 >/dev/null
check 403 "$(code 203.0.113.10)" "A1 blocked IP rejected"
check 200 "$(code 203.0.113.11)" "A2 other IP still allowed"
ok "A3 block key TTL=$(rdb ttl agentwall:block:203.0.113.10)s"

echo
echo "=== B. Human verification + headless detection (real OpenResty + Lua) ==="
rdb set agentwall:challenge:203.0.113.20 1 300 >/dev/null
check 429 "$(code 203.0.113.20)" "B0 challenged IP gets the interstitial"
curl -s -H 'X-Forwarded-For: 203.0.113.20' "$URL/" -o "$WORK/challenge.html"
grep -q "__agentwall_verify" "$WORK/challenge.html" && ok "B0b interstitial posts the report to /__agentwall_verify" || bad "B0b interstitial lacks /__agentwall_verify"
read -r CHAL_ID NONCE DIFF < <("$PY" "$E2E_DIR/solve_pow.py" "$WORK/challenge.html")
ok "B1 solved PoW id=${CHAL_ID:0:8}.. nonce=$NONCE diff=$DIFF"
"$PY" "$E2E_DIR/report.py" human "$CHAL_ID" "$NONCE" > "$WORK/human.json"
curl -s -D "$WORK/pow_headers.txt" -o "$WORK/pow_body.txt" -X POST \
    -H 'Content-Type: application/json' -H 'X-Forwarded-For: 203.0.113.20' \
    --data-binary @"$WORK/human.json" "$URL/__agentwall_verify"
pow_status=$(awk 'NR==1{print $2}' "$WORK/pow_headers.txt")
COOKIE=$(sed -n 's/^Set-Cookie: \(agentwall_clr=[^;]*\).*/\1/ip' "$WORK/pow_headers.txt" | head -1)
[ "$pow_status" = "200" ] && ok "B2 human report accepted -> 200 JSON" || bad "B2 human report status=$pow_status"
[ -n "$COOKIE" ] && ok "B3 signed clearance cookie issued (${COOKIE:0:22}...)" || bad "B3 no Set-Cookie"
check 200 "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.20' -H "Cookie: $COOKIE" "$URL/")" "B4 cookie passes the challenge"
[ "$(rdb get agentwall:cleared:203.0.113.20)" = "1" ] && ok "B5 agentwall:cleared written for the scorer" || bad "B5 cleared key missing"
[ "$(rdb exists agentwall:challenge:203.0.113.20)" = "0" ] && ok "B6 challenge key cleared" || bad "B6 challenge key still present"
rdb set agentwall:challenge:203.0.113.21 1 300 >/dev/null
check 429 "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.21' -H 'Cookie: agentwall_clr=1' "$URL/")" "B7 forged legacy cookie rejected"
rdb set agentwall:challenge:203.0.113.22 1 300 >/dev/null
check 429 "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.22' -H "Cookie: $COOKIE" "$URL/")" "B8 cookie is IP-bound (replay rejected)"

# B9-B10: default Playwright/Puppeteer headless report -> marker + 403 in block mode
rdb set agentwall:challenge:203.0.113.23 1 300 >/dev/null
curl -s -H 'X-Forwarded-For: 203.0.113.23' "$URL/" -o "$WORK/challenge-hl.html"
read -r HL_ID HL_NONCE _ < <("$PY" "$E2E_DIR/solve_pow.py" "$WORK/challenge-hl.html")
"$PY" "$E2E_DIR/report.py" headless "$HL_ID" "$HL_NONCE" > "$WORK/headless.json"
hl_status=$(curl -s -o "$WORK/headless_body.txt" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' -H 'X-Forwarded-For: 203.0.113.23' \
    --data-binary @"$WORK/headless.json" "$URL/__agentwall_verify")
[ "$hl_status" = "403" ] && ok "B9 default Playwright/Puppeteer report rejected (403)" || bad "B9 headless report status=$hl_status"
[ "$(rdb exists agentwall:headless:203.0.113.23)" = "1" ] && ok "B10 agentwall:headless marker written by Lua" || bad "B10 headless marker missing"
rdb set agentwall:challenge:203.0.113.23 1 300 >/dev/null
check 403 "$(code 203.0.113.23)" "B11 marker blocks even a normal-UA request on a challenged IP"

# B12: explicit automation UA is detected (marker) on the first request; the
# next challenged request is denied (verify-first design avoids breaking the
# interstitial for the request that discovers the UA).
curl -s -o /dev/null -A 'Mozilla/5.0 HeadlessChrome/124.0.0.0' \
    -H 'X-Forwarded-For: 203.0.113.24' "$URL/"
[ "$(rdb exists agentwall:headless:203.0.113.24)" = "1" ] && ok "B12 automation UA marker written" || bad "B12 automation UA marker missing"
# The Lua layer caches "challenge absent" for 2s; let the negative cache expire
# so the newly set challenge (and the marker check) is evaluated.
"$PY" -c 'import time; time.sleep(2.2)'
rdb set agentwall:challenge:203.0.113.24 1 300 >/dev/null
check 403 "$(code 203.0.113.24)" "B13 automation-UA marker denies the next challenged request"

# B14: GET fallback (?agentwall_id&agentwall_pow) works when explicitly enabled
# (AGENTWALL_GET_FALLBACK=on; the default in block mode is off)
rdb set agentwall:challenge:203.0.113.25 1 300 >/dev/null
curl -s -H 'X-Forwarded-For: 203.0.113.25' "$URL/" -o "$WORK/challenge-get.html"
read -r GID GNONCE _ < <("$PY" "$E2E_DIR/solve_pow.py" "$WORK/challenge-get.html")
curl -s -D "$WORK/get_headers.txt" -o /dev/null -H 'X-Forwarded-For: 203.0.113.25' \
    "$URL/?agentwall_id=$GID&agentwall_pow=$GNONCE"
g_status=$(awk 'NR==1{print $2}' "$WORK/get_headers.txt")
GCOOKIE=$(sed -n 's/^Set-Cookie: \(agentwall_clr=[^;]*\).*/\1/ip' "$WORK/get_headers.txt" | head -1)
case "$g_status" in 200|302) ok "B14 GET fallback verified the PoW ($g_status)" ;; *) bad "B14 GET fallback status=$g_status" ;; esac
check 200 "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.25' -H "Cookie: $GCOOKIE" "$URL/")" "B15 GET fallback cookie passes"

# B16-B17: Strix default sandbox browser profile (source-derived:
# containers/Dockerfile + tools/agent_browser). Normal Chrome UA,
# AutomationControlled disabled (webdriver=false), but empty plugin surface,
# SwiftShader rasterizer, PDF viewer disabled -> correlated headless score.
rdb set agentwall:challenge:203.0.113.26 1 300 >/dev/null
curl -s -H 'X-Forwarded-For: 203.0.113.26' "$URL/" -o "$WORK/challenge-strix.html"
read -r SID SNONCE _ < <("$PY" "$E2E_DIR/solve_pow.py" "$WORK/challenge-strix.html")
"$PY" "$E2E_DIR/report.py" strix "$SID" "$SNONCE" > "$WORK/strix.json"
strix_status=$(curl -s -o "$WORK/strix_body.txt" -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -A 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' \
    -H 'X-Forwarded-For: 203.0.113.26' \
    --data-binary @"$WORK/strix.json" "$URL/__agentwall_verify")
[ "$strix_status" = "403" ] && ok "B16 Strix default sandbox browser profile blocked (403)" || bad "B16 Strix profile status=$strix_status"
[ "$(rdb exists agentwall:headless:203.0.113.26)" = "1" ] && ok "B17 Strix profile marked headless" || bad "B17 Strix profile marker missing"

echo
echo "=== C. IPv6 /64 aggregation ==="
rdb set agentwall:block:2001:db8:: 1 60 >/dev/null
check 403 "$(code '2001:db8::1')" "C0 IPv6 address inside the blocked /64 rejected"
check 200 "$(code '2001:db8:1::1')" "C1 IPv6 address in another /64 allowed"

echo
echo "=== F. Source-derived agent/scanner default profiles ==="
check 200 "$(ua_code 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36' 203.0.113.90)" "F0 normal browser UA allowed"
check 200 "$(ua_code 'python-httpx/0.27.2' 203.0.113.91)" "F0b python-httpx library allowed (FP control)"
check 200 "$(ua_code 'curl/8.4.0' 203.0.113.92)" "F0c ordinary curl UA allowed (FP control)"
f_index=0
while IFS= read -r profile_ua; do
    [ -z "$profile_ua" ] && continue
    f_index=$((f_index + 1))
    profile_ip="203.0.113.$((100 + f_index))"
    check 403 "$(ua_code "$profile_ua" "$profile_ip")" "F$f_index blocked: $profile_ua"
done <<'AGENT_UAS'
artex-enrich/1.0
norma/0.4
artex-selfupdate
nuclei/v3.3.0
sqlmap/1.8#stable
Fuzz Faster U Fool v2.1.0-dev
Nmap Scripting Engine
dirsearch/0.4.3
WafW00F/2.2.0
arjun/2.2.2
katana/v1.1.0
subfinder/v2.6.6
naabu/v2.3.0
gospider/v1.1.6
interactsh-client/v1.2.0
nikto/2.5.0
gobuster/3.6
feroxbuster/2.10.0
wpscan/3.8.25
masscan/1.3
zgrab/0.1
httpx/1.6.0
AGENT_UAS

echo
echo "=== D. REAL scorer (river + redis) -> Redis -> OpenResty ==="
rm -f "$WORK/state/model.pkl"
: > "$WORK/logs/agentwall_access.log"
PYTHONUNBUFFERED=1 "$PY" "$REPO_ROOT/scorer/agentwall_scorer.py" \
    --log "$WORK/logs/agentwall_access.log" --enforce --backend redis --headless-mode block \
    --redis-url "redis://:${REDIS_PASS}@127.0.0.1:${REDIS_PORT}/0" \
    --warmup 0 --min-events 1 --cooldown 0 --challenge-grace 5 \
    --floor-block 0.15 --floor-watch 0.05 --p-block 0.99 --p-watch 0.95 \
    --block-ttl 300 --challenge-ttl 300 --allowlist '10.99.99.99/32' \
    --state "$WORK/state/model.pkl" --log-level INFO > "$WORK/logs/scorer.log" 2>&1 &
scorer_pid=$!
deadline=$((SECONDS + 60))
while [ "$SECONDS" -lt "$deadline" ]; do
    grep -q "started mode=ENFORCE" "$WORK/logs/scorer.log" 2>/dev/null && break
    "$PY" -c 'import time; time.sleep(0.1)'
done
if grep -q "started mode=ENFORCE" "$WORK/logs/scorer.log"; then
    ok "D0 real scorer started in ENFORCE mode"
else
    bad "D0 scorer did not start"; cat "$WORK/logs/scorer.log"
fi
"$PY" -c 'import time; time.sleep(0.6)'   # let tail() open+seek before we append

# First log field is the real client; the xff tail is a forged loopback value.
# The scorer runs WITHOUT --use-xff and must key on the first field only.
echo "203.0.113.30 - - [$(ts)] \"GET /admin/login HTTP/1.1\" 404 12 \"-\" \"curl/8.4.0\" rt=0.001 urt=0.001 ua_flag=1 probe=1 xff=\"127.0.0.1\"" >> "$WORK/logs/agentwall_access.log"
if wait_key agentwall:block:203.0.113.30 30; then ok "D1 scorer wrote agentwall:block from the real log line"; else bad "D1 scorer did not write the block key"; fi
[ "$(rdb exists agentwall:block:127.0.0.1)" = "0" ] && ok "D1b spoofed xff=127.0.0.1 did not become the verdict key" || bad "D1b scorer trusted the left-most xff"
check 403 "$(code 203.0.113.30)" "D2 OpenResty enforces the scorer's real block (403)"
ttl=$(rdb ttl agentwall:block:203.0.113.30)
[ "$ttl" -gt 250 ] && [ "$ttl" -le 300 ] && ok "D3 block TTL honours --block-ttl (${ttl}s)" || bad "D3 unexpected TTL=$ttl"

for i in $(seq 1 16); do
    echo "203.0.113.31 - - [$(ts)] \"GET /probe$i HTTP/1.1\" 404 12 \"-\" \"curl/8.4.0\" rt=0.001 urt=0.001 ua_flag=0 probe=1 xff=\"203.0.113.31\"" >> "$WORK/logs/agentwall_access.log"
done
if wait_key agentwall:challenge:203.0.113.31 30; then ok "D4 scorer wrote agentwall:challenge for a non-hard suspicious IP"; else bad "D4 no challenge key written"; fi
check 429 "$(code 203.0.113.31)" "D5 OpenResty serves the challenge for the scorer's verdict"
curl -s -H 'X-Forwarded-For: 203.0.113.31' "$URL/" -o "$WORK/challenge2.html"
read -r CID2 N2 D2 < <("$PY" "$E2E_DIR/solve_pow.py" "$WORK/challenge2.html")
curl -s -D "$WORK/pow2_headers.txt" -o /dev/null -H 'X-Forwarded-For: 203.0.113.31' \
    "$URL/?agentwall_id=$CID2&agentwall_pow=$N2"
st2=$(awk 'NR==1{print $2}' "$WORK/pow2_headers.txt")
C2=$(sed -n 's/^Set-Cookie: \(agentwall_clr=[^;]*\).*/\1/ip' "$WORK/pow2_headers.txt" | head -1)
[ "$st2" = "302" ] && ok "D6 PoW for the scorer-issued challenge solved -> 302" || bad "D6 PoW status=$st2"
check 200 "$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 203.0.113.31' -H "Cookie: $C2" "$URL/")" "D7 challenged client passes after PoW"
[ "$(rdb get agentwall:cleared:203.0.113.31)" = "1" ] && ok "D8 agentwall:cleared visible to the scorer" || bad "D8 cleared key missing"

# D9: the edge marks a challenged IP as headless; the real scorer must hard-block it
echo "203.0.113.32 - - [$(ts)] \"GET /probe-hl HTTP/1.1\" 404 12 \"-\" \"curl/8.4.0\" rt=0.001 urt=0.001 ua_flag=0 probe=1 xff=\"203.0.113.32\"" >> "$WORK/logs/agentwall_access.log"
if wait_key agentwall:challenge:203.0.113.32 30; then ok "D9 scorer issued a challenge for the headless test IP"; else bad "D9 no challenge for the headless test IP"; fi
rdb set agentwall:headless:203.0.113.32 1 300 >/dev/null
echo "203.0.113.32 - - [$(ts)] \"GET /next HTTP/1.1\" 404 12 \"-\" \"curl/8.4.0\" rt=0.001 urt=0.001 ua_flag=0 probe=1 xff=\"203.0.113.32\"" >> "$WORK/logs/agentwall_access.log"
if wait_key agentwall:block:203.0.113.32 30; then ok "D10 scorer converted the headless marker into a hard block"; else bad "D10 scorer did not block the headless marker"; fi
check 403 "$(code 203.0.113.32)" "D11 OpenResty enforces the headless block (403)"

echo
echo "=== E. OpenResty error log ==="
errs=$(grep -cE '\[(error|crit)\]' "$WORK/nginx/logs/error.log" 2>/dev/null || true)
if [ "${errs:-0}" -eq 0 ]; then
    ok "E0 no error/crit lines in the OpenResty error log"
else
    bad "E0 $errs error/crit lines"; tail -5 "$WORK/nginx/logs/error.log"
fi

echo
echo "=== RESULT: PASS=$PASS FAIL=$FAIL ==="
echo "artifacts (logs, challenge pages): $WORK"
[ "$FAIL" -eq 0 ]
