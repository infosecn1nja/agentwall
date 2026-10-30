#!/usr/bin/env bash
# =============================================================================
# deploy/validate-linux.sh
#
# Linux-native validation for the agentwall stack, driven from macOS/Linux
# with Docker. EVERYTHING is installed inside throwaway `docker run --rm`
# containers: the host system is never modified and no host package is touched.
#
# What is validated (and where):
#
#   1. systemd unit        ubuntu:24.04 + systemd
#        - systemd-analyze verify deploy/agentwall-scorer.service
#          (run twice: once "as shipped" where the missing /opt/... ExecStart
#           binary is an EXPECTED warning, once with a stub ExecStart so the
#           unit must verify completely clean)
#        - systemd-analyze security --offline=true (INFORMATIONAL, not a gate)
#
#   2. fail2ban            ubuntu:24.04 (fail2ban 1.0.x)
#        - fail2ban-client -t (config test) on the installed filters/jails
#        - jail load test + effective maxretry/findtime/bantime per jail
#          (catches the "trailing '#' comment silently drops the option" bug)
#        - fail2ban-regex counts against synthetic nginx access logs:
#            agentwall-behavior vs 404/403 (+ 429, static 404, 200) -> 2 matched, 1 ignored
#            agentwall-auth     vs 401/403 on /login (+ 404)      -> 2 matched
#            agentwall-ml       vs mixed lines                    -> 0 matched
#        - the same fail2ban checks are re-run on ubuntu:22.04, which ships
#          fail2ban 0.11.2, to cover the 0.11.x compatibility claim
#          (disable with --skip-fail2ban-011)
#
#   3. Apache snippet      httpd:2.4-alpine
#        - httpd -t with waf/apache-agentwall.conf included AFTER the stock
#          config (`-c Include ...`) so modules loaded by the stock config are
#          visible and the <IfModule> blocks are actually parsed; mod_rewrite /
#          mod_remoteip are LoadModule'd explicitly when the image ships them
#        - canary tests: a deliberately-broken RewriteRule / RequestReadTimeout
#          must be REJECTED, proving those blocks are exercised (not skipped)
#        - mod_evasive / mod_qos are NOT in the image: their <IfModule> blocks
#          are skipped and reported as UNTESTED
#
#   4. OpenResty -t        openresty/openresty:alpine
#        - deploy/nginx.conf.example (the full production config) with the
#          nginx-lua/ tree linked at /etc/nginx/lua as the deployment guide says
#        - luajit -bl syntax check of nginx-lua/*.lua (nginx -t does not compile
#          *_by_lua_file bodies)
#        - if deploy/nginx.conf.example does not exist yet, waits up to
#          --nginx-conf-wait seconds (default 300) for it and then falls back to
#          a structural check of waf/nginx-agentwall.conf (SKIP, not FAIL)
#
#   5. Redis contract      redis:7-alpine
#        - requirepass: unauthenticated PING rejected, authenticated PING=PONG
#        - SET agentwall:block:1.2.3.4 1 EX 60 -> TTL 60 -> GET 1
#          (the exact key/TTL contract the nginx-Lua enforcement layer uses)
#        - INFORMATIONAL, not a gate (failures are WARN, never FAIL)
#
# Usage:
#   deploy/validate-linux.sh [options]
#
# Options:
#   --skip-systemd        do not run the systemd section
#   --skip-fail2ban       do not run the fail2ban section (both versions)
#   --skip-fail2ban-011   skip the ubuntu:22.04 / fail2ban 0.11.x re-run only
#   --skip-apache         do not run the Apache section
#   --skip-openresty      do not run the OpenResty section
#   --skip-redis          do not run the Redis section
#   --no-pull             never pull images; fail if an image is missing
#   --nginx-conf-wait N   seconds to wait for deploy/nginx.conf.example
#                         (default 300; 0 disables waiting)
#   -h, --help            show this help
#
# Exit status:
#   0  zero FAIL (WARN/SKIP are allowed and do not affect the exit code)
#   1  at least one FAIL
#   2  validation could not run (Docker missing/unreachable, bad arguments)
#
# NOTE: the first run can take several minutes. It pulls up to five images and
# apt-installs systemd + fail2ban inside the ubuntu containers (~30-60 s each;
# the apt layer is NOT cached between runs). Subsequent runs reuse the images
# but still pay the apt cost.
# =============================================================================
set -uo pipefail

# ---------------------------------------------------------------------------
# Constants / globals
# ---------------------------------------------------------------------------
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

IMAGE_UBUNTU="${AGENTWALL_UBUNTU_IMAGE:-ubuntu:24.04}"          # systemd 255, fail2ban 1.0.x
IMAGE_UBUNTU_OLD="${AGENTWALL_UBUNTU_OLD_IMAGE:-ubuntu:22.04}"  # fail2ban 0.11.2
IMAGE_HTTPD="${AGENTWALL_HTTPD_IMAGE:-httpd:2.4-alpine}"
IMAGE_OPENRESTY="${AGENTWALL_OPENRESTY_IMAGE:-openresty/openresty:alpine}"
IMAGE_REDIS="${AGENTWALL_REDIS_IMAGE:-redis:7-alpine}"

SKIP_SYSTEMD=0
SKIP_FAIL2BAN=0
SKIP_FAIL2BAN_011=0
SKIP_APACHE=0
SKIP_OPENRESTY=0
SKIP_REDIS=0
NO_PULL=0
NGINX_CONF_WAIT=300

PASS=0
WARN=0
FAIL=0
SKIP=0
FAILURES=()
WARNINGS=()
SKIPPED=()
IMAGES_USED=()
PULLED_IMAGES=()
DOCKER_VERSION="unknown"
WORKDIR=""

# ---------------------------------------------------------------------------
# Output helpers (host side)
# ---------------------------------------------------------------------------
section() {
    printf '\n==========================================================================\n'
    printf ' %s\n' "$*"
    printf '==========================================================================\n'
}
p() { PASS=$((PASS + 1)); printf '  [PASS] %s\n' "$*"; }
w() { WARN=$((WARN + 1)); WARNINGS+=("$*"); printf '  [WARN] %s\n' "$*"; }
f() { FAIL=$((FAIL + 1)); FAILURES+=("$*"); printf '  [FAIL] %s\n' "$*"; }
s() { SKIP=$((SKIP + 1)); SKIPPED+=("$*"); printf '  [SKIP] %s\n' "$*"; }
i() { printf '  [INFO] %s\n' "$*"; }
raw_line() { printf '       | %s\n' "$*"; }

usage() {
    cat <<'USAGE'
deploy/validate-linux.sh — Linux-native validation of agentwall (Docker only)

Usage:
  deploy/validate-linux.sh [options]

Sections (all run by default):
  1) systemd unit        ubuntu:24.04 + systemd  -> systemd-analyze verify,
                                                  systemd-analyze security (info)
  2) fail2ban            ubuntu:24.04 + fail2ban 1.0.x -> fail2ban-client -t,
                         jail load + effective options, fail2ban-regex counts
  2b) fail2ban 0.11.x    ubuntu:22.04 + fail2ban 0.11.2 -> same fail2ban checks
  3) Apache snippet      httpd:2.4-alpine        -> httpd -t + canary coverage
  4) OpenResty -t        openresty/openresty:alpine -> deploy/nginx.conf.example
  5) Redis contract      redis:7-alpine          -> requirepass / SET EX (info)

Options:
  --skip-systemd        do not run the systemd section
  --skip-fail2ban       do not run the fail2ban section (both versions)
  --skip-fail2ban-011   skip the ubuntu:22.04 / fail2ban 0.11.x re-run only
  --skip-apache         do not run the Apache section
  --skip-openresty      do not run the OpenResty section
  --skip-redis          do not run the Redis section
  --no-pull             never pull images; fail if an image is missing
  --nginx-conf-wait N   seconds to wait for deploy/nginx.conf.example
                        (default 300; 0 disables waiting)
  -h, --help            show this help

Exit status:
  0  zero FAIL (WARN/SKIP are allowed and do not affect the exit code)
  1  at least one FAIL
  2  validation could not run (Docker missing/unreachable, bad arguments)

Images are printed in each section header; all installs happen inside
`docker run --rm` containers and the host is never modified.
USAGE
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --skip-systemd)      SKIP_SYSTEMD=1 ;;
            --skip-fail2ban)     SKIP_FAIL2BAN=1 ;;
            --skip-fail2ban-011) SKIP_FAIL2BAN_011=1 ;;
            --skip-apache)       SKIP_APACHE=1 ;;
            --skip-openresty)    SKIP_OPENRESTY=1 ;;
            --skip-redis)        SKIP_REDIS=1 ;;
            --no-pull)           NO_PULL=1 ;;
            --nginx-conf-wait)
                shift
                NGINX_CONF_WAIT="${1:-}"
                ;;
            --nginx-conf-wait=*)
                NGINX_CONF_WAIT="${1#*=}"
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                printf 'Unknown option: %s\n\n' "$1" >&2
                usage >&2
                exit 2
                ;;
        esac
        shift
    done
    case "$NGINX_CONF_WAIT" in
        ''|*[!0-9]*)
            printf 'Invalid --nginx-conf-wait value: %s (must be a non-negative integer)\n' "$NGINX_CONF_WAIT" >&2
            exit 2
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Docker preflight + image handling
# ---------------------------------------------------------------------------
docker_preflight() {
    if ! command -v docker >/dev/null 2>&1; then
        printf 'FATAL: docker CLI not found in PATH. This script needs Docker (containers only).\n' >&2
        exit 2
    fi
    if ! docker info >/dev/null 2>&1; then
        printf 'FATAL: Docker daemon not reachable. Start Docker Desktop / dockerd and retry.\n' >&2
        exit 2
    fi
    DOCKER_VERSION="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
    i "docker server: ${DOCKER_VERSION}"
    i "repo: ${REPO_ROOT}"
    i "workdir: ${WORKDIR}"
    printf '  [INFO] first run may take several minutes (image pulls + apt installs in ubuntu containers)\n'
}

ensure_image() {
    img="$1"
    if docker image inspect "$img" >/dev/null 2>&1; then
        IMAGES_USED+=("$img")
        i "image available: ${img}"
        return 0
    fi
    if [ "$NO_PULL" = 1 ]; then
        f "image not present (--no-pull): ${img}"
        return 1
    fi
    i "pulling ${img} (first run only) ..."
    if docker pull -q "$img" >/dev/null 2>&1; then
        PULLED_IMAGES+=("$img")
        IMAGES_USED+=("$img")
        i "pulled: ${img}"
        return 0
    fi
    f "could not pull image: ${img}"
    return 1
}

# ---------------------------------------------------------------------------
# Container I/O plumbing.
#
# Container scripts emit one record per line: PASS|/WARN|/FAIL|/SKIP|/INFO|/RAW|
# The host dispatches those into the counters; anything else is printed as
# container noise instead of silently dropped.
# ---------------------------------------------------------------------------
dispatch() {
    local line
    while IFS= read -r line; do
        case "$line" in
            PASS\|*) p "${line#PASS|}" ;;
            WARN\|*) w "${line#WARN|}" ;;
            FAIL\|*) f "${line#FAIL|}" ;;
            SKIP\|*) s "${line#SKIP|}" ;;
            INFO\|*) i "${line#INFO|}" ;;
            RAW\|*)  raw_line "${line#RAW|}" ;;
            '')      ;;
            *)       raw_line "$line" ;;
        esac
    done
}

# run_container_script <image> <shell> <script-file> [extra docker run args...]
run_container_script() {
    local image="$1" shell="$2" script="$3"
    shift 3
    local out="${WORKDIR}/container-out.$$.$RANDOM"
    local rc
    docker run --rm -i --label agentwall-validate=1 "$@" "$image" "$shell" -s < "$script" > "$out" 2>&1
    rc=$?
    dispatch < "$out"
    rm -f "$out"
    return "$rc"
}

# ---------------------------------------------------------------------------
# Container scripts are generated into $WORKDIR so the exact code that runs is
# inspectable with `bash -x`. All mounts are read-only.
# ---------------------------------------------------------------------------
generate_container_scripts() {
    local helpers="${WORKDIR}/helpers.sh"
    local systemd_part="${WORKDIR}/systemd-part.sh"
    local fail2ban_part="${WORKDIR}/fail2ban-part.sh"

    cat > "$helpers" <<'CONTAINER_HELPERS'
# --- shared container-side output helpers (POSIX sh compatible) -------------
p() { printf 'PASS|%s\n' "$*"; }
w() { printf 'WARN|%s\n' "$*"; }
f() { printf 'FAIL|%s\n' "$*"; }
i() { printf 'INFO|%s\n' "$*"; }
s() { printf 'SKIP|%s\n' "$*"; }
r() { while IFS= read -r line; do printf 'RAW|%s\n' "$line"; done; }
CONTAINER_HELPERS

    cat > "$systemd_part" <<'CONTAINER_SYSTEMD'
# --- 1) systemd unit -------------------------------------------------------
if [ "${RUN_SYSTEMD:-0}" = 1 ]; then
    i "systemd: $(systemd-analyze --version 2>&1 | head -1)"
    i "unit: /repo/deploy/agentwall-scorer.service (copied to /tmp for verify)"
    if getent group adm >/dev/null 2>&1; then
        i "group 'adm' exists (unit uses SupplementaryGroups=adm)"
    else
        w "group 'adm' missing in image; unit's SupplementaryGroups=adm would fail at start on such a host"
    fi
    if id agentwall >/dev/null 2>&1; then
        i "service user 'agentwall' already exists"
    elif useradd --system --no-create-home --shell /usr/sbin/nologin agentwall >/dev/null 2>&1; then
        i "created service user 'agentwall' (system, nologin, no home)"
    else
        f "could not create service user 'agentwall'"
    fi
    if cp /repo/deploy/agentwall-scorer.service /tmp/agentwall-scorer.service 2>/dev/null; then
        i "copied unit to /tmp/agentwall-scorer.service"
    else
        f "could not copy deploy/agentwall-scorer.service into container"
    fi

    # --- run 1: exactly as a fresh box has it (no /opt install, no env file).
    out=$(systemd-analyze verify /tmp/agentwall-scorer.service 2>&1); rc=$?
    if [ -n "$out" ]; then printf '%s\n' "$out" | r; fi
    unknown=$(printf '%s\n' "$out" | grep -E 'Unknown key|Unknown lvalue|Unknown section|Failed to parse|is not a valid|Invalid' || true)
    unexpected=$(printf '%s\n' "$out" | grep -vE 'is not executable: No such file or directory|^$' || true)
    if [ -n "$unknown" ]; then
        f "systemd-analyze verify: REAL unit defect (unknown/invalid key or parse error) — see above"
        if [ -n "$unexpected" ]; then printf '%s\n' "$unexpected" | r; fi
    elif [ -n "$unexpected" ]; then
        f "systemd-analyze verify: unexpected diagnostics (not the expected missing-binary warning) — see above"
    elif [ "$rc" -ne 0 ]; then
        w "systemd-analyze verify rc=$rc, explained ONLY by the expected warning for the missing /opt/agentwall ExecStart binary (not installed in this throwaway container)"
    else
        p "systemd-analyze verify: clean rc=0 (unit syntax/keys valid)"
    fi

    # --- run 2: stub ExecStart so verify MUST be completely clean. This is the
    #     gated check: if any Unknown key / permission-option error existed it
    #     would show up here.
    mkdir -p /opt/agentwall/.venv/bin /var/lib/agentwall
    printf '#!/bin/sh\nexit 0\n' > /opt/agentwall/.venv/bin/python3
    chmod 0755 /opt/agentwall/.venv/bin/python3
    : > /etc/agentwall-scorer.env
    chmod 0600 /etc/agentwall-scorer.env
    out2=$(systemd-analyze verify /tmp/agentwall-scorer.service 2>&1); rc2=$?
    if [ "$rc2" -eq 0 ] && [ -z "$out2" ]; then
        p "systemd-analyze verify: rc=0 with stub ExecStart + /etc/agentwall-scorer.env present (zero syntax/unknown-key/permission-option errors)"
    else
        f "systemd-analyze verify: still not clean with stub ExecStart (rc=$rc2); output above"
        if [ -n "$out2" ]; then printf '%s\n' "$out2" | r; fi
    fi

    # --- exposure score: informational only, never a gate.
    if sec=$(systemd-analyze security --offline=true /tmp/agentwall-scorer.service 2>&1); then
        score=$(printf '%s\n' "$sec" | grep 'Overall exposure level' | tail -1)
        unfixed=$(printf '%s\n' "$sec" | grep -c '✗' || true)
        i "systemd-analyze security --offline=true: ${score:-<no exposure line>} (${unfixed} unhardened knobs; INFORMATIONAL, not a gate)"
    else
        w "systemd-analyze security --offline=true unavailable/failed on this systemd; exposure score skipped (informational)"
    fi
fi
CONTAINER_SYSTEMD

    cat > "$fail2ban_part" <<'CONTAINER_FAIL2BAN'
# --- 2) fail2ban filters + jails ------------------------------------------
if [ "${RUN_FAIL2BAN:-0}" = 1 ]; then
    i "fail2ban: $(fail2ban-client --version 2>&1 | head -1)"
    if cp /repo/fail2ban/filter.d/*.conf /etc/fail2ban/filter.d/ 2>/dev/null; then
        i "installed filters: $(for x in /etc/fail2ban/filter.d/agentwall-*.conf; do basename "$x"; done | tr '\n' ' ')"
    else
        f "could not copy fail2ban/filter.d/*.conf into /etc/fail2ban/filter.d/"
    fi
    if cp /repo/fail2ban/jail.d/*.local /etc/fail2ban/jail.d/ 2>/dev/null; then
        i "installed jails: $(for x in /etc/fail2ban/jail.d/*.local; do basename "$x"; done | tr '\n' ' ')"
    else
        f "could not copy fail2ban/jail.d/*.local into /etc/fail2ban/jail.d/"
    fi

    # The log the jails point at must exist (fail2ban validates it at start).
    mkdir -p /var/log/nginx
    printf '%s\n' '203.0.113.9 - - [27/Oct/2026:12:00:01 +0000] "GET /admin HTTP/1.1" 404 153 "-" "agentwall-validate-dummy" rt=0.001 urt=- ua_flag=0 probe=0 xff="-"' > /var/log/nginx/agentwall_access.log
    chmod 0640 /var/log/nginx/agentwall_access.log
    i "created /var/log/nginx/agentwall_access.log (0640) with a dummy line"

    # Ubuntu ships [sshd] enabled with backend=systemd; there is no PID-1
    # systemd inside a docker run container, so disable it for this test only.
    # This is a harness adjustment, not a change to the repository config.
    printf '[sshd]\nenabled = false\n' > /etc/fail2ban/jail.d/99-validate-disable-sshd.local
    i "disabled distro [sshd] jail for the container run (backend=systemd, no systemd PID 1 here)"

    # The behavioural jails ship enabled = false (shadow phase). Validate them
    # exactly as an operator enables them in the enforce phase (zz- sorts after
    # agentwall.local, so it overrides enabled = false).
    printf '[agentwall-behavior]\nenabled = true\n\n[agentwall-auth]\nenabled = true\n' \
        > /etc/fail2ban/jail.d/zz-validate-enable-agentwall.local
    i "enabled agentwall-behavior/agentwall-auth for the load test (shipped disabled)"

    # --- config test ------------------------------------------------------
    out=$(fail2ban-client -t 2>&1); rc=$?
    printf '%s\n' "$out" | r
    if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'OK: configuration test is successful'; then
        if printf '%s\n' "$out" | grep -qE 'Wrong value for|ERROR'; then
            f "fail2ban-client -t: OK but config parse problems present ('Wrong value for'/ERROR above) — an option was silently dropped (usually a trailing '#' comment on an option line)"
        else
            p "fail2ban-client -t: OK: configuration test is successful (rc=0; no 'Wrong value for'/ERROR)"
        fi
    else
        f "fail2ban-client -t: FAILED (rc=$rc) — exact output above"
    fi

    # --- jail load test + EFFECTIVE option values (this is what catches a
    #     trailing '#' comment: -t can pass while the option is dropped). -----
    rm -f /run/fail2ban/fail2ban.sock
    fail2ban-client start >/dev/null 2>&1
    n=0
    while [ "$n" -lt 40 ]; do
        [ -S /run/fail2ban/fail2ban.sock ] && break
        sleep 0.25
        n=$((n + 1))
    done
    st=$(fail2ban-client status 2>&1)
    printf '%s\n' "$st" | r
    for jail in agentwall-behavior agentwall-auth agentwall-ml; do
        if printf '%s\n' "$st" | grep -q "$jail"; then
            p "jail loaded after start: $jail"
        else
            f "jail NOT loaded after start: $jail (a dropped/invalid option can make a jail refuse to start)"
        fi
    done
    check_opt() {
        local jail="$1" opt="$2" want="$3" got
        got=$(fail2ban-client get "$jail" "$opt" 2>/dev/null | tail -1 | awk '{print $1}')
        if [ "$got" = "$want" ]; then
            p "effective option ${jail}/${opt} = ${got} (configured value honoured)"
        else
            f "effective option ${jail}/${opt} = '${got:-<missing>}' (expected ${want}) — option was silently dropped; check for a trailing '#' comment in jail.d"
        fi
    }
    if printf '%s\n' "$st" | grep -q 'agentwall-behavior'; then
        check_opt agentwall-behavior maxretry 40
        check_opt agentwall-behavior findtime 60
        check_opt agentwall-behavior bantime 1800
    fi
    if printf '%s\n' "$st" | grep -q 'agentwall-auth'; then
        check_opt agentwall-auth maxretry 10
        check_opt agentwall-auth findtime 120
        check_opt agentwall-auth bantime 1800
    fi
    if printf '%s\n' "$st" | grep -q 'agentwall-ml'; then
        check_opt agentwall-ml maxretry 9999
        check_opt agentwall-ml findtime 10
        check_opt agentwall-ml bantime 1800
    fi
    fail2ban-client stop >/dev/null 2>&1

    # --- fail2ban-regex against synthetic nginx 'agentwall' access-log lines. ----
    # Leading fields must stay: <ip> <ident> <user> [time] "request" <status> ...
    LOGDIR=/tmp/agentwall-f2b-logs
    mkdir -p "$LOGDIR"
    cat > "$LOGDIR/behavior.log" <<'LOG'
203.0.113.10 - - [27/Oct/2026:12:00:01 +0000] "GET /admin HTTP/1.1" 404 153 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" rt=0.002 urt=- ua_flag=0 probe=0 xff="-"
203.0.113.11 - - [27/Oct/2026:12:00:02 +0000] "GET /api/users?page=2 HTTP/1.1" 429 41 "-" "python-requests/2.31.0" rt=0.001 urt=- ua_flag=0 probe=0 xff="198.51.100.7"
203.0.113.12 - - [27/Oct/2026:12:00:03 +0000] "POST /wp-login.php HTTP/1.1" 403 199 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)" rt=0.003 urt=- ua_flag=1 probe=0 xff="-"
203.0.113.13 - - [27/Oct/2026:12:00:03 +0000] "GET /static/app.3f9c.js?v=2 HTTP/1.1" 404 153 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" rt=0.001 urt=- ua_flag=0 probe=0 xff="-"
198.51.100.20 - - [27/Oct/2026:12:00:04 +0000] "GET / HTTP/1.1" 200 5320 "https://example.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" rt=0.010 urt=0.008 ua_flag=0 probe=0 xff="-"
LOG
    cat > "$LOGDIR/auth.log" <<'LOG'
203.0.113.30 - - [27/Oct/2026:12:01:01 +0000] "POST /login HTTP/1.1" 401 61 "-" "curl/8.5.0" rt=0.004 urt=- ua_flag=0 probe=0 xff="-"
203.0.113.31 - - [27/Oct/2026:12:01:02 +0000] "POST /login HTTP/1.1" 403 199 "-" "curl/8.5.0" rt=0.004 urt=- ua_flag=0 probe=0 xff="-"
203.0.113.32 - - [27/Oct/2026:12:01:03 +0000] "GET /login HTTP/1.1" 404 153 "-" "curl/8.5.0" rt=0.004 urt=- ua_flag=0 probe=0 xff="-"
198.51.100.21 - - [27/Oct/2026:12:01:04 +0000] "GET /oauth/authorize?redirect_uri=/login HTTP/1.1" 200 22 "-" "curl/8.5.0" rt=0.004 urt=- ua_flag=0 probe=0 xff="-"
LOG
    cat > "$LOGDIR/ml.log" <<'LOG'
203.0.113.40 - - [27/Oct/2026:12:02:01 +0000] "GET /admin HTTP/1.1" 404 153 "-" "curl/8.5.0" rt=0.002 urt=- ua_flag=0 probe=0 xff="-"
203.0.113.41 - - [27/Oct/2026:12:02:02 +0000] "GET /__agentwall_ml_never_match__ HTTP/1.1" 599 0 "-" "agentwall-scorer" rt=0.000 urt=- ua_flag=0 probe=0 xff="-"
203.0.113.42 - - [27/Oct/2026:12:02:03 +0000] "POST /login HTTP/1.1" 401 61 "-" "curl/8.5.0" rt=0.004 urt=- ua_flag=0 probe=0 xff="-"
198.51.100.22 - - [27/Oct/2026:12:02:04 +0000] "GET / HTTP/1.1" 200 5320 "-" "Mozilla/5.0" rt=0.010 urt=0.008 ua_flag=0 probe=0 xff="-"
LOG

    regex_check() {
        # <label> <log> <filter> <expected matched> [expected ignored]
        local label="$1" log="$2" filt="$3" want_m="$4" want_ign="${5:-}" out summary matched ignored
        out=$(fail2ban-regex "$log" "$filt" 2>&1)
        summary=$(printf '%s\n' "$out" | grep -E '^Lines:' | tail -1)
        if [ -z "$summary" ]; then
            f "${label}: fail2ban-regex produced no 'Lines:' summary — filter could not be loaded"
            printf '%s\n' "$out" | tail -10 | r
            return
        fi
        matched=$(printf '%s\n' "$summary" | sed -n 's/.*, \([0-9][0-9]*\) matched,.*/\1/p')
        ignored=$(printf '%s\n' "$summary" | sed -n 's/^Lines: [0-9][0-9]* lines, \([0-9][0-9]*\) ignored,.*/\1/p')
        i "${label}: ${summary}"
        if [ "${matched:-x}" = "$want_m" ] && { [ -z "$want_ign" ] || [ "${ignored:-x}" = "$want_ign" ]; }; then
            p "${label}: matched=${matched} ignored=${ignored:-?} (expected matched=${want_m}${want_ign:+ ignored=${want_ign}})"
        else
            f "${label}: matched=${matched:-?} ignored=${ignored:-?} (expected matched=${want_m}${want_ign:+ ignored=${want_ign}})"
            printf '%s\n' "$out" | tail -10 | r
        fi
    }
    regex_check "agentwall-behavior regex vs nginx 404/403 (429/static-404/200 not counted)" "$LOGDIR/behavior.log" /etc/fail2ban/filter.d/agentwall-behavior.conf 2 1
    regex_check "agentwall-auth regex vs 401/403 login (+404/200)" "$LOGDIR/auth.log" /etc/fail2ban/filter.d/agentwall-auth.conf 2 0
    regex_check "agentwall-ml regex vs mixed log (must never match)" "$LOGDIR/ml.log" /etc/fail2ban/filter.d/agentwall-ml.conf 0 1
fi
CONTAINER_FAIL2BAN

    # --- ubuntu:24.04 assembler -------------------------------------------
    cat > "$WORKDIR/apt-ubuntu24.sh" <<'APT24'
# --- ubuntu:24.04 package setup (container network required) --------------
export DEBIAN_FRONTEND=noninteractive
pkgs=""
if [ "${RUN_SYSTEMD:-0}" = 1 ]; then pkgs="$pkgs systemd"; fi
if [ "${RUN_FAIL2BAN:-0}" = 1 ]; then pkgs="$pkgs fail2ban"; fi
if [ -n "$pkgs" ]; then
    i "apt-get update (image: ubuntu:24.04) ..."
    if ! apt-get update -qq >/tmp/apt-update.log 2>&1; then
        f "apt-get update failed in ubuntu:24.04 container (network?) — cannot continue systemd/fail2ban checks"
        tail -20 /tmp/apt-update.log | r
        exit 3
    fi
    i "apt-get install:${pkgs} ..."
    # shellcheck disable=SC2086
    if ! apt-get install -y -qq $pkgs >/tmp/apt-install.log 2>&1; then
        f "apt-get install failed:${pkgs}"
        tail -30 /tmp/apt-install.log | r
        exit 3
    fi
    i "installed:${pkgs}"
fi
APT24
    { echo '#!/usr/bin/env bash'; echo 'set -uo pipefail'; cat "$helpers" "$WORKDIR/apt-ubuntu24.sh" "$systemd_part" "$fail2ban_part"; echo 'exit 0'; } > "$WORKDIR/ubuntu24.sh"

    # --- ubuntu:22.04 assembler (fail2ban 0.11.x compat) ------------------
    cat > "$WORKDIR/apt-ubuntu22.sh" <<'APT22'
# --- ubuntu:22.04 package setup: fail2ban 0.11.x compat -------------------
export DEBIAN_FRONTEND=noninteractive
i "apt-get update (image: ubuntu:22.04) ..."
if ! apt-get update -qq >/tmp/apt-update.log 2>&1; then
    f "apt-get update failed in ubuntu:22.04 container (network?) — cannot continue fail2ban-0.11.x compat checks"
    tail -20 /tmp/apt-update.log | r
    exit 3
fi
i "apt-get install: fail2ban ..."
if ! apt-get install -y -qq fail2ban >/tmp/apt-install.log 2>&1; then
    f "apt-get install fail2ban failed in ubuntu:22.04"
    tail -30 /tmp/apt-install.log | r
    exit 3
fi
i "installed: fail2ban"
APT22
    { echo '#!/usr/bin/env bash'; echo 'set -uo pipefail'; cat "$helpers" "$WORKDIR/apt-ubuntu22.sh" "$fail2ban_part"; echo 'exit 0'; } > "$WORKDIR/ubuntu22.sh"

    # --- Apache (httpd:2.4-alpine) ----------------------------------------
    { cat "$helpers"; cat <<'APACHE'
# --- 3) Apache 2.4 config snippet (POSIX sh) ------------------------------
mkdir -p /var/log/apache2 /var/log/apache2/evasive
i "httpd: $(httpd -v 2>&1 | head -1)"
i "pre-created /var/log/apache2 (the snippet's CustomLog target; Debian/Ubuntu layout)"

# Stock image config must be valid before we blame the snippet.
out=$(httpd -t 2>&1); rc=$?
printf '%s\n' "$out" | r
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'Syntax OK'; then
    p "baseline: stock httpd:2.4-alpine config -> Syntax OK"
else
    f "baseline: stock httpd:2.4-alpine config test failed (image problem, not the snippet)"
fi

mods=$(httpd -M 2>/dev/null)
loaded=$(printf '%s\n' "$mods" | sed -n 's/^[[:space:]]*\([a-z0-9_]*\)_module[[:space:]].*/\1/p' | tr '\n' ' ')
i "loaded modules: ${loaded}"
for m in log_config reqtimeout headers setenvif mime; do
    if printf '%s\n' "$loaded" | grep -qw "$m"; then
        i "module loaded by default: ${m}"
    else
        w "module NOT loaded by default in image: ${m}"
    fi
done

# Include the snippet AFTER the stock config (-c) so modules that the stock
# config loads (reqtimeout, headers, ...) are already visible inside
# <IfModule>. With -C (pre-config) those blocks would be silently skipped.
set -- -C "ServerName validate.local"

have_rewrite=0
if printf '%s\n' "$mods" | grep -q 'rewrite_module'; then
    have_rewrite=1
    i "mod_rewrite already loaded"
elif [ -f /usr/local/apache2/modules/mod_rewrite.so ]; then
    set -- "$@" -C "LoadModule rewrite_module modules/mod_rewrite.so"
    have_rewrite=1
    i "loading mod_rewrite explicitly so <IfModule mod_rewrite.c> is parsed"
else
    w "mod_rewrite not shipped by this image: RewriteCond/RewriteRule block SKIPPED/untested"
fi
if printf '%s\n' "$mods" | grep -q 'remoteip_module'; then
    i "mod_remoteip already loaded (its <IfModule> block only contains commented directives, so nothing extra is parsed)"
elif [ -f /usr/local/apache2/modules/mod_remoteip.so ]; then
    set -- "$@" -C "LoadModule remoteip_module modules/mod_remoteip.so"
    i "loaded mod_remoteip (its <IfModule> block only contains commented directives, so nothing extra is parsed)"
fi

# --- the real check: include the repository snippet -----------------------
i "httpd -c 'Include /waf/apache-agentwall.conf' -t (plus module/serverName -C args)"
out=$(httpd "$@" -c "Include /waf/apache-agentwall.conf" -t 2>&1); rc=$?
printf '%s\n' "$out" | r
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'Syntax OK'; then
    p "httpd -t: Syntax OK with waf/apache-agentwall.conf included (RewriteCond/RewriteRule + RequestReadTimeout actually parsed)"
else
    f "httpd -t: FAILED including waf/apache-agentwall.conf (rc=$rc) — exact error above; production config was NOT weakened"
fi

# Literal '-C Include' (pre-config) form, informational: it passes but skips
# <IfModule> blocks whose modules the stock config loads later.
out2=$(httpd "$@" -C "Include /waf/apache-agentwall.conf" -t 2>&1); rc2=$?
if [ "$rc2" -eq 0 ]; then
    i "also tested the literal '-C Include' (pre-config) form: rc=0 (weaker: reqtimeout <IfModule> is skipped in that order)"
else
    i "literal '-C Include' (pre-config) form rc=$rc2 — expected to be weaker; the gated check above uses -c"
fi

# --- canary tests: prove the parsed blocks are really exercised -----------
if [ "$have_rewrite" = 1 ]; then
    printf '<IfModule mod_rewrite.c>\nRewriteRule ^ - [BOGUSFLAG]\n</IfModule>\n' > /tmp/canary-rewrite.conf
    cout=$(httpd "$@" -c "Include /tmp/canary-rewrite.conf" -t 2>&1); crc=$?
    if [ "$crc" -ne 0 ] && printf '%s\n' "$cout" | grep -q "unknown flag 'BOGUSFLAG'"; then
        p "canary: deliberately-broken RewriteRule is REJECTED -> mod_rewrite directives are really parsed (block NOT skipped)"
    else
        f "canary: broken RewriteRule was ACCEPTED -> <IfModule mod_rewrite.c> block is NOT exercised"
    fi
else
    w "canary: mod_rewrite unavailable in image; RewriteCond/RewriteRule remain UNTESTED"
fi
if printf '%s\n' "$loaded" | grep -qw reqtimeout; then
    printf '<IfModule mod_reqtimeout.c>\nRequestReadTimeout nonsense\n</IfModule>\n' > /tmp/canary-reqtimeout.conf
    cout=$(httpd "$@" -c "Include /tmp/canary-reqtimeout.conf" -t 2>&1); crc=$?
    if [ "$crc" -ne 0 ] && printf '%s\n' "$cout" | grep -q 'Invalid RequestReadTimeout'; then
        p "canary: deliberately-broken RequestReadTimeout is REJECTED -> <IfModule mod_reqtimeout.c> block is really parsed"
    else
        f "canary: broken RequestReadTimeout was ACCEPTED -> <IfModule mod_reqtimeout.c> block is NOT exercised"
    fi
else
    w "canary: mod_reqtimeout not loaded; RequestReadTimeout remains UNTESTED"
fi

w "mod_evasive and mod_qos are NOT installed in httpd:2.4-alpine: their <IfModule> blocks (DOS*/QS_*) are SKIPPED and UNTESTED by this script — residual risk, validate on a host with libapache2-mod-evasive/libapache2-mod-qos"
i "covered by httpd -t: LogFormat/CustomLog, RequestReadTimeout, RewriteCond/RewriteRule, commented RemoteIP config"
i "skipped by httpd -t: mod_evasive DOS* directives, mod_qos QS_*/MaxClients (modules absent)"
APACHE
    } > "$WORKDIR/apache.sh"

    # --- OpenResty (openresty/openresty:alpine) ---------------------------
    { cat "$helpers"; cat <<'OPENRESTY'
# --- 4) OpenResty production config (POSIX sh) ---------------------------
mkdir -p /tmp/ngx/logs /var/log/nginx /etc/nginx
ln -sfn /repo/nginx-lua /etc/nginx/lua
i "openresty: $(/usr/local/openresty/bin/openresty -v 2>&1 | head -1)"

# nginx -t does not compile *_by_lua_file bodies, so syntax-check them here.
lua_bad=0
for lf in /repo/nginx-lua/*.lua; do
    if /usr/local/openresty/luajit/bin/luajit -bl "$lf" >/dev/null 2>/tmp/luajit.err; then
        :
    else
        lua_bad=1
        i "luajit syntax error in $(basename "$lf"): $(head -3 /tmp/luajit.err | tr '\n' ' ')"
    fi
done
if [ "$lua_bad" -eq 0 ]; then
    p "luajit -bl syntax check: all nginx-lua/*.lua compile (syntax only, not runtime)"
else
    f "luajit -bl syntax check: nginx-lua/*.lua has syntax error(s) — see above"
fi

if [ "${MODE:-real}" = "real" ]; then
    i "openresty -p /tmp/ngx -c /repo/deploy/nginx.conf.example -t  (full production config)"
    out=$(/usr/local/openresty/bin/openresty -p /tmp/ngx -c /repo/deploy/nginx.conf.example -t 2>&1); rc=$?
    printf '%s\n' "$out" | r
    if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'syntax is ok' && printf '%s\n' "$out" | grep -q 'test is successful'; then
        p "openresty -t: \"syntax is ok\" + \"test is successful\" on deploy/nginx.conf.example"
    else
        f "openresty -t: FAILED on deploy/nginx.conf.example (rc=$rc) — exact error above"
    fi
else
    # Fallback structural validation of the snippet. It contains
    # `listen 443 ssl;` and ships no certificate, so the wrapper supplies a
    # throwaway self-signed cert at http level (valid context for ssl_certificate).
    w "deploy/nginx.conf.example absent: production-config 'openresty -t' recorded as SKIP; validating waf/nginx-agentwall.conf structurally instead (weaker)"
    cert_ok=0
    if [ -x /usr/local/openresty/openssl3/bin/openssl ]; then
        # The image's openssl is built with a compile-time OPENSSLDIR whose
        # openssl.cnf is not shipped, so pass a minimal explicit -config.
        printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = validate.local\n' > /tmp/ngx/openssl.cnf
        if /usr/local/openresty/openssl3/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
            -config /tmp/ngx/openssl.cnf -keyout /tmp/ngx/key.pem -out /tmp/ngx/cert.pem >/dev/null 2>&1; then
            cert_ok=1
            i "generated throwaway self-signed cert for the wrapper config"
        fi
    fi
    include_target=/repo/waf/nginx-agentwall.conf
    if [ "$cert_ok" -ne 1 ]; then
        sed 's/^[[:space:]]*listen 443 ssl;/    listen 8443;/' "$include_target" > /tmp/ngx/defense-nossl.conf
        include_target=/tmp/ngx/defense-nossl.conf
        w "could not generate a test certificate; wrapper uses a copy with 'listen 443 ssl' replaced by 'listen 8443' (only the listen line changed)"
    fi
    {
        echo 'worker_processes 1;'
        echo 'error_log /tmp/ngx/error.log;'
        echo 'pid /tmp/ngx/nginx.pid;'
        echo 'events { worker_connections 128; }'
        echo 'http {'
        if [ "$cert_ok" -eq 1 ]; then
            echo '    ssl_certificate     /tmp/ngx/cert.pem;'
            echo '    ssl_certificate_key /tmp/ngx/key.pem;'
        fi
        echo "    include ${include_target};"
        echo '}'
    } > /tmp/ngx/wrapper.conf
    out=$(/usr/local/openresty/bin/openresty -p /tmp/ngx -c /tmp/ngx/wrapper.conf -t 2>&1); rc=$?
    printf '%s\n' "$out" | r
    if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q 'syntax is ok' && printf '%s\n' "$out" | grep -q 'test is successful'; then
        p "openresty -t: waf/nginx-agentwall.conf wrapped in http{} -> syntax is ok + test is successful"
    else
        f "openresty -t: waf/nginx-agentwall.conf failed structural nginx parse (rc=$rc)"
    fi

    src=/repo/waf/nginx-agentwall.conf
    active=$(sed 's/#.*//' "$src")
    opens=$(printf '%s\n' "$active" | grep -o '{' | wc -l | tr -d ' ')
    closes=$(printf '%s\n' "$active" | grep -o '}' | wc -l | tr -d ' ')
    if [ "$opens" = "$closes" ]; then
        p "structural: braces balanced in waf/nginx-agentwall.conf (${opens} '{' / ${closes} '}')"
    else
        f "structural: braces NOT balanced in waf/nginx-agentwall.conf (${opens} '{' vs ${closes} '}')"
    fi
    for d in "limit_req_zone" "limit_conn_zone" "limit_req_status" "limit_conn_status" "log_format agentwall" "server {" "access_log"; do
        if printf '%s\n' "$active" | grep -Fq "$d"; then
            p "structural: present: ${d}"
        else
            f "structural: MISSING directive: ${d}"
        fi
    done
    for d in 'map $http_user_agent' 'map "$uri|$query_string"'; do
        if printf '%s\n' "$active" | grep -Fq "$d"; then
            p "structural: present: ${d}"
        else
            f "structural: MISSING directive: ${d}"
        fi
    done
fi
OPENRESTY
    } > "$WORKDIR/openresty.sh"
}

# ---------------------------------------------------------------------------
# Section runners
# ---------------------------------------------------------------------------
run_systemd_fail2ban() {
    section "1+2) systemd unit + fail2ban  (image: ${IMAGE_UBUNTU}; fail2ban 1.0.x)"
    if ! ensure_image "$IMAGE_UBUNTU"; then
        s "systemd + fail2ban: ubuntu image unavailable"
        return
    fi
    local run_sys="$((1 - SKIP_SYSTEMD))"
    local run_f2b="$((1 - SKIP_FAIL2BAN))"
    run_container_script "$IMAGE_UBUNTU" bash "$WORKDIR/ubuntu24.sh" \
        -e "RUN_SYSTEMD=${run_sys}" -e "RUN_FAIL2BAN=${run_f2b}" \
        -v "${REPO_ROOT}:/repo:ro"
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        f "ubuntu:24.04 validation container exited rc=$rc — one or more checks could not run (see output above)"
    fi
}

run_fail2ban_011() {
    section "2b) fail2ban 0.11.x compatibility  (image: ${IMAGE_UBUNTU_OLD}; expected fail2ban 0.11.2)"
    if ! ensure_image "$IMAGE_UBUNTU_OLD"; then
        s "fail2ban 0.11.x compat: ubuntu:22.04 image unavailable"
        return
    fi
    run_container_script "$IMAGE_UBUNTU_OLD" bash "$WORKDIR/ubuntu22.sh" \
        -e "RUN_FAIL2BAN=1" -e "RUN_SYSTEMD=0" \
        -v "${REPO_ROOT}:/repo:ro"
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        f "ubuntu:22.04 fail2ban-compat container exited rc=$rc — one or more checks could not run"
    fi
}

run_apache() {
    section "3) Apache 2.4 config  (image: ${IMAGE_HTTPD})"
    if ! ensure_image "$IMAGE_HTTPD"; then
        s "apache: image unavailable"
        return
    fi
    run_container_script "$IMAGE_HTTPD" sh "$WORKDIR/apache.sh" \
        -v "${REPO_ROOT}/waf:/waf:ro"
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        f "httpd:2.4-alpine container exited rc=$rc — one or more checks could not run"
    fi
}

wait_for_nginx_conf() {
    # Wait up to NGINX_CONF_WAIT seconds for deploy/nginx.conf.example to appear
    # (it may be edited/written by another team member while this runs).
    local conf="${REPO_ROOT}/deploy/nginx.conf.example"
    [ -f "$conf" ] && return 0
    [ "$NGINX_CONF_WAIT" -le 0 ] && return 1
    i "deploy/nginx.conf.example not present yet; waiting up to ${NGINX_CONF_WAIT}s for it ..."
    local waited=0
    while [ ! -f "$conf" ] && [ "$waited" -lt "$NGINX_CONF_WAIT" ]; do
        sleep 5
        waited=$((waited + 5))
        if [ $((waited % 30)) -eq 0 ] && [ ! -f "$conf" ]; then
            i "still waiting for deploy/nginx.conf.example (${waited}s/${NGINX_CONF_WAIT}s)"
        fi
    done
    [ -f "$conf" ]
}

run_openresty() {
    section "4) OpenResty -t production config  (image: ${IMAGE_OPENRESTY})"
    if ! ensure_image "$IMAGE_OPENRESTY"; then
        s "openresty: image unavailable"
        return
    fi
    local mode=real
    if [ ! -f "${REPO_ROOT}/deploy/nginx.conf.example" ]; then
        if wait_for_nginx_conf; then
            mode=real
        else
            mode=fallback
            s "openresty -t on deploy/nginx.conf.example: file absent (SKIP) — falling back to structural validation of waf/nginx-agentwall.conf"
        fi
    fi
    run_container_script "$IMAGE_OPENRESTY" sh "$WORKDIR/openresty.sh" \
        -e "MODE=${mode}" \
        -v "${REPO_ROOT}:/repo:ro"
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        f "openresty container exited rc=$rc — one or more checks could not run"
    fi
}

run_redis() {
    section "5) Redis auth + block-key contract  (image: ${IMAGE_REDIS}; INFORMATIONAL, not a gate)"
    if ! ensure_image "$IMAGE_REDIS"; then
        s "redis: image unavailable"
        return
    fi
    local rpass name cid
    rpass="agentwall-validate-$(date +%s)-$$"
    name="agentwall-validate-redis-$$"
    cid=$(docker run -d --rm --label agentwall-validate=1 --name "$name" "$IMAGE_REDIS" \
        redis-server --requirepass "$rpass" --save '' --appendonly no 2>/dev/null)
    if [ -z "$cid" ]; then
        w "redis: could not start redis:7-alpine container (informational only, not gated)"
        return
    fi
    local ready=0 n=0
    while [ "$n" -lt 50 ]; do
        if docker exec "$cid" redis-cli -a "$rpass" --no-auth-warning ping 2>/dev/null | grep -q PONG; then
            ready=1
            break
        fi
        sleep 0.2
        n=$((n + 1))
    done
    if [ "$ready" -ne 1 ]; then
        w "redis: server did not become ready; contract not validated (informational only)"
        docker rm -f "$cid" >/dev/null 2>&1 || true
        return
    fi
    local out
    out=$(docker exec "$cid" redis-cli ping 2>&1 || true)
    if printf '%s' "$out" | grep -q 'NOAUTH'; then
        p "redis: unauthenticated PING rejected ('NOAUTH Authentication required.')"
    else
        w "redis: unauthenticated PING was NOT rejected (got: ${out})"
    fi
    out=$(docker exec "$cid" redis-cli -a "$rpass" --no-auth-warning ping 2>&1 || true)
    if [ "$out" = "PONG" ]; then
        p "redis: authenticated PING -> PONG (--requirepass honoured)"
    else
        w "redis: authenticated PING failed (got: ${out})"
    fi
    out=$(docker exec "$cid" redis-cli -a "$rpass" --no-auth-warning SET agentwall:block:1.2.3.4 1 EX 60 2>&1 || true)
    if [ "$out" = "OK" ]; then
        p "redis: SET agentwall:block:1.2.3.4 1 EX 60 -> OK (contract used by the Lua enforcement layer)"
    else
        w "redis: SET agentwall:block:1.2.3.4 1 EX 60 failed (got: ${out})"
    fi
    out=$(docker exec "$cid" redis-cli -a "$rpass" --no-auth-warning TTL agentwall:block:1.2.3.4 2>&1 || true)
    if [ "$out" -gt 0 ] 2>/dev/null && [ "$out" -le 60 ] 2>/dev/null; then
        p "redis: TTL agentwall:block:1.2.3.4 = ${out}s (0 < ttl <= 60)"
    else
        w "redis: TTL agentwall:block:1.2.3.4 unexpected (got: ${out}; expected 1..60)"
    fi
    out=$(docker exec "$cid" redis-cli -a "$rpass" --no-auth-warning GET agentwall:block:1.2.3.4 2>&1 || true)
    if [ "$out" = "1" ]; then
        p "redis: GET agentwall:block:1.2.3.4 -> 1"
    else
        w "redis: GET agentwall:block:1.2.3.4 unexpected (got: ${out})"
    fi
    i "note: validates the Redis key/TTL contract only; it does not run the Lua layer against Redis"
    docker rm -f "$cid" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    printf '\n'
    printf '==========================================================================\n'
    printf ' SUMMARY: PASS=%d  WARN=%d  FAIL=%d  SKIP=%d\n' "$PASS" "$WARN" "$FAIL" "$SKIP"
    printf ' runtime: %ss   docker server: %s\n' "$SECONDS" "${DOCKER_VERSION}"
    if [ "${#IMAGES_USED[@]}" -gt 0 ]; then
        printf ' images used: %s\n' "${IMAGES_USED[*]}"
    fi
    if [ "${#PULLED_IMAGES[@]}" -gt 0 ]; then
        printf ' pulled this run: %s\n' "${PULLED_IMAGES[*]}"
    fi
    if [ "$FAIL" -gt 0 ]; then
        printf '\n FAILURES (must be fixed):\n'
        local x
        for x in "${FAILURES[@]}"; do
            printf '   - %s\n' "$x"
        done
    fi
    if [ "$WARN" -gt 0 ]; then
        printf '\n WARNINGS (not gated, review them):\n'
        local x
        for x in "${WARNINGS[@]}"; do
            printf '   - %s\n' "$x"
        done
    fi
    if [ "$SKIP" -gt 0 ]; then
        printf '\n SKIPPED:\n'
        local x
        for x in "${SKIPPED[@]}"; do
            printf '   - %s\n' "$x"
        done
    fi
    printf '==========================================================================\n'
    if [ "$FAIL" -gt 0 ]; then
        printf ' RESULT: FAIL (%d failure(s))\n' "$FAIL"
        return 1
    fi
    printf ' RESULT: PASS (zero FAIL; %d warning(s), %d skip(s))\n' "$WARN" "$SKIP"
    return 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
cleanup() {
    local ids
    ids=$(docker ps -aq --filter label=agentwall-validate=1 2>/dev/null || true)
    if [ -n "$ids" ]; then
        # shellcheck disable=SC2086
        docker rm -f $ids >/dev/null 2>&1 || true
    fi
    if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
        rm -rf "$WORKDIR"
    fi
}

main() {
    parse_args "$@"
    if [ -z "$WORKDIR" ]; then
        WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/agentwall-validate.XXXXXX")" || {
            printf 'FATAL: could not create temporary workdir\n' >&2
            exit 2
        }
    fi
    trap cleanup EXIT
    trap 'exit 130' INT TERM

    printf 'agentwall — Linux-native validation (Docker only; host untouched)\n'
    docker_preflight
    generate_container_scripts

    if [ "$SKIP_SYSTEMD" = 0 ] || [ "$SKIP_FAIL2BAN" = 0 ]; then
        run_systemd_fail2ban
    else
        s "systemd + fail2ban sections (--skip-systemd --skip-fail2ban)"
    fi

    if [ "$SKIP_FAIL2BAN" = 0 ] && [ "$SKIP_FAIL2BAN_011" = 0 ]; then
        run_fail2ban_011
    else
        s "fail2ban 0.11.x compat re-run (--skip-fail2ban / --skip-fail2ban-011)"
    fi

    if [ "$SKIP_APACHE" = 0 ]; then
        run_apache
    else
        s "apache section (--skip-apache)"
    fi

    if [ "$SKIP_OPENRESTY" = 0 ]; then
        run_openresty
    else
        s "openresty section (--skip-openresty)"
    fi

    if [ "$SKIP_REDIS" = 0 ]; then
        run_redis
    else
        s "redis section (--skip-redis)"
    fi

    print_summary
}

main "$@"
