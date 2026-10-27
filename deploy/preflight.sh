#!/usr/bin/env bash
# =============================================================================
# deploy/preflight.sh — go-live / self-test for the AgentWall defense stack
# -----------------------------------------------------------------------------
# Run this ON THE HOST that will run each component (proxy host for the log /
# nginx / fail2ban checks; scorer host for Redis/Lua/secret checks), after you
# have installed the files but BEFORE you rely on them. It never changes
# anything: every check is read-only.
#
#   ./deploy/preflight.sh                                  # defaults
#   sudo ./deploy/preflight.sh --use-xff                   # proxy host, scorer uses XFF
#   sudo ./deploy/preflight.sh --backend fail2ban --fail2ban-sudo
#   sudo ./deploy/preflight.sh --phase 3                   # expect enforce enabled
#   ./deploy/preflight.sh --log /var/log/apache2/agentwall_access.log \
#                         --apache-conf waf/apache-agentwall.conf
#
# Exit status: 0 = no hard failures (warnings may be present), 1 = at least one
# FAIL, 2 = usage error. WARN items are things to review, not blockers; FAIL
# items mean the stack is misconfigured for the mode you asked for.
#
# Checks:
#   1. scorer sources present + `python3 -m py_compile scorer/*.py`
#   2. all nginx-lua/*.lua compile via `lua -e assert(loadfile(...))`
#   3. access log readable; with --use-xff the recent lines must carry xff="..."
#   4. Redis ping for REDIS_URL (when redis-cli is installed)
#   5. `nginx -t` / `openresty -t` when the binary exists and we are root
#   6. AGENTWALL_CHAL_SECRET / AGENTWALL_REDIS_PASS presence warnings
#   7. fail2ban config test + `agentwall-ml` jail existence (backend fail2ban/both)
#      and the sudoers rule when --fail2ban-sudo is used
#   8. repo-config regressions: compose command has no inline-comment tokens;
#      the systemd unit is dry-run unless --phase 3; Apache LogFormat has xff=
#      and CustomLog is enabled
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

PASS=0; WARN=0; FAIL=0; SKIP=0
USE_XFF=0
BACKEND="none"
JAIL="agentwall-ml"
REDIS_URL="${REDIS_URL:-redis://127.0.0.1:6379/0}"
LOG=""
PHASE=1
APACHE_CONF=""
SKIP_REDIS=0
FAIL2BAN_SUDO=0
PYTHON="${PYTHON:-python3}"
TMPD=""

if [ -t 1 ]; then
    C_PASS=$'\033[32m'; C_WARN=$'\033[33m'; C_FAIL=$'\033[31m'
    C_SKIP=$'\033[36m'; C_OFF=$'\033[0m'
else
    C_PASS=""; C_WARN=""; C_FAIL=""; C_SKIP=""; C_OFF=""
fi

pass() { PASS=$((PASS + 1)); printf '%sPASS%s %s\n' "$C_PASS" "$C_OFF" "$*"; }
warn() { WARN=$((WARN + 1)); printf '%sWARN%s %s\n' "$C_WARN" "$C_OFF" "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '%sFAIL%s %s\n' "$C_FAIL" "$C_OFF" "$*" >&2; }
skip() { SKIP=$((SKIP + 1)); printf '%sSKIP%s %s\n' "$C_SKIP" "$C_OFF" "$*"; }

usage() {
    cat <<'EOF'
Usage: deploy/preflight.sh [options]

Read-only go-live self-test for the AgentWall defense stack.
Exit 0 = no FAIL, 1 = at least one FAIL, 2 = usage error.

Options:
  --log PATH          access log the scorer/fail2ban read
                      (default: auto-detect nginx then apache agentwall log)
  --use-xff           scorer runs with --use-xff: require xff="..." in the log
  --backend MODE      scorer backend: none|redis|fail2ban|both (default: none)
  --jail NAME         fail2ban manual-ban jail name (default: agentwall-ml)
  --redis-url URL     Redis URL to ping (default: $REDIS_URL or 127.0.0.1:6379/0)
  --skip-redis        do not treat an unreachable Redis as a failure
  --phase N           expected rollout phase 1..4 (default: 1). With --phase 3+
                      an active --enforce in the repo config is expected, not a bug.
  --apache-conf PATH  Apache config to check for LogFormat xff= + CustomLog
                      (default: <repo>/waf/apache-agentwall.conf if present)
  --fail2ban-sudo     scorer uses --fail2ban-sudo: check sudoers + unit NNP
  --python PATH       Python interpreter (default: python3 / $PYTHON)
  -h, --help          show this help
EOF
}

cleanup() {
    if [ -n "$TMPD" ] && [ -d "$TMPD" ]; then
        rm -rf "$TMPD"
    fi
}
trap cleanup EXIT INT TERM
TMPD="$(mktemp -d "${TMPDIR:-/tmp}/agentwall-preflight.XXXXXX")"

# Mask credentials in URLs before printing them.
mask_url() {
    printf '%s' "$1" | sed -E 's#(redis://[^:/@]*:)[^@]*@#\1***@#'
}

# --- argument parsing -------------------------------------------------------
while [ "$#" -gt 0 ]; do
    case "$1" in
        --log)
            [ "$#" -ge 2 ] || { echo "error: --log needs a value" >&2; exit 2; }
            LOG="$2"; shift 2 ;;
        --use-xff)          USE_XFF=1; shift ;;
        --backend)
            [ "$#" -ge 2 ] || { echo "error: --backend needs a value" >&2; exit 2; }
            BACKEND="$2"; shift 2 ;;
        --jail)
            [ "$#" -ge 2 ] || { echo "error: --jail needs a value" >&2; exit 2; }
            JAIL="$2"; shift 2 ;;
        --redis-url)
            [ "$#" -ge 2 ] || { echo "error: --redis-url needs a value" >&2; exit 2; }
            REDIS_URL="$2"; shift 2 ;;
        --skip-redis)       SKIP_REDIS=1; shift ;;
        --phase)
            [ "$#" -ge 2 ] || { echo "error: --phase needs a value" >&2; exit 2; }
            PHASE="$2"; shift 2 ;;
        --apache-conf)
            [ "$#" -ge 2 ] || { echo "error: --apache-conf needs a value" >&2; exit 2; }
            APACHE_CONF="$2"; shift 2 ;;
        --fail2ban-sudo)    FAIL2BAN_SUDO=1; shift ;;
        --python)
            [ "$#" -ge 2 ] || { echo "error: --python needs a value" >&2; exit 2; }
            PYTHON="$2"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        *)
            echo "error: unknown option: $1" >&2
            usage >&2
            exit 2 ;;
    esac
done

case "$PHASE" in
    1|2|3|4) : ;;
    *) echo "error: --phase must be 1..4" >&2; exit 2 ;;
esac

echo "AGENTWALL preflight — $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "  repo:     $REPO_ROOT"
echo "  phase:    $PHASE"
echo "  backend:  $BACKEND (jail: $JAIL)"
echo "  redis:    $(mask_url "$REDIS_URL")"
echo "  xff mode: $([ "$USE_XFF" -eq 1 ] && echo yes || echo no)"
echo

# --- 1. scorer sources ------------------------------------------------------
echo "== 1. Scorer sources =="
SCORER_DIR="$REPO_ROOT/scorer"
if [ -f "$SCORER_DIR/agentwall_scorer.py" ]; then
    pass "scorer present: scorer/agentwall_scorer.py"
else
    fail "missing scorer/agentwall_scorer.py (is REPO_ROOT=$REPO_ROOT the repo?)"
fi
if command -v "$PYTHON" >/dev/null 2>&1; then
    mkdir -p "$TMPD/pycache"
    if PYTHONPYCACHEPREFIX="$TMPD/pycache" "$PYTHON" -m py_compile "$SCORER_DIR"/*.py \
            >"$TMPD/pycompile.out" 2>&1; then
        pass "scorer/*.py compile ($("$PYTHON" --version 2>&1))"
    else
        fail "py_compile failed: $(tail -n 3 "$TMPD/pycompile.out" | tr '\n' ' ')"
    fi
else
    warn "$PYTHON not found — cannot compile-check the scorer"
fi

# --- 2. Lua -----------------------------------------------------------------
echo
echo "== 2. Lua (nginx-lua/) =="
if command -v lua >/dev/null 2>&1; then
    lua_count=0
    lua_bad=0
    for f in "$REPO_ROOT"/nginx-lua/*.lua; do
        [ -e "$f" ] || continue
        lua_count=$((lua_count + 1))
        if ! lua -e "assert(loadfile([[$f]]))" >/dev/null 2>"$TMPD/lua.err"; then
            fail "Lua failed to load: ${f#"$REPO_ROOT"/} — $(tail -n 1 "$TMPD/lua.err")"
            lua_bad=$((lua_bad + 1))
        fi
    done
    if [ "$lua_count" -eq 0 ]; then
        warn "no nginx-lua/*.lua files found"
    elif [ "$lua_bad" -eq 0 ]; then
        pass "all $lua_count nginx-lua/*.lua files load (syntax/compile)"
    fi
else
    warn "lua not installed — skipping Lua syntax check (install lua5.1/luajit to enable)"
fi

# --- 3. access log ----------------------------------------------------------
echo
echo "== 3. Access log =="
if [ -z "$LOG" ]; then
    for cand in /var/log/nginx/agentwall_access.log /var/log/apache2/agentwall_access.log; do
        if [ -r "$cand" ]; then LOG="$cand"; break; fi
    done
fi
if [ -z "$LOG" ]; then
    fail "no readable agentwall access log found (nginx/apache defaults absent) — pass --log PATH"
elif [ ! -r "$LOG" ]; then
    fail "log not readable: $LOG (the scorer user needs adm/group read; e.g. SupplementaryGroups=adm)"
else
    pass "log readable: $LOG"
    # Last 500 lines are plenty to verify the format without loading the file.
    recent="$(tail -n 500 "$LOG" 2>/dev/null || true)"
    if [ "$USE_XFF" -eq 1 ]; then
        if grep -q 'xff="' <<<"$recent"; then
            pass "recent lines contain xff=\"...\" (required for --use-xff)"
        else
            fail "no xff=\"...\" field in the last 500 lines but --use-xff was requested — add xff=\"%{X-Forwarded-For}i\" to the log format or drop --use-xff"
        fi
    else
        if grep -q 'xff="' <<<"$recent"; then
            pass "log carries xff=\"...\" (unused without --use-xff; fine in real_ip mode)"
        else
            warn "log has no xff=\"...\" tail (fine in real_ip mode; --use-xff would silently fall back to the first field)"
        fi
    fi
    if [ -n "$(find "$LOG" -mmin -15 2>/dev/null || true)" ]; then
        pass "log written within the last 15 min"
    else
        warn "log not modified in 15 min — is the proxy writing it? (scorer/fail2ban would idle)"
    fi
fi

# --- 4. Redis ---------------------------------------------------------------
echo
echo "== 4. Redis =="
if [ "$SKIP_REDIS" -eq 1 ]; then
    warn "Redis check skipped (--skip-redis)"
elif command -v redis-cli >/dev/null 2>&1; then
    redis_pong="$(redis-cli -u "$REDIS_URL" ping 2>/dev/null || true)"
    if grep -q '^PONG$' <<<"$redis_pong"; then
        pass "Redis reachable: $(mask_url "$REDIS_URL")"
    else
        fail "redis-cli ping failed: $(mask_url "$REDIS_URL") — check requirepass/network; dry-run may start without Redis but challenge/enforce cannot"
    fi
else
    warn "redis-cli not installed — cannot verify $(mask_url "$REDIS_URL") (install redis-tools or check by hand)"
fi

# --- 5. proxy config test ---------------------------------------------------
echo
echo "== 5. Proxy config test =="
NGINX_BIN=""
if command -v nginx >/dev/null 2>&1; then
    NGINX_BIN="$(command -v nginx)"
elif command -v openresty >/dev/null 2>&1; then
    NGINX_BIN="$(command -v openresty)"
fi
if [ -n "$NGINX_BIN" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        if "$NGINX_BIN" -t >"$TMPD/nginx.out" 2>&1; then
            pass "nginx -t OK ($NGINX_BIN)"
        else
            fail "nginx -t FAILED: $(tail -n 3 "$TMPD/nginx.out" | tr '\n' ' ')"
        fi
    else
        warn "nginx installed but 'nginx -t' needs root (log/pid files) — rerun as root to test the installed config"
    fi
else
    warn "no nginx/openresty binary found — skipping 'nginx -t' (expected on a non-proxy host)"
fi

# --- 6. secrets -------------------------------------------------------------
echo
echo "== 6. Challenge/Redis secrets (env) =="
if [ -n "${AGENTWALL_CHAL_SECRET:-}" ]; then
    pass "AGENTWALL_CHAL_SECRET is set"
else
    warn "AGENTWALL_CHAL_SECRET is not set — the Lua challenge layer FAILS OPEN loudly (CRIT log, no challenge issued) until it is set; required before phase 2 (challenge-only)"
fi
if [ -n "${AGENTWALL_REDIS_PASS:-}" ] || [ -n "${REDIS_PASS:-}" ]; then
    pass "Redis password env is set (AGENTWALL_REDIS_PASS/REDIS_PASS)"
else
    warn "neither AGENTWALL_REDIS_PASS (Lua) nor REDIS_PASS (compose) is set — required when Redis uses requirepass (the compose stack does); the Lua AUTH fails otherwise"
fi

# --- 7. fail2ban ------------------------------------------------------------
echo
echo "== 7. fail2ban =="
case "$BACKEND" in
    fail2ban|both)
        if command -v fail2ban-client >/dev/null 2>&1; then
            if [ "$(id -u)" -eq 0 ]; then
                if fail2ban-client -t >"$TMPD/f2b.out" 2>&1; then
                    pass "fail2ban config test OK (fail2ban-client -t)"
                else
                    fail "fail2ban-client -t FAILED: $(tail -n 3 "$TMPD/f2b.out" | tr '\n' ' ')"
                fi
                if fail2ban-client status "$JAIL" >/dev/null 2>&1; then
                    pass "fail2ban jail '$JAIL' exists"
                else
                    fail "fail2ban jail '$JAIL' not found — install fail2ban/{filter.d,jail.d}/*, then 'fail2ban-client -t && fail2ban-client reload'"
                fi
            else
                warn "fail2ban-client needs root for -t/status — rerun as root to verify jail '$JAIL'"
            fi
        else
            warn "fail2ban-client not found — backend '$BACKEND' will log ban failures at runtime"
        fi
        if [ "$FAIL2BAN_SUDO" -eq 1 ]; then
            if [ -f /etc/sudoers.d/agentwall-ml ]; then
                pass "sudoers rule installed: /etc/sudoers.d/agentwall-ml"
            else
                fail "--fail2ban-sudo requested but /etc/sudoers.d/agentwall-ml is missing — install deploy/sudoers.d-agentwall (mode 0440) and 'visudo -cf' it"
            fi
            if grep -q '^NoNewPrivileges=true' "$REPO_ROOT/deploy/agentwall-scorer.service" 2>/dev/null; then
                warn "deploy/agentwall-scorer.service sets NoNewPrivileges=true — that blocks setuid sudo; set it false for --fail2ban-sudo (or prefer --backend redis)"
            fi
            if command -v sudo >/dev/null 2>&1; then
                if sudo -n -l /usr/bin/fail2ban-client set "$JAIL" banip 203.0.113.7 >/dev/null 2>&1; then
                    pass "sudoers allows exactly the scoring ban command (sudo -n -l)"
                else
                    warn "could not confirm the sudoers rule non-interactively (sudo -n -l); test as the service user: sudo -u agentwall sudo -n fail2ban-client set $JAIL banip 203.0.113.7"
                fi
            fi
        fi
        ;;
    redis|none)
        pass "backend '$BACKEND' does not need the fail2ban manual-ban path"
        ;;
    *)
        warn "unknown --backend '$BACKEND' (expected none|redis|fail2ban|both)"
        ;;
esac

# --- 8. repo config regressions --------------------------------------------
echo
echo "== 8. Repo config regressions =="
COMPOSE="$REPO_ROOT/deploy/docker-compose.yml"
if [ -f "$COMPOSE" ]; then
    if ! command -v "$PYTHON" >/dev/null 2>&1; then
        warn "python3 not found — cannot parse $COMPOSE"
    else
        rc=0
        "$PYTHON" -c '
import sys, shlex
try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML not installed\n")
    sys.exit(4)
try:
    with open(sys.argv[1]) as fh:
        d = yaml.safe_load(fh)
    cmd = d["services"]["scorer"]["command"]
except Exception as e:
    sys.stderr.write("parse error: %s\n" % e)
    sys.exit(1)
if isinstance(cmd, str):
    sys.stderr.write("command is a YAML scalar, not a list: a folded > scalar"
                     " swallows # comments into argv; use a YAML list\n")
    sys.exit(5)
bad = [t for t in cmd if "#" in str(t)]
if bad:
    sys.stderr.write("inline comment leaked into argv: %r\n" % (bad,))
    sys.exit(3)
print("%d args, no inline-comment tokens" % len(cmd))
' "$COMPOSE" >"$TMPD/compose.out" 2>&1 || rc=$?
        case "$rc" in
            0)
                pass "compose scorer command: $(cat "$TMPD/compose.out")" ;;
            4)
                warn "PyYAML not installed — cannot validate $COMPOSE (pip install pyyaml)" ;;
            1)
                fail "compose YAML invalid: $(tail -n 2 "$TMPD/compose.out" | tr '\n' ' ')" ;;
            5)
                fail "compose scorer command is a YAML scalar, not a list — a '#' comment inside a folded '>' scalar becomes CLI args; use a YAML list" ;;
            3)
                fail "compose scorer command contains '#' tokens — an inline comment leaked into argv; argparse exits 2 and the scorer crash-loops" ;;
            *)
                fail "compose command check failed (rc=$rc): $(tail -n 2 "$TMPD/compose.out" | tr '\n' ' ')" ;;
        esac
    fi
    # Active (uncommented) --enforce in the scorer command list.
    if grep -q -- '"--enforce"' <<<"$(grep -vE '^[[:space:]]*#' "$COMPOSE")"; then
        if [ "$PHASE" -ge 3 ]; then
            pass "compose scorer is enforcing (phase $PHASE requested)"
        else
            fail "compose scorer command has an active \"--enforce\" but phase=$PHASE — the shipped default must be dry-run"
        fi
    else
        pass "compose scorer is dry-run by default (no active --enforce)"
    fi
else
    warn "no deploy/docker-compose.yml found under $REPO_ROOT"
fi

UNIT="$REPO_ROOT/deploy/agentwall-scorer.service"
if [ -f "$UNIT" ]; then
    if grep -q -- '--enforce' <<<"$(grep -vE '^[[:space:]]*#' "$UNIT")"; then
        if [ "$PHASE" -ge 3 ]; then
            pass "systemd unit enforces (phase $PHASE requested)"
        else
            fail "systemd unit has an ACTIVE --enforce line but phase=$PHASE — the shipped default must be dry-run (comment the phase-3 ExecStart)"
        fi
    else
        pass "systemd unit is dry-run by default (no active --enforce)"
    fi
    if grep -q -- 'EnvironmentFile=-/etc/agentwall-scorer.env' <<<"$(grep -vE '^[[:space:]]*#' "$UNIT")"; then
        pass "systemd unit loads REDIS_URL from /etc/agentwall-scorer.env"
    else
        warn "systemd unit does not reference EnvironmentFile=-/etc/agentwall-scorer.env — REDIS_URL would fall back to localhost"
    fi
    # A '#' folded into ExecStart (e.g. a comment between continuation lines)
    # would be passed to the scorer as an argument — same class of bug as the
    # compose scalar. Join continuations, then look for '#' in the directive.
    awk '
        BEGIN { buf = "" }
        {
            if (buf == "" && $0 ~ /^[[:space:]]*#/) next
            if (buf == "") buf = $0; else buf = buf " " $0
            if (buf ~ /\\[[:space:]]*$/) { sub(/\\[[:space:]]*$/, "", buf); next }
            if (buf ~ /^[[:space:]]*ExecStart=/ && index(buf, "#") > 0) print buf
            buf = ""
        }
        END {
            if (buf ~ /^[[:space:]]*ExecStart=/ && index(buf, "#") > 0) print buf
        }
    ' "$UNIT" >"$TMPD/unit.out" 2>&1 || true
    if [ -s "$TMPD/unit.out" ]; then
        fail "systemd ExecStart contains a '#' token — a comment was folded into the command line: $(tail -n 1 "$TMPD/unit.out")"
    else
        pass "systemd ExecStart has no inline-comment tokens"
    fi
else
    warn "no deploy/agentwall-scorer.service found under $REPO_ROOT"
fi

if [ -z "$APACHE_CONF" ] && [ -f "$REPO_ROOT/waf/apache-agentwall.conf" ]; then
    APACHE_CONF="$REPO_ROOT/waf/apache-agentwall.conf"
    APACHE_IS_REPO_COPY=1
else
    APACHE_IS_REPO_COPY=0
fi
if [ -n "$APACHE_CONF" ]; then
    if [ ! -f "$APACHE_CONF" ]; then
        fail "--apache-conf not found: $APACHE_CONF"
    else
        label="$APACHE_CONF"
        [ "$APACHE_IS_REPO_COPY" -eq 1 ] && label="$(basename "$APACHE_CONF") (repo copy)"
        if grep -qE '^[[:space:]]*LogFormat.*xff=' "$APACHE_CONF"; then
            pass "Apache LogFormat includes the xff= field ($label)"
        else
            fail "Apache LogFormat lacks xff=\"...\" — the scorer cannot read XFF ($label)"
        fi
        if grep -qE '^[[:space:]]*CustomLog[^#]*agentwall_access\.log.*agentwall' "$APACHE_CONF"; then
            pass "Apache CustomLog writes agentwall_access.log ($label)"
        else
            fail "Apache CustomLog for agentwall_access.log is missing/commented — fail2ban + scorer have no log to read ($label)"
        fi
    fi
else
    skip "no Apache config to check (pass --apache-conf PATH)"
fi

# --- summary ----------------------------------------------------------------
echo
echo "== Summary =="
printf 'PASS=%d  WARN=%d  FAIL=%d  SKIP=%d\n' "$PASS" "$WARN" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf '%sRESULT: FAIL%s — fix the FAIL item(s) above before go-live.\n' "$C_FAIL" "$C_OFF"
    exit 1
fi
if [ "$WARN" -gt 0 ]; then
    printf '%sRESULT: PASS (with warnings)%s — review the WARN item(s) above.\n' "$C_WARN" "$C_OFF"
    exit 0
fi
printf '%sRESULT: PASS%s — no warnings.\n' "$C_PASS" "$C_OFF"
exit 0
