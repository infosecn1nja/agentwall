#!/usr/bin/env bash
# =============================================================================
# deploy/gen-secrets.sh — generate the agentwall secret files
# -----------------------------------------------------------------------------
# Produces three 0600 env files whose secrets MATCH across the stack (one Redis
# password shared by Redis, the scorer and the nginx-Lua layer):
#
#   compose.env   REDIS_PASS=<48 hex>          -> cp to deploy/.env for compose
#   agentwall-scorer.env  REDIS_URL=redis://:<pass>@.. -> /etc/agentwall-scorer.env (scorer)
#   nginx.env     AGENTWALL_REDIS_PASS / AGENTWALL_CHAL_SECRET / challenge tuning
#                                              -> nginx/OpenResty EnvironmentFile
#
# Usage:
#   ./deploy/gen-secrets.sh [options]
#   ./deploy/gen-secrets.sh --out /root/agentwall-secrets --redis-host 10.0.0.5
#
# Options:
#   --out DIR          output directory (default: ./secrets)
#   --force            overwrite existing files (ROTATION: invalidates issued
#                      challenge cookies and the old Redis password)
#   --redis-host HOST  host used in the scorer's REDIS_URL (default: 127.0.0.1)
#   --redis-port PORT  port used in the scorer's REDIS_URL (default: 6379)
#   --redis-db N       database index used in the scorer's REDIS_URL (default: 0)
#   -h, --help         this help
#
# The script never prints secrets to stdout; it prints the exact next commands
# with file paths only. Exit 0 = files written, 1 = refused/failed, 2 = usage.
# =============================================================================
set -euo pipefail
umask 077

OUT="./secrets"
FORCE=0
REDIS_HOST="127.0.0.1"
REDIS_PORT="6379"
REDIS_DB="0"

usage() {
    cat <<'EOF'
Usage: deploy/gen-secrets.sh [options]

Generate the matching secret files for the agentwall stack:
  compose.env   REDIS_PASS            (docker compose Redis requirepass)
  agentwall-scorer.env  REDIS_URL             (scorer EnvironmentFile)
  nginx.env     AGENTWALL_REDIS_PASS, AGENTWALL_CHAL_SECRET, challenge tuning
                                      (nginx/OpenResty EnvironmentFile)

Options:
  --out DIR          output directory (default: ./secrets)
  --force            overwrite existing files (rotation: invalidates issued
                     clearance cookies and the old Redis password)
  --redis-host HOST  Redis host in REDIS_URL (default: 127.0.0.1)
  --redis-port PORT  Redis port in REDIS_URL (default: 6379)
  --redis-db N       Redis db index in REDIS_URL (default: 0)
  -h, --help         show this help

Exit status: 0 = secrets written, 1 = refused/failed, 2 = usage error.
Files are created mode 0600 in a 0700 directory; nothing is printed secret.
EOF
}

die() { printf 'gen-secrets: error: %s\n' "$*" >&2; exit 1; }
usage_error() { printf 'gen-secrets: error: %s\n' "$*" >&2; exit 2; }
say() { printf '%s\n' "$*"; }

# --- argument parsing -------------------------------------------------------
need_value() { [ "$#" -ge 2 ] || usage_error "$1 needs a value (try --help)"; }

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)          usage; exit 0 ;;
        --out)              need_value "$@"; OUT="$2"; shift 2 ;;
        --out=*)            OUT="${1#*=}"; shift ;;
        --force)            FORCE=1; shift ;;
        --redis-host)       need_value "$@"; REDIS_HOST="$2"; shift 2 ;;
        --redis-host=*)     REDIS_HOST="${1#*=}"; shift ;;
        --redis-port)       need_value "$@"; REDIS_PORT="$2"; shift 2 ;;
        --redis-port=*)     REDIS_PORT="${1#*=}"; shift ;;
        --redis-db)         need_value "$@"; REDIS_DB="$2"; shift 2 ;;
        --redis-db=*)       REDIS_DB="${1#*=}"; shift ;;
        --)                 shift; break ;;
        -*)                 usage_error "unknown option: $1 (try --help)" ;;
        *)                  usage_error "unexpected argument: $1 (try --help)" ;;
    esac
done
[ "$#" -eq 0 ] || usage_error "unexpected argument: $1 (try --help)"

# --- validation -------------------------------------------------------------
[ -n "$OUT" ] || usage_error "--out must not be empty"
# Avoid a path that option parsers could mistake for a flag.
case "$OUT" in -*) OUT="./${OUT}" ;; esac
case "$OUT" in *$'\n'*|*' '*) usage_error "--out must not contain spaces or newlines: $OUT" ;; esac

[ -n "$REDIS_HOST" ] || usage_error "--redis-host must not be empty"
case "$REDIS_HOST" in
    *@*|*/*|*' '*) usage_error "--redis-host must be a hostname or IP without @, / or spaces (got: $REDIS_HOST)" ;;
esac
case "$REDIS_PORT" in
    ''|*[!0-9]*) usage_error "--redis-port must be a number (got: $REDIS_PORT)" ;;
esac
[ "$REDIS_PORT" -ge 1 ] && [ "$REDIS_PORT" -le 65535 ] \
    || usage_error "--redis-port must be within 1-65535 (got: $REDIS_PORT)"
case "$REDIS_DB" in
    ''|*[!0-9]*) usage_error "--redis-db must be a number (got: $REDIS_DB)" ;;
esac
[ "$REDIS_DB" -le 32767 ] || usage_error "--redis-db is unreasonably large (got: $REDIS_DB)"

# IPv6 literal hosts must be bracketed inside a URL: redis://[::1]:6379/0
case "$REDIS_HOST" in
    \[*\])  url_host="$REDIS_HOST" ;;
    *:*)    url_host="[${REDIS_HOST}]" ;;
    *)      url_host="$REDIS_HOST" ;;
esac

# --- secure randomness ------------------------------------------------------
# Prefer openssl (present on every distro and macOS); fall back to python3's
# secrets module; last resort is /dev/urandom via od. All are CSPRNG-backed.
rand_hex() {
    local bytes="$1" out=""
    if command -v openssl >/dev/null 2>&1; then
        out="$(openssl rand -hex "$bytes" 2>/dev/null || true)"
        if [ "${#out}" -eq "$((bytes * 2))" ]; then printf '%s\n' "$out"; return 0; fi
    fi
    if command -v python3 >/dev/null 2>&1; then
        out="$(python3 -c 'import secrets,sys; sys.stdout.write(secrets.token_hex(int(sys.argv[1])))' "$bytes" 2>/dev/null || true)"
        if [ "${#out}" -eq "$((bytes * 2))" ]; then printf '%s\n' "$out"; return 0; fi
    fi
    if [ -r /dev/urandom ] && command -v od >/dev/null 2>&1; then
        out="$(od -An -N "$bytes" -tx1 /dev/urandom | tr -d ' \n')"
        if [ "${#out}" -eq "$((bytes * 2))" ]; then printf '%s\n' "$out"; return 0; fi
    fi
    die "cannot generate secure random bytes (need openssl, python3 or /dev/urandom)"
}

# 24 random bytes = 48 hex chars for the Redis password;
# 32 random bytes = 64 hex chars for the challenge HMAC secret.
REDIS_PASS="$(rand_hex 24)"
CHAL_SECRET="$(rand_hex 32)"

# --- refuse to clobber existing secrets without --force ---------------------
TARGETS=("$OUT/compose.env" "$OUT/agentwall-scorer.env" "$OUT/nginx.env")

if [ -e "$OUT" ] && [ ! -d "$OUT" ]; then
    usage_error "--out exists and is not a directory: $OUT"
fi
if [ -d "$OUT" ]; then
    existing=()
    for f in "${TARGETS[@]}"; do
        [ -e "$f" ] && existing+=("$f")
    done
    if [ "${#existing[@]}" -gt 0 ] && [ "$FORCE" -ne 1 ]; then
        {
            printf 'gen-secrets: refusing to overwrite existing secret file(s):\n'
            printf '  %s\n' "${existing[@]}"
            printf 'Re-run with --force to rotate them. NOTE: rotation changes the\n'
            printf 'Redis password and AGENTWALL_CHAL_SECRET, so outstanding challenge\n'
            printf 'cookies become invalid and Redis/compose must be updated too.\n'
        } >&2
        exit 1
    fi
fi

# --- write files (atomic: tmp in the same dir + mv) -------------------------
created_dir=0
if [ ! -d "$OUT" ]; then
    mkdir -p "$OUT" || die "cannot create output directory: $OUT"
    created_dir=1
fi
[ -w "$OUT" ] || die "output directory is not writable: $OUT"
[ "$created_dir" -eq 1 ] && chmod 0700 "$OUT"

tmp_cleanup() {
    rm -f "$OUT"/.*.tmp.* 2>/dev/null || true
}
trap tmp_cleanup EXIT

write_secret_file() { # write_secret_file <path> <content>
    local path="$1" content="$2" tmp
    tmp="$(dirname "$path")/.$(basename "$path").tmp.$$"
    if ! printf '%s\n' "$content" > "$tmp"; then
        rm -f "$tmp" 2>/dev/null || true
        die "cannot write $tmp"
    fi
    chmod 0600 "$tmp" || { rm -f "$tmp"; die "cannot chmod 0600 $tmp"; }
    mv -f "$tmp" "$path" || { rm -f "$tmp"; die "cannot replace $path"; }
}

compose_content="REDIS_PASS=${REDIS_PASS}"
agentwall_scorer_content="REDIS_URL=redis://:${REDIS_PASS}@${url_host}:${REDIS_PORT}/${REDIS_DB}"
nginx_content="AGENTWALL_REDIS_PASS=${REDIS_PASS}
AGENTWALL_CHAL_SECRET=${CHAL_SECRET}
AGENTWALL_POW_DIFF=4
AGENTWALL_CHAL_TTL=600
AGENTWALL_CLR_TTL=600
AGENTWALL_IPV6_PREFIX=64
AGENTWALL_HEADLESS_MODE=mark
AGENTWALL_HEADLESS_TTL=3600
AGENTWALL_HEADLESS_BLOCK=0.60
AGENTWALL_HEADLESS_SUSPECT=0.35
AGENTWALL_MIN_SOLVE_MS=250"

write_secret_file "$OUT/compose.env" "$compose_content"
write_secret_file "$OUT/agentwall-scorer.env" "$agentwall_scorer_content"
write_secret_file "$OUT/nginx.env" "$nginx_content"

OUT_ABS="$(cd "$OUT" && pwd -P)"

# --- report (paths only, never secrets) -------------------------------------
say ""
say "Generated secrets in: $OUT_ABS"
printf '  %-14s %s\n' "compose.env"  "0600  Redis requirepass for docker compose (var: REDIS_PASS)"
printf '  %-14s %s\n' "agentwall-scorer.env" "0600  scorer Redis URL (var: REDIS_URL, host ${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB})"
printf '  %-14s %s\n' "nginx.env"    "0600  Lua/Redis AUTH + challenge secret + tuning (AGENTWALL_* vars)"
say ""
say "Next steps:"
say ""
say "1) Docker compose (Redis + scorer on this host):"
say "     cp \"$OUT_ABS/compose.env\" deploy/.env"
say "   deploy/.env is gitignored; deploy/docker-compose.yml consumes REDIS_PASS"
say "   and builds the scorer's REDIS_URL from it."
say ""
say "2) Scorer systemd unit (bare metal) — keep secrets OUT of the unit file:"
say "     sudo install -m 0600 -o root -g agentwall \"$OUT_ABS/agentwall-scorer.env\" /etc/agentwall-scorer.env"
say "   deploy/agentwall-scorer.service loads it via EnvironmentFile=-/etc/agentwall-scorer.env"
say "   and runs as User=agentwall, so the file must stay readable only by root:agentwall."
say ""
say "3) nginx/OpenResty (Lua challenge + Redis AUTH) — systemd EnvironmentFile:"
say "     sudo install -m 0600 -o root -g root \"$OUT_ABS/nginx.env\" /etc/agentwall-nginx.env"
say "     # drop-in for the running proxy unit (nginx.service or openresty.service):"
say "     sudo install -d -m 0755 /etc/systemd/system/nginx.service.d"
say "     printf '[Service]\\nEnvironmentFile=-/etc/agentwall-nginx.env\\n' \\"
say "       | sudo tee /etc/systemd/system/nginx.service.d/agentwall-env.conf"
say "     sudo systemctl daemon-reload && sudo systemctl restart nginx"
say ""
say "   Then forward the values to the workers from the *main* context of nginx.conf"
say "   ('env NAME;' without a value inherits it from the process environment, which"
say "   the EnvironmentFile above provides):"
for v in AGENTWALL_REDIS_PASS AGENTWALL_CHAL_SECRET AGENTWALL_POW_DIFF AGENTWALL_CHAL_TTL AGENTWALL_CLR_TTL AGENTWALL_IPV6_PREFIX \
         AGENTWALL_HEADLESS_MODE AGENTWALL_HEADLESS_TTL AGENTWALL_HEADLESS_BLOCK AGENTWALL_HEADLESS_SUSPECT AGENTWALL_MIN_SOLVE_MS; do
    say "     env $v;"
done
say ""
say "   Alternative — inline the values in nginx.conf main context (that file is"
say "   root-only, mode 0640 root:root, and never in git). This script does NOT"
say "   print the secret values; copy them out of the generated file, e.g."
say "   'sudo cat /etc/agentwall-nginx.env', and substitute them below:"
say "     env AGENTWALL_REDIS_PASS=<paste AGENTWALL_REDIS_PASS from nginx.env>;"
say "     env AGENTWALL_CHAL_SECRET=<paste AGENTWALL_CHAL_SECRET from nginx.env>;"
say "     env AGENTWALL_POW_DIFF=4; env AGENTWALL_CHAL_TTL=600; env AGENTWALL_CLR_TTL=600;"
say "     env AGENTWALL_IPV6_PREFIX=64;"
say "     env AGENTWALL_HEADLESS_MODE=mark; env AGENTWALL_MIN_SOLVE_MS=250;   # mark -> block in phase 3"
say ""
say "   AGENTWALL_REDIS_HOST / AGENTWALL_REDIS_PORT / AGENTWALL_REDIS_DB are not secrets;"
say "   set them wherever the Lua reads env (or inline in nginx.conf), e.g."
say "     env AGENTWALL_REDIS_HOST; env AGENTWALL_REDIS_PORT; env AGENTWALL_REDIS_DB;"
say ""
say "4) Verify, then load the go-live self-test (read-only):"
say "     stat -c '%a %n' \"$OUT_ABS\"/*        # expect 600 for each file"
say "     bash deploy/preflight.sh --log /var/log/nginx/agentwall_access.log --use-xff"
say ""
say "5) Rotation: re-run with --force, then update Redis/compose/scorer/nginx"
say "   together. New AGENTWALL_CHAL_SECRET invalidates issued clearance cookies;"
say "   new REDIS_PASS invalidates clients until every component is restarted."
say ""
say "Never commit these files. deploy/.env already matches .gitignore, but the"
say "default ./secrets output directory is NOT ignored: add 'secrets/' to"
say ".gitignore or use --out outside the repo (e.g. /root/agentwall-secrets)."
say "The directory is 0700 and every file is 0600."
