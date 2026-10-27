-- =============================================================================
-- agentwall_redis_block.lua — inline 403 enforcement from the ML scorer's verdicts
-- -----------------------------------------------------------------------------
-- The scorer (out-of-band) writes:   SET agentwall:block:<ip_key> 1 EX <block_ttl>
-- This checks that key in the request path and returns 403 while it exists, so
-- a ban expires on its own (TTL) with no cleanup job.
--
-- FAILURE POLICY (deliberate):
--   * infrastructure failure (Redis unreachable / timeout / I/O) -> FAIL OPEN
--     (allow the request) and log rate-limited ERR. A Redis outage must never
--     take the site down.
--   * configuration failure (NOAUTH, WRONGPASS, AUTH-without-requirepass) ->
--     FAIL OPEN but log rate-limited ngx.CRIT. This is the bug this rewrite
--     fixes: previously a commented-out AUTH() made every GET fail NOAUTH and
--     the script silently returned, so blocks never actually enforced.
--
-- nginx.conf (main context): declare every AGENTWALL_* env var used here:
--   env AGENTWALL_REDIS_HOST; env AGENTWALL_REDIS_PORT; env AGENTWALL_REDIS_PASS;
--   env AGENTWALL_REDIS_DB;   env AGENTWALL_REDIS_TIMEOUT_MS; env AGENTWALL_IPV6_PREFIX;
-- http:
--   lua_package_path "/etc/nginx/lua/?.lua;;";
--   lua_shared_dict agentwall_cache 2m;          # optional; adds 5s positive cache
-- server:
--   real_ip ...                              # FIRST: recover the true client IP
--   access_by_lua_file /etc/nginx/lua/agentwall_redis_block.lua;
--
-- This is the BLOCK-ONLY variant. For block + PoW challenge use
-- agentwall_challenge_block.lua instead (it performs the same block check onward).
-- =============================================================================

local common = require "agentwall_common"

local ip = ngx.var.remote_addr
if not ip then return end

local redis_cfg = common.load_redis_config()
-- Python and Lua must agree on the key. A malformed $remote_addr is an
-- infrastructure oddity, not a config error: fail open on the raw IP fallback.
local ip_key = common.ip_key(ip, redis_cfg.ipv6_prefix) or ip

-- Optional shared-dict cache. Tolerate the dict being absent (nginx.conf not
-- updated yet) so a missing `lua_shared_dict` cannot break enforcement.
local cache = ngx.shared and ngx.shared.agentwall_cache or nil
local CACHE_PREFIX = "rb:"          -- "redis block" namespace
local CACHE_BLOCK_TTL = 5
local CACHE_ALLOW_TTL = 2

local function log_limited(reason, level, msg)
    common.log_limited(cache, "rblog:" .. reason, 5, ngx.log, level, msg)
end

-- Redis auth/permission errors mean the operator's configuration is wrong; log
-- those at CRIT so they stand out from ordinary connectivity noise.
local function is_config_error(err)
    if type(err) ~= "string" then return false end
    if err:find("NOAUTH", 1, true) then return true end
    if err:find("WRONGPASS", 1, true) then return true end
    if err:find("invalid password", 1, true) then return true end
    if err:find("no password is set", 1, true) then return true end
    return false
end

-- Fast path: a cached positive block answers without touching Redis.
if cache then
    local hit = cache:get(CACHE_PREFIX .. ip_key)
    if hit == 1 then
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

local redis = require "resty.redis"
local red = redis:new()
red:set_timeout(redis_cfg.timeout_ms)

local ok, err = red:connect(redis_cfg.host, redis_cfg.port)
if not ok then
    log_limited("connect", ngx.ERR,
        "agentwall: redis connect failed host=" .. tostring(redis_cfg.host) ..
        " port=" .. tostring(redis_cfg.port) .. " err=" .. tostring(err) ..
        " (failing open)")
    return
end

if redis_cfg.pass and redis_cfg.pass ~= "" then
    local aok, aerr = red:auth(redis_cfg.pass)
    if not aok then
        red:close()
        log_limited("auth", ngx.CRIT,
            "agentwall: redis AUTH failed (check AGENTWALL_REDIS_PASS / requirepass): " ..
            tostring(aerr) .. " (failing open)")
        return
    end
end
-- If AGENTWALL_REDIS_PASS is unset but the server requires a password, the GET
-- below returns NOAUTH and is logged at CRIT there (the fail-open bug being
-- fixed was silence, not the fail-open itself).

if redis_cfg.db and redis_cfg.db ~= 0 then
    local sok, serr = red:select(redis_cfg.db)
    if not sok then
        red:close()
        log_limited("select", ngx.CRIT,
            "agentwall: redis SELECT " .. tostring(redis_cfg.db) .. " failed: " ..
            tostring(serr) .. " (failing open)")
        return
    end
end

local blocked, gerr = red:get(common.KEY_BLOCK .. ip_key)
if not blocked then
    red:close()
    local where = common.KEY_BLOCK .. ip_key
    if is_config_error(gerr) then
        log_limited("get-noauth", ngx.CRIT,
            "agentwall: redis GET " .. where .. " failed with a CONFIGURATION error: " ..
            tostring(gerr) .. " (set AGENTWALL_REDIS_PASS and declare `env AGENTWALL_REDIS_PASS;`; failing open)")
    else
        log_limited("get", ngx.ERR,
            "agentwall: redis GET " .. where .. " failed: " .. tostring(gerr) .. " (failing open)")
    end
    return
end

-- Return the connection to the pool (keepalive) on every success path.
red:set_keepalive(10000, 100)

if blocked ~= ngx.null then
    if cache then cache:set(CACHE_PREFIX .. ip_key, 1, CACHE_BLOCK_TTL) end
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

if cache then cache:set(CACHE_PREFIX .. ip_key, 0, CACHE_ALLOW_TTL) end
return
