-- =============================================================================
-- agentwall_behavior_log.lua — edge behavioural prevention (log phase + timer)
-- -----------------------------------------------------------------------------
-- The Python scorer is the rich behavioural brain, but it is OUT-OF-BAND and
-- only acts after --warmup events. This module gives the EDGE itself a cheap,
-- immediate, model-free behavioural signal so an autonomous agent's *pattern*
-- (not its User-Agent) is acted on within one short window:
--
--   * a probe/injection payload on the URI or query               -> block
--   * an out-of-band interaction callback host (interactsh/oast/   -> block
--     collaborator/dnslog/ceye/...) anywhere in URI/query/Referer
--   * an enumeration burst (many 4xx in the window)               -> challenge
--   * a credential-stuffing burst (many 4xx on auth endpoints)    -> challenge
--   * a scripted client with a browser UA but no Fetch-Metadata/  -> counts as
--     Accept-Language (header inconsistency)                         one error
--
-- It is wired with `log_by_lua_file`, so it never adds latency to the response.
-- The LOG phase itself cannot open sockets (OpenResty disables the cosocket API
-- there), so the request facts are classified in the log phase and the Redis
-- work is handed to a detached `ngx.timer.at(0, ...)` which has full socket
-- access. The timer writes only the SAME verdict keys the scorer writes
-- (agentwall:block / agentwall:challenge), which the access-phase script
-- enforces on the NEXT request from the key; TTLs expire on their own.
--
-- SHIPPED IN SHADOW: AGENTWALL_BEHAVIOR_MODE=mark (default) tallies and logs the
-- would-be verdict but writes no verdict key. Set it to `challenge` to enforce,
-- or `off` to disable the module entirely. Review the WARN lines first; behind
-- CGNAT the thresholds need tuning.
--
-- nginx.conf:
--   http { lua_shared_dict agentwall_cache 10m; ... }
--   server/location: log_by_lua_file /etc/nginx/lua/agentwall_behavior_log.lua;
--   Declare env AGENTWALL_BEHAVIOR_MODE; (and the other AGENTWALL_* vars).
--
-- State model: fixed-window counters in Redis, keyed
--   agentwall:bw:<signal>:<window_bucket>:<ip_key>   INCR, EX window*2
-- so memory is bounded and no cleanup job is needed. A missing shared dict or
-- Redis is tolerated (fail open, no action).
-- =============================================================================

local common = require "agentwall_common"

local bcfg = common.load_behavior_config()
if bcfg.mode == common.BEHAVIOR_MODE_OFF then return end

local ip = ngx.var.remote_addr
if not ip then return end

local redis_cfg = common.load_redis_config()
local ip_key = common.ip_key(ip, redis_cfg.ipv6_prefix) or ip

-- --- classify THIS request/response (pure string work; no sockets here) ----
local status = tonumber(ngx.var.status) or 0
local uri = ngx.var.uri or ""
local qs = ngx.var.query_string or ""
local referer = ngx.var.http_referer or ""
local haystack = uri .. "|" .. qs .. "|" .. referer

local function urldecode(s)
    return (s:gsub("%%(%x%x)", function(h) return string.char(tonumber(h, 16)) end))
end
local is_probe = common.is_probe_payload(uri) or common.is_probe_payload(qs)
    or common.is_probe_payload(urldecode(uri)) or common.is_probe_payload(urldecode(qs))
local is_oob = common.is_oob_callback(haystack, bcfg.oob_extra)
-- 4xx that is a real client/enumeration error. 429 is AgentWall's own rate
-- limiter / challenge status, never counted (it would feed on itself). 404 on a
-- static asset is page noise, not enumeration.
local is_error = (status >= 400 and status < 500 and status ~= 429
    and not common.is_static_path(uri))
local is_auth_fail = common.is_auth_path(uri) and (status == 401 or status == 403)

-- Header consistency: a request claiming a modern browser over HTTPS but
-- missing Fetch-Metadata / Accept-Language is a scripted-client tell. Counted
-- toward the error bucket only (never an immediate block): a soft signal.
local hdr_score = common.browser_header_inconsistency({
    user_agent      = ngx.var.http_user_agent,
    sec_fetch_mode  = ngx.var.http_sec_fetch_mode,
    sec_fetch_site  = ngx.var.http_sec_fetch_site,
    sec_fetch_dest  = ngx.var.http_sec_fetch_dest,
    accept_language = ngx.var.http_accept_language,
    accept          = ngx.var.http_accept,
    sec_ch_ua       = ngx.var.http_sec_ch_ua,
    scheme          = ngx.var.scheme,
})
local hdr_suspect = hdr_score >= bcfg.header_suspect

-- Nothing of interest: don't schedule a timer at all.
if not (is_probe or is_oob or is_error or is_auth_fail or hdr_suspect) then
    return
end

-- --- deferred worker: runs OUTSIDE the log phase, cosockets allowed ---------
local function worker(premature, data)
    if premature then return end
    local cache = ngx.shared and ngx.shared.agentwall_cache or nil
    local function log_limited(reason, level, msg)
        common.log_limited(cache, "bwlog:" .. reason .. ":" .. data.ip_key, 5,
                           ngx.log, level, msg)
    end

    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(data.redis_cfg.timeout_ms)
    local ok = red:connect(data.redis_cfg.host, data.redis_cfg.port)
    if not ok then return end                 -- fail open, silently
    if data.redis_cfg.pass and data.redis_cfg.pass ~= "" then
        if not red:auth(data.redis_cfg.pass) then red:close(); return end
    end
    if data.redis_cfg.db and data.redis_cfg.db ~= 0 then
        if not red:select(data.redis_cfg.db) then red:close(); return end
    end

    local bucket = math.floor(ngx.time() / data.bcfg.window)
    local ttl = data.bcfg.window * 2
    local function bump(signal)
        local key = "agentwall:bw:" .. signal .. ":" .. bucket .. ":" .. data.ip_key
        local n = red:incr(key)
        if not n then return 0 end
        if n == 1 then red:expire(key, ttl) end
        return n
    end

    local counts = { probe = 0, oob = 0, errors = 0, auth_fail = 0 }
    if data.is_oob then counts.oob = bump("oob") end
    if data.is_probe then counts.probe = bump("probe") end
    if data.is_auth_fail then counts.auth_fail = bump("authfail") end
    if data.is_error or data.hdr_suspect then counts.errors = bump("err") end

    local action, reason = common.behavior_decision(counts, data.bcfg)
    if not action then red:set_keepalive(10000, 100); return end

    if data.bcfg.mode == common.BEHAVIOR_MODE_MARK then
        red:set_keepalive(10000, 100)
        log_limited("mark-" .. reason, ngx.WARN,
            "agentwall: behaviour " .. action .. " WOULD fire ip_key=" .. data.ip_key ..
            " reason=" .. reason .. " probe=" .. counts.probe .. " oob=" .. counts.oob ..
            " err=" .. counts.errors .. " authfail=" .. counts.auth_fail ..
            " (mode=mark, no verdict written)")
        return
    end

    if action == "block" then
        red:set("agentwall:block:" .. data.ip_key, "1", "EX", data.bcfg.block_ttl)
        red:del("agentwall:challenge:" .. data.ip_key)
        if cache then cache:delete("cc:" .. data.ip_key) end
        log_limited("block-" .. reason, ngx.WARN,
            "agentwall: behaviour BLOCK ip_key=" .. data.ip_key .. " reason=" .. reason ..
            " probe=" .. counts.probe .. " oob=" .. counts.oob)
    else
        red:set("agentwall:challenge:" .. data.ip_key, "1", "EX", data.bcfg.challenge_ttl)
        if cache then cache:delete("cc:" .. data.ip_key) end
        log_limited("challenge-" .. reason, ngx.WARN,
            "agentwall: behaviour CHALLENGE ip_key=" .. data.ip_key .. " reason=" .. reason ..
            " err=" .. counts.errors .. " authfail=" .. counts.auth_fail)
    end
    red:set_keepalive(10000, 100)
end

local ok, err = ngx.timer.at(0, worker, {
    ip_key = ip_key, redis_cfg = redis_cfg, bcfg = bcfg,
    is_probe = is_probe, is_oob = is_oob, is_error = is_error,
    is_auth_fail = is_auth_fail, hdr_suspect = hdr_suspect,
})
if not ok then
    common.log_limited(ngx.shared and ngx.shared.agentwall_cache or nil,
        "bwtimer", 5, ngx.log, ngx.ERR,
        "agentwall: behaviour timer failed to start: " .. tostring(err) .. " (skipping)")
end
