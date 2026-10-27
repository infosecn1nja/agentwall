-- =============================================================================
-- agentwall_common.lua — shared, dependency-free helpers for the AGENTWALL nginx layer
-- -----------------------------------------------------------------------------
-- This module is deliberately PURE Lua: it never touches `ngx` at load time and
-- never requires a C library, so it can be unit-tested with stock `lua`
-- (see tests/lua/test_agentwall_common.lua). Everything that needs the request
-- context (ngx.hmac_sha1, ngx.sha1_bin, ngx.now, ...) is injected as a function
-- argument by the caller.
--
-- Must run on OpenResty / LuaJIT (Lua 5.1): no `//`, `&`, `|`, `<<`, `goto`,
-- integer division, or other Lua 5.2+/5.3+ syntax.
--
-- Redis key contract (all keyed by the normalized `ip_key`, see M.ip_key):
--   agentwall:block:<ip_key>      "1"  TTL block_ttl      (written by the scorer)
--   agentwall:challenge:<ip_key>  "1"  TTL challenge_ttl  (written by the scorer)
--   agentwall:cleared:<ip_key>    "1"  TTL cleared_ttl    (written by Lua after PoW)
--   agentwall:chal:<id>           "<ip_key>|<issued_ms>" TTL 180s
--                             (written by Lua, single use)
--   agentwall:headless:<ip_key>   "1"  TTL headless_ttl   (written by Lua on detection)
--
-- The Python scorer MUST normalize keys with an identical algorithm. The
-- reference implementation is documented in nginx-lua/README.md.
-- =============================================================================

local M = {}

-- --- Constants --------------------------------------------------------------
M.COOKIE_NAME    = "agentwall_clr"
M.COOKIE_VERSION = "v1"

M.KEY_BLOCK      = "agentwall:block:"
M.KEY_CHALLENGE  = "agentwall:challenge:"
M.KEY_CLEARED    = "agentwall:cleared:"
M.KEY_CHAL       = "agentwall:chal:"
M.KEY_HEADLESS   = "agentwall:headless:"

M.CHAL_ID_TTL    = 180     -- seconds; single-use proof-of-work challenge id
M.CHAL_ID_MAX    = 64      -- defensive bound on the id string we hash/lookup

M.HEADLESS_MODE_MARK  = "mark"
M.HEADLESS_MODE_BLOCK = "block"

M.DEFAULT_IPV6_PREFIX      = 64
M.DEFAULT_POW_DIFF         = 4
M.POW_DIFF_MIN             = 3
M.POW_DIFF_MAX             = 6
M.DEFAULT_CHAL_TTL         = 600
M.DEFAULT_CLR_TTL          = 600
M.DEFAULT_HEADLESS_MODE    = "mark"
M.DEFAULT_HEADLESS_TTL     = 3600
M.HEADLESS_TTL_MIN         = 60
M.HEADLESS_TTL_MAX         = 86400 * 7
M.DEFAULT_HEADLESS_BLOCK   = 0.60
M.DEFAULT_HEADLESS_SUSPECT = 0.35
M.DEFAULT_MIN_SOLVE_MS     = 250
M.DEFAULT_REDIS_HOST       = "127.0.0.1"
M.DEFAULT_REDIS_PORT       = 6379
M.DEFAULT_REDIS_DB         = 0
M.DEFAULT_REDIS_TIMEOUT_MS = 100

-- =============================================================================
-- IPv4 / IPv6 parsing and canonicalization
-- =============================================================================
-- Goal: produce the SAME string Python's stdlib produces for
--   str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False).network_address)
-- for IPv6, and str(ipaddress.ip_address(addr)) for IPv4, with one extra rule
-- from the contract: IPv4-mapped IPv6 (::ffff:a.b.c.d) is treated as IPv4.
--
-- No bit libraries: mask/count with plain arithmetic on 16-bit groups.

local function parse_ipv4(s)
    local a, b, c, d = s:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    local parts = { a, b, c, d }
    local out = {}
    for i = 1, 4 do
        local p = parts[i]
        -- Python's ipaddress rejects leading zeros ("010.0.0.1" is invalid),
        -- so reject them here too: the scorer would never emit such a key.
        if #p > 1 and p:sub(1, 1) == "0" then return nil end
        local n = tonumber(p)
        if not n or n > 255 then return nil end
        out[i] = n
    end
    return out
end

local function split_colon(s)
    local out = {}
    if s == "" then return out end
    for part in (s .. ":"):gmatch("(.-):") do
        out[#out + 1] = part
    end
    return out
end

local function parse_hex_group(g)
    if #g < 1 or #g > 4 then return nil end
    if not g:match("^%x+$") then return nil end
    return tonumber(g, 16)
end

-- Returns 8 groups (each 0..65535) or nil.
local function parse_ipv6(input)
    local s = input:lower()

    -- Embedded dotted-quad tail ("::ffff:1.2.3.4", "2001:db8::1.2.3.4").
    local head, tail = s:match("^(.*):(%d+%.%d+%.%d+%.%d+)$")
    if head then
        local o = parse_ipv4(tail)
        if not o then return nil end
        -- head may legitimately end with ":" (e.g. "::1.2.3.4" -> head ":").
        local hi = o[1] * 256 + o[2]
        local lo = o[3] * 256 + o[4]
        s = head .. string.format(":%x:%x", hi, lo)
    end

    local groups = {}
    local dc = s:find("::", 1, true)
    if dc then
        -- Only one "::" is legal.
        if s:find("::", dc + 1, true) then return nil end
        local left = split_colon(s:sub(1, dc - 1))
        local right = split_colon(s:sub(dc + 2))
        local count = #left + #right
        -- "::" must stand for at least one zero group.
        if count > 7 then return nil end
        for i = 1, #left do
            local g = parse_hex_group(left[i])
            if not g then return nil end
            groups[#groups + 1] = g
        end
        for _ = 1, 8 - count do
            groups[#groups + 1] = 0
        end
        for i = 1, #right do
            local g = parse_hex_group(right[i])
            if not g then return nil end
            groups[#groups + 1] = g
        end
    else
        local parts = split_colon(s)
        if #parts ~= 8 then return nil end
        for i = 1, #parts do
            local g = parse_hex_group(parts[i])
            if not g then return nil end
            groups[#groups + 1] = g
        end
    end

    if #groups ~= 8 then return nil end
    return groups
end

-- IPv4-mapped IPv6 is ::ffff:xxxx:xxxx (top 96 bits == 0xffff). Matches the
-- semantics of Python's IPv6Address.ipv4_mapped, regardless of prefix.
local function mapped_ipv4(groups)
    for i = 1, 5 do
        if groups[i] ~= 0 then return nil end
    end
    if groups[6] ~= 0xffff then return nil end
    local hi = groups[7] * 65536 + groups[8]
    return string.format(
        "%d.%d.%d.%d",
        math.floor(hi / 16777216),
        math.floor(hi / 65536) % 256,
        math.floor(hi / 256) % 256,
        hi % 256
    )
end

local function normalize_prefix(p)
    p = tonumber(p)
    if not p then return M.DEFAULT_IPV6_PREFIX end
    p = math.floor(p)
    if p < 0 or p > 128 then return M.DEFAULT_IPV6_PREFIX end
    return p
end

-- Mask the address down to its network address for an arbitrary prefix
-- (works for /0../128, including non-nibble prefixes like /65).
local function mask_groups(groups, prefix)
    local full = math.floor(prefix / 16)
    local rem = prefix - full * 16
    for i = 1, 8 do
        if i <= full then
            -- keep the whole group
        elseif i == full + 1 and rem > 0 then
            local step = 2 ^ (16 - rem)
            groups[i] = math.floor(groups[i] / step) * step
        else
            groups[i] = 0
        end
    end
end

-- Canonical RFC 5952-ish text, matching Python's ipaddress: longest run of
-- zero groups (length >= 2, leftmost on ties) becomes "::".
local function format_groups(groups)
    local best_start, best_len = 0, 0
    local i = 1
    while i <= 8 do
        if groups[i] == 0 then
            local j = i
            while j < 8 and groups[j + 1] == 0 do
                j = j + 1
            end
            local len = j - i + 1
            if len > best_len then
                best_start, best_len = i, len
            end
            i = j + 1
        else
            i = i + 1
        end
    end

    local function hexes(a, b)
        local t = {}
        for k = a, b do
            t[#t + 1] = string.format("%x", groups[k])
        end
        return table.concat(t, ":")
    end

    if best_len >= 2 then
        local left = ""
        if best_start > 1 then left = hexes(1, best_start - 1) end
        local right = ""
        if best_start + best_len <= 8 then
            right = hexes(best_start + best_len, 8)
        end
        return left .. "::" .. right
    end
    return hexes(1, 8)
end

-- =============================================================================
-- Redis key normalization: the single source of truth for ip_key
-- =============================================================================
-- IPv4            -> dotted quad                         ("1.2.3.4")
-- IPv4-mapped v6  -> dotted quad                         ("::ffff:1.2.3.4" -> "1.2.3.4")
-- IPv6            -> canonical network address text for /prefix
--                    ("2001:0DB8:0:0:1:0:0:1", 64) -> "2001:db8::"
-- Invalid input   -> nil (callers fail open and use the raw IP as fallback key)
function M.ip_key(ip, ipv6_prefix)
    if type(ip) ~= "string" then return nil end
    if ip == "" then return nil end
    -- nginx never puts whitespace/zone-id in $remote_addr; be strict so we do
    -- not silently build a key the scorer would never write.
    if ip:find("%s") or ip:find("%%") then return nil end

    if not ip:find(":", 1, true) then
        local o = parse_ipv4(ip)
        if not o then return nil end
        return string.format("%d.%d.%d.%d", o[1], o[2], o[3], o[4])
    end

    local groups = parse_ipv6(ip)
    if not groups then return nil end

    local mapped = mapped_ipv4(groups)
    if mapped then
        return mapped
    end

    mask_groups(groups, normalize_prefix(ipv6_prefix))
    return format_groups(groups)
end

-- =============================================================================
-- Hex helpers (no bit library required)
-- =============================================================================
function M.hex(bin)
    if type(bin) ~= "string" then return nil end
    local out = {}
    for i = 1, #bin do
        out[#out + 1] = string.format("%02x", bin:byte(i))
    end
    return table.concat(out)
end

function M.unhex(h)
    if type(h) ~= "string" then return nil, "not a string" end
    if #h % 2 ~= 0 then return nil, "odd length" end
    if h ~= "" and h:find("[^0-9a-fA-F]") then return nil, "invalid hex" end
    local out = {}
    for i = 1, #h, 2 do
        out[#out + 1] = string.char(tonumber(h:sub(i, i + 1), 16))
    end
    return table.concat(out)
end

-- =============================================================================
-- HMAC / clearance-cookie helpers
-- =============================================================================
-- hmac_fn(secret, data) must return the raw binary digest (ngx.hmac_sha1 in
-- production; a deterministic stub in tests). Returns lowercase hex or nil,err.
function M.hmac_hex(secret, data, hmac_fn)
    if type(secret) ~= "string" or secret == "" then return nil, "missing secret" end
    if type(data) ~= "string" then return nil, "bad data" end
    if type(hmac_fn) ~= "function" then return nil, "hmac function unavailable" end
    local sig, err = hmac_fn(secret, data)
    if not sig then return nil, err or "hmac failed" end
    return M.hex(sig)
end

-- Cookie value: v1:<exp_epoch>:<hex(hmac_sha1(secret, ip_key .. "|" .. exp_epoch))>
function M.cookie_sign(secret, ip_key, expires, hmac_fn)
    if type(ip_key) ~= "string" or ip_key == "" then return nil, "bad ip key" end
    local exp = tonumber(expires)
    if not exp then return nil, "bad expiry" end
    exp = math.floor(exp)
    local sig, err = M.hmac_hex(secret, ip_key .. "|" .. string.format("%d", exp), hmac_fn)
    if not sig then return nil, err end
    return M.COOKIE_VERSION .. ":" .. string.format("%d", exp) .. ":" .. sig
end

-- Returns ok(boolean), reason(string|nil). Signature compare is constant-ish
-- time (fixed work proportional to the signature length, no early exit).
function M.cookie_verify(secret, ip_key, value, now, ttl, hmac_fn)
    if type(secret) ~= "string" or secret == "" then return false, "missing secret" end
    if type(ip_key) ~= "string" or ip_key == "" then return false, "bad ip key" end
    if type(value) ~= "string" or value == "" then return false, "missing cookie" end
    if #value > 256 then return false, "cookie too long" end

    local exp_s, sig = value:match("^v1:(%d+):([0-9a-fA-F]+)$")
    if not exp_s then return false, "malformed cookie" end
    if #sig % 2 ~= 0 then return false, "malformed signature" end

    local exp = tonumber(exp_s)
    if not exp then return false, "bad expiry" end
    -- Reject non-canonical expiry text ("0170..."): signatures are computed
    -- over the canonical integer, so otherwise a re-encoded cookie would replay.
    if string.format("%d", exp) ~= exp_s then return false, "non-canonical expiry" end

    local now_n = tonumber(now)
    if not now_n then return false, "bad clock" end
    now_n = math.floor(now_n)
    local ttl_n = tonumber(ttl)
    if not ttl_n or ttl_n <= 0 then return false, "bad ttl" end
    ttl_n = math.floor(ttl_n)

    if exp <= now_n then return false, "expired" end
    if exp > now_n + ttl_n then return false, "expiry too far in future" end

    local expected, err = M.hmac_hex(secret, ip_key .. "|" .. string.format("%d", exp), hmac_fn)
    if not expected then return false, err or "sign failed" end

    local provided = sig:lower()
    if #expected ~= #provided then return false, "bad signature" end

    local diff = 0
    for i = 1, #expected do
        diff = diff + math.abs(expected:byte(i) - provided:byte(i))
    end
    if diff ~= 0 then return false, "bad signature" end
    return true
end

-- =============================================================================
-- Proof of work
-- =============================================================================
-- The browser computes SHA-1(id .. ":" .. nonce) and looks for `diff` leading
-- zero HEX characters. The server does exactly ONE SHA-1 of the submitted
-- nonce: no brute force server-side, no bit library needed.
-- nonce must be pure decimal digits, 1..10 characters. Returns boolean, reason.
function M.pow_ok(id, nonce, diff, sha1_fn)
    if type(id) ~= "string" or id == "" or #id > M.CHAL_ID_MAX then
        return false, "bad challenge id"
    end
    if type(nonce) ~= "string" then return false, "bad nonce" end
    if #nonce < 1 or #nonce > 10 then return false, "bad nonce length" end
    if not nonce:match("^%d+$") then return false, "nonce is not decimal" end
    if type(sha1_fn) ~= "function" then return false, "sha1 function unavailable" end

    local d = tonumber(diff)
    if not d then return false, "bad difficulty" end
    d = math.floor(d)
    if d < 0 then return false, "bad difficulty" end

    local digest, err = sha1_fn(id .. ":" .. nonce)
    if not digest then return false, err or "sha1 failed" end

    local hexed = M.hex(digest)
    if not hexed then return false, "sha1 returned no digest" end
    if d > #hexed then return false, "difficulty exceeds digest length" end
    for i = 1, d do
        if hexed:byte(i) ~= 48 then  -- '0'
            return false, "insufficient leading zeros"
        end
    end
    return true
end

-- =============================================================================
-- Challenge-id value parsing (v3): "<ip_key>|<issued_ms>"
-- =============================================================================
-- Split ONCE on the first '|' (an IP key never contains '|'). Returns
-- ip_key, issued_ms or nil, reason.
function M.parse_chal_value(value)
    if type(value) ~= "string" or value == "" then return nil, "empty" end
    local pos = value:find("|", 1, true)
    if not pos then return nil, "missing issued_ms" end
    local key = value:sub(1, pos - 1)
    local ms_s = value:sub(pos + 1)
    if key == "" then return nil, "empty ip_key" end
    if ms_s == "" or not ms_s:match("^%d+$") then return nil, "bad issued_ms" end
    local ms = tonumber(ms_s)
    if not ms then return nil, "bad issued_ms" end
    return key, ms
end

-- =============================================================================
-- URI helper: same URI with agentwall_id/agentwall_pow removed
-- =============================================================================
-- Used by the verify endpoint to compute {"next": ...}. Kept pure (no ngx) so
-- it is unit-testable. Preserves the encoding of all other query parameters.
-- Server-side validation for a same-origin redirect target. Reject absolute
-- URLs, protocol-relative ("//evil"), backslash tricks ("/\\evil") and control
-- characters. The client guard is not authoritative: `next` may later be used
-- in a Location header.
function M.safe_relative_path(uri)
    if type(uri) ~= "string" or uri == "" then return "/" end
    local path = uri:match("^([^?]*)") or ""
    if path == "" or path:sub(1, 1) ~= "/" then return "/" end
    if path:sub(1, 2) == "//" then return "/" end
    if path:find("\\", 1, true) then return "/" end
    for i = 1, #path do
        local b = path:byte(i)
        if b == 0 or b < 32 or b == 127 then return "/" end
    end
    return uri
end


function M.strip_pow_args(uri)
    if type(uri) ~= "string" or uri == "" then return "/" end
    uri = uri:gsub("#.*$", "")                 -- drop fragment
    local path, rest = uri:match("^([^?]*)(.*)$")
    if path == nil or path == "" then path = "/" end
    if rest == nil or #rest < 2 then return M.safe_relative_path(path) end
    local query = rest:sub(2)
    local kept = {}
    for part in query:gmatch("[^&]+") do
        local raw_key = part:match("^([^=]*)") or ""
        -- decode just enough to compare keys (%61rt... cannot disguise these)
        local key = raw_key:gsub("%%(%x%x)", function(h)
            return string.char(tonumber(h, 16))
        end)
        if key ~= "agentwall_id" and key ~= "agentwall_pow" then
            kept[#kept + 1] = part
        end
    end
    if #kept == 0 then return M.safe_relative_path(path) end
    return M.safe_relative_path(path .. "?" .. table.concat(kept, "&"))
end

-- =============================================================================
-- Headless / automation detection (pure; applied server-side per request)
-- =============================================================================
-- Honest limits: these are cheap heuristics. Default Playwright/Puppeteer are
-- caught; playwright-extra/puppeteer-extra-plugin-stealth, patched Chromium and
-- a real browser driven by a human are not reliably distinguishable.
local AUTOMATION_UA_MARKERS = {
    -- generic headless/browser-automation markers
    "headlesschrome",
    "electron/",
    "phantomjs",
    "slimerjs",
    "playwright",
    "puppeteer",
    "selenium",
    "webdriver",
    "htmlunit",
    "jsdom",
    "cypress",
    -- scanner / agent toolchain fingerprints (defaults; operators can rotate
    -- UAs, which is why behaviour scoring remains the primary layer)
    "artex-enrich",
    "artex-selfupdate",
    "norma/",
    "nuclei",
    "sqlmap",
    "ffuf",
    "fuzz faster u fool",
    "nmap scripting engine",
    "dirsearch",
    "wafw00f",
    "arjun/",
    "katana/",
    "subfinder",
    "naabu",
    "gospider",
    "interactsh",
    "nikto",
    "gobuster",
    "feroxbuster",
    "wpscan",
    "masscan",
    "zgrab",
}

function M.is_automation_ua(ua)
    if type(ua) ~= "string" or ua == "" then return false end
    local lower = ua:lower()
    -- ProjectDiscovery's httpx sends "httpx/<version>"; the widely-used Python
    -- library sends "python-httpx/<version>" and must not be blocked as a tool.
    if lower:match("^httpx/") then return true end
    for i = 1, #AUTOMATION_UA_MARKERS do
        if lower:find(AUTOMATION_UA_MARKERS[i], 1, true) then
            return true
        end
    end
    return false
end

local SOFTWARE_GL_MARKERS = {
    "swiftshader",
    "llvmpipe",
    "mesa",
    "angle",
    "microsoft basic render",
    "swangle",
}

local EXPECTED_REPORT_KEYS = {
    "webdriver", "ua", "languages", "plugins", "mimeTypes", "chrome",
    "webglVendor", "webglRenderer", "hardwareConcurrency", "deviceMemory",
    "screenW", "screenH", "outerW", "outerH",
}

local function report_num(report, key)
    local v = report[key]
    if type(v) == "number" then return v end
    return nil
end

local function report_bool(report, key)
    return report[key] == true
end

local function report_str(report, key)
    local v = report[key]
    if type(v) == "string" then return v end
    return nil
end

local function looks_like_software_gl(vendor, renderer)
    local combined = ""
    if type(vendor) == "string" then combined = vendor:lower() end
    if type(renderer) == "string" then combined = combined .. " " .. renderer:lower() end
    for i = 1, #SOFTWARE_GL_MARKERS do
        if combined:find(SOFTWARE_GL_MARKERS[i], 1, true) then
            return true
        end
    end
    return false
end

-- headless_score(report, opts) -> number in [0,1]
--   opts = { min_solve_ms = <number, default 250>, solve_ms = <number|nil> }
-- Weights are deliberately simple/auditable and tuned so that:
--   * a normal desktop Chrome report scores 0;
--   * default Playwright/Puppeteer headless scores well over the default 0.60
--     block threshold;
--   * any single weak signal (e.g. software WebGL alone) stays below 0.35.
function M.headless_score(report, opts)
    opts = opts or {}
    local min_solve_ms = tonumber(opts.min_solve_ms)
    if not min_solve_ms then min_solve_ms = M.DEFAULT_MIN_SOLVE_MS end
    local solve_ms = tonumber(opts.solve_ms)

    local score = 0
    local r
    if type(report) ~= "table" then
        -- Not a report at all: strong malformed/noise signal, then evaluate the
        -- missing surfaces like an empty report.
        score = score + 0.40
        r = {}
    else
        r = report
    end

    -- Report completeness: fewer than 5 of the expected surfaces is not a
    -- genuine browser report (attacker sent junk/partial JSON).
    local present = 0
    for i = 1, #EXPECTED_REPORT_KEYS do
        if r[EXPECTED_REPORT_KEYS[i]] ~= nil then present = present + 1 end
    end
    if type(report) == "table" and present < 5 then
        score = score + 0.40
    end

    local ua = report_str(r, "ua") or ""
    local ua_lower = ua:lower()
    local is_chrome_ua = ua_lower:find("chrome/", 1, true) ~= nil
    local is_firefox_ua = ua_lower:find("firefox/", 1, true) ~= nil
    local is_headless_ua = ua_lower:find("headlesschrome", 1, true) ~= nil

    -- Direct automation markers.
    if report_bool(r, "webdriver") then score = score + 0.50 end
    if report_bool(r, "cdp") then score = score + 0.50 end

    -- Client-reported UA (the verify endpoint overwrites this with the
    -- authoritative server-side $http_user_agent before scoring).
    if is_headless_ua then
        score = score + 0.60
    elseif M.is_automation_ua(ua) then
        score = score + 0.40
    end

    -- Browser surface consistency.
    local plugins = report_num(r, "plugins") or 0
    local mime_types = report_num(r, "mimeTypes") or 0
    if plugins == 0 and mime_types == 0 and (is_chrome_ua or is_firefox_ua) then
        score = score + 0.20
    end
    if report_bool(r, "chrome") == false and is_chrome_ua then
        score = score + 0.25
    end
    local software_gl = looks_like_software_gl(
        report_str(r, "webglVendor"), report_str(r, "webglRenderer"))
    if software_gl then
        score = score + 0.20
    end
    -- Correlated headless surfaces: empty plugin/MIME surface + software
    -- rasterizer is the default-headless-Chromium shape (Playwright/Puppeteer,
    -- and Strix's agent-browser inside a container). Either signal alone is
    -- weak; together they are a strong automation signal.
    if plugins == 0 and mime_types == 0 and software_gl then
        score = score + 0.25
    end
    -- Disabled/absent PDF viewer combined with an empty plugin surface is
    -- another headless build tell.
    if r["pdfViewer"] == false and plugins == 0 then
        score = score + 0.15
    end

    local languages = r["languages"]
    if type(languages) ~= "table" or #languages == 0 then
        score = score + 0.15
    end

    local outer_w = report_num(r, "outerW")
    local outer_h = report_num(r, "outerH")
    local screen_w = report_num(r, "screenW")
    if (outer_w ~= nil and outer_w == 0)
        or (outer_h ~= nil and outer_h == 0)
        or (outer_w ~= nil and screen_w ~= nil and screen_w > 0 and outer_w > screen_w) then
        score = score + 0.20
    end
    if screen_w ~= nil and screen_w == 0 then
        score = score + 0.15
    end

    local hw = report_num(r, "hardwareConcurrency")
    if hw == nil or hw <= 1 then
        score = score + 0.05
    end

    -- Impossible timing: a human cannot read/execute the interstitial in less
    -- than AGENTWALL_MIN_SOLVE_MS. One signal only (not sufficient on its own).
    if solve_ms == nil or solve_ms < min_solve_ms then
        score = score + 0.30
    end

    -- Client Hints consistency (server-side): a real Chromium reports a
    -- Sec-CH-UA brand version matching its UA. Automation that overrides only
    -- the UA string (a common stealth shortcut) is inconsistent; on HTTPS a
    -- Chrome UA without Client Hints is also suspicious.
    local ua_major = ua:match("Chrome/(%d+)")
    if ua_major then
        local sec = opts.sec_ch_ua
        local sec_major
        if type(sec) == "string" then
            sec_major = sec:match('v="(%d+)') or sec:match("v=(%d+)")
        end
        if sec_major and sec_major ~= ua_major then
            score = score + 0.25
        elseif not sec_major and opts.scheme == "https" then
            score = score + 0.15
        end
    end

    if score < 0 then return 0 end
    if score > 1 then return 1 end
    return score
end


-- =============================================================================
-- Configuration helpers (env vars are read in the nginx scripts, not here)
-- =============================================================================
-- NOTE: the nginx.conf MAIN context MUST declare each var with `env NAME;`
-- (or `env NAME=value;`), otherwise nginx strips it from the worker
-- environment and os.getenv() returns nil. See nginx-lua/README.md.

function M.env_str(name, default)
    local getenv = os and os.getenv
    if type(getenv) ~= "function" then return default end
    local v = getenv(name)
    if v == nil then return default end
    v = v:match("^%s*(.-)%s*$")
    if v == "" then return default end
    return v
end

-- Integer env var. When clamp is true, out-of-range values are clamped to
-- [min,max]; otherwise they fall back to `default` (bad config stays harmless
-- but visible, see scripts).
function M.env_int(name, default, min, max, clamp)
    local raw = M.env_str(name, nil)
    if not raw then return default end
    local n = tonumber(raw)
    if not n then return default end
    n = math.floor(n)
    if clamp then
        if min and n < min then n = min end
        if max and n > max then n = max end
        return n
    end
    if min and n < min then return default end
    if max and n > max then return default end
    return n
end

-- Float env var (ratios such as AGENTWALL_HEADLESS_BLOCK). Clamped to [min,max]
-- when clamp is true, else out-of-range falls back to `default`.
function M.env_float(name, default, min, max, clamp)
    local raw = M.env_str(name, nil)
    if not raw then return default end
    local n = tonumber(raw)
    if not n then return default end
    if clamp then
        if min and n < min then n = min end
        if max and n > max then n = max end
        return n
    end
    if min and n < min then return default end
    if max and n > max then return default end
    return n
end

function M.load_redis_config()
    return {
        host        = M.env_str("AGENTWALL_REDIS_HOST", M.DEFAULT_REDIS_HOST),
        port        = M.env_int("AGENTWALL_REDIS_PORT", M.DEFAULT_REDIS_PORT, 1, 65535, false),
        pass        = M.env_str("AGENTWALL_REDIS_PASS", nil),
        db          = M.env_int("AGENTWALL_REDIS_DB", M.DEFAULT_REDIS_DB, 0, 1024, false),
        timeout_ms  = M.env_int("AGENTWALL_REDIS_TIMEOUT_MS", M.DEFAULT_REDIS_TIMEOUT_MS, 1, 60000, false),
        ipv6_prefix = M.env_int("AGENTWALL_IPV6_PREFIX", M.DEFAULT_IPV6_PREFIX, 0, 128, false),
    }
end

function M.load_challenge_config()
    local mode = M.env_str("AGENTWALL_HEADLESS_MODE", M.DEFAULT_HEADLESS_MODE)
    mode = mode:lower()
    if mode ~= M.HEADLESS_MODE_BLOCK then
        mode = M.HEADLESS_MODE_MARK          -- unknown/misspelled -> safe shadow
    end
    return {
        secret    = M.env_str("AGENTWALL_CHAL_SECRET", nil),
        pow_diff  = M.env_int("AGENTWALL_POW_DIFF", M.DEFAULT_POW_DIFF,
                              M.POW_DIFF_MIN, M.POW_DIFF_MAX, true),
        chal_ttl  = M.env_int("AGENTWALL_CHAL_TTL", M.DEFAULT_CHAL_TTL, 1, 86400 * 30, false),
        clr_ttl   = M.env_int("AGENTWALL_CLR_TTL", M.DEFAULT_CLR_TTL, 1, 86400 * 30, false),
        headless_mode = mode,
        headless_ttl  = M.env_int("AGENTWALL_HEADLESS_TTL", M.DEFAULT_HEADLESS_TTL,
                                  M.HEADLESS_TTL_MIN, M.HEADLESS_TTL_MAX, true),
        headless_block = M.env_float("AGENTWALL_HEADLESS_BLOCK",
                                     M.DEFAULT_HEADLESS_BLOCK, 0, 1, true),
        headless_suspect = M.env_float("AGENTWALL_HEADLESS_SUSPECT",
                                       M.DEFAULT_HEADLESS_SUSPECT, 0, 1, true),
        min_solve_ms = M.env_int("AGENTWALL_MIN_SOLVE_MS", M.DEFAULT_MIN_SOLVE_MS,
                                 0, 600000, false),
    }
end

-- =============================================================================
-- Small utility: one log line per key per ttl seconds, using the optional
-- shared dict (tolerates it being absent -> always logs, never crashes).
-- =============================================================================
function M.log_limited(cache, key, ttl, log_fn, level, msg)
    if cache then
        local added = cache:add(key, true, ttl)
        if not added then return false end
    end
    if type(log_fn) == "function" then
        log_fn(level, msg)
    end
    return true
end

return M
