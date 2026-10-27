-- =============================================================================
-- agentwall_challenge_block.lua — hard block + signed JS PoW + headless detection
-- =============================================================================
-- v3. Per-request flow (access phase, after real_ip):
--
--   TOP (all requests):
--     1. cached positive hard block            -> 403 (JSON for /__agentwall_verify)
--     2. Redis connect/auth/select
--     3. GET agentwall:block:<ip_key>              -> 403 if present (always wins)
--     4. URI == /__agentwall_verify                -> verify handler, JSON only
--     5. GET agentwall:challenge:<ip_key>          -> absent: allow
--     6. mode=block and agentwall:headless present -> 403 (challenged requests only;
--                                                 read before step 7 writes it)
--     7. automation User-Agent (every request) -> write marker + WARN (never a
--                                                 direct response; blocks via 6
--                                                 and via the verify score)
--     8. valid clearance cookie                -> SET agentwall:cleared, DEL challenge,
--                                                 allow
--     9. GET fallback ?agentwall_id=&agentwall_pow=    -> id+PoW verify (no report, no
--                                                 headless signal), Set-Cookie, 302
--    10. otherwise                             -> mint <id>, store
--        "agentwall:chal:<id>" = "<ip_key>|<issued_ms>" EX 180, serve 429 interstitial
--
--   /__agentwall_verify (POST, application/json, body <= 4096B):
--     {"id","nonce","report":{...}} with report schema documented in README.
--     200 {"ok":true,"next":"/<page uri without agentwall_id/agentwall_pow>"} + Set-Cookie
--     403 {"ok":false,"reason":"automation"} (mode=block; marker written)
--     403 {"ok":false,"reason":"blocked"}    (agentwall:block wins)
--     429 {"ok":false,"reason":"retry"}      (bad body/id/nonce/ip-binding/PoW)
--     Infra failure: 200 {"ok":true,...} without cookie (fail open), never 5xx.
--
-- The interstitial computes the SHA-1 PoW client side, then collects a browser
-- environment report (webdriver/CDP artifacts/plugin surface/WebGL/timing) and
-- POSTs it. Headless detection is ADVISORY: default Playwright/Puppeteer is
-- caught; stealth plugins / patched builds / a real browser driven by a human
-- are not reliably distinguishable. Default mode is `mark` (shadow): record a
-- marker + WARN but still clear the visitor.
--
-- nginx.conf main context MUST declare (see nginx-lua/README.md):
--   env AGENTWALL_REDIS_HOST; env AGENTWALL_REDIS_PORT; env AGENTWALL_REDIS_PASS;
--   env AGENTWALL_REDIS_DB;   env AGENTWALL_REDIS_TIMEOUT_MS; env AGENTWALL_IPV6_PREFIX;
--   env AGENTWALL_CHAL_SECRET; env AGENTWALL_POW_DIFF; env AGENTWALL_CHAL_TTL;
--   env AGENTWALL_CLR_TTL;     env AGENTWALL_HEADLESS_MODE; env AGENTWALL_HEADLESS_TTL;
--   env AGENTWALL_HEADLESS_BLOCK; env AGENTWALL_HEADLESS_SUSPECT; env AGENTWALL_MIN_SOLVE_MS;
-- http context:
--   lua_package_path "/etc/nginx/lua/?.lua;;";
--   lua_shared_dict agentwall_cache 2m;
-- server context:
--   real_ip ...                               # FIRST, so $remote_addr is true
--   access_by_lua_file /etc/nginx/lua/agentwall_challenge_block.lua;
-- =============================================================================

local common = require "agentwall_common"

local ip = ngx.var.remote_addr
if not ip then return end

local redis_cfg = common.load_redis_config()
local cfg = common.load_challenge_config()
local ip_key = common.ip_key(ip, redis_cfg.ipv6_prefix) or ip

-- The verify endpoint is special-cased before any challenge/interstitial logic.
local is_verify = (ngx.var.uri == "/__agentwall_verify")

local cache = ngx.shared and ngx.shared.agentwall_cache or nil
local CACHE_BLOCK         = "cb:"
local CACHE_CHALLENGE     = "cc:"
local CACHE_HEADLESS_MARK = "hm:"     -- debounce marker writes
local CACHE_BLOCK_TTL     = 5
local CACHE_CHALLENGE_TTL = 2
local CACHE_LOG           = "clog:"

local function log_limited(reason, level, msg)
    common.log_limited(cache, CACHE_LOG .. reason, 5, ngx.log, level, msg)
end

local function is_config_error(err)
    if type(err) ~= "string" then return false end
    if err:find("NOAUTH", 1, true) then return true end
    if err:find("WRONGPASS", 1, true) then return true end
    if err:find("invalid password", 1, true) then return true end
    if err:find("no password is set", 1, true) then return true end
    return false
end

local hmac_fn = ngx.hmac_sha1
local sha1_fn = ngx.sha1_bin

-- =============================================================================
-- JSON responses (verify endpoint only; ordinary requests keep plain statuses)
-- =============================================================================
local cjson_module = nil
local function get_cjson()
    if cjson_module then return cjson_module end
    local ok, mod = pcall(require, "cjson.safe")
    if ok and type(mod) == "table" then
        cjson_module = mod
    end
    return cjson_module
end

local function json_escape(s)
    s = tostring(s or "")
    s = s:gsub("\\", "\\\\"):gsub('"', '\\"')
    s = s:gsub("[%z\1-\31]", function(c)
        return string.format("\\u%04x", c:byte())
    end)
    return s
end

-- Always JSON + no-store, exactly as the contract requires. Exits the request.
local function json_response(status, payload)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["X-Content-Type-Options"] = "nosniff"
    local cjson = get_cjson()
    local body
    if cjson then
        body = cjson.encode(payload)
    elseif payload.ok == true then
        body = '{"ok":true,"next":"' .. json_escape(payload.next or "/") .. '"}'
    else
        body = '{"ok":false,"reason":"' .. json_escape(payload.reason or "retry") .. '"}'
    end
    ngx.print(body)
    return ngx.exit(status)
end

-- "Same URI as the interstitial page, minus agentwall_id/agentwall_pow". The browser
-- fetch() to /__agentwall_verify carries the interstitial page URL as Referer; we
-- only ever keep its path/query, so the returned `next` is a same-origin path.
local function next_uri_from_referer()
    local ref = ngx.var.http_referer
    if type(ref) ~= "string" or ref == "" then return "/" end
    local path = ref:match("^[%a][%w+.-]*://[^/]*(/.*)$")
    if not path and ref:sub(1, 1) == "/" then
        path = ref
    end
    if not path then return "/" end
    return common.strip_pow_args(path)
end

-- =============================================================================
-- Interstitial: no external assets; inline WebCrypto PoW + environment report
-- =============================================================================
local INTERSTITIAL = [[<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;text-align:center;margin:0;padding-top:12vh;background:#fafafa;color:#222}
h1{font-size:1.2rem;font-weight:600;margin:0 0 .5rem}
p{color:#555;max-width:34rem;margin:.6rem auto;line-height:1.5}
#status{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#777}
</style>
</head>
<body>
<h1>Checking your browser&hellip;</h1>
<p id="status">Solving a small proof-of-work challenge. This page redirects automatically.</p>
<noscript><p>JavaScript is required to continue.</p></noscript>
<script>
(function () {
  "use strict";
  var CHAL_ID = "__AGENTWALL_ID__";
  var DIFF = __AGENTWALL_DIFF__;
  var MAX_ATTEMPTS = 100000000;
  var statusEl = document.getElementById("status");

  function show(msg) { if (statusEl) { statusEl.textContent = msg; } }

  if (!window.crypto || !window.crypto.subtle ||
      typeof window.crypto.subtle.digest !== "function" ||
      typeof window.TextEncoder !== "function" ||
      typeof window.fetch !== "function") {
    show("Your browser cannot complete the security check (WebCrypto/fetch is unavailable). " +
         "Please use a current browser over HTTPS.");
    return;
  }

  function toHex(buf) {
    var bytes = new Uint8Array(buf);
    var out = "";
    for (var i = 0; i < bytes.length; i++) {
      out += (bytes[i] < 16 ? "0" : "") + bytes[i].toString(16);
    }
    return out;
  }

  function sha1Hex(str) {
    return window.crypto.subtle.digest("SHA-1", new TextEncoder().encode(str)).then(toHex);
  }

  function collectReport() {
    var nav = window.navigator || {};
    var languages = [];
    try {
      if (Array.isArray(nav.languages)) {
        languages = nav.languages.slice(0);
      } else if (typeof nav.language === "string" && nav.language) {
        languages = [nav.language];
      }
    } catch (e) { languages = []; }

    var plugins = 0, mimeTypes = 0;
    try { plugins = nav.plugins ? nav.plugins.length : 0; } catch (e) { plugins = 0; }
    try { mimeTypes = nav.mimeTypes ? nav.mimeTypes.length : 0; } catch (e) { mimeTypes = 0; }

    var webglVendor = "", webglRenderer = "";
    try {
      var canvas = document.createElement("canvas");
      var gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {
        var dbg = gl.getExtension("WEBGL_debug_renderer_info");
        if (dbg) {
          try { webglVendor = String(gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || ""); } catch (e) {}
          try { webglRenderer = String(gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || ""); } catch (e) {}
        }
        if (!webglVendor) { try { webglVendor = String(gl.getParameter(gl.VENDOR) || ""); } catch (e) {} }
        if (!webglRenderer) { try { webglRenderer = String(gl.getParameter(gl.RENDERER) || ""); } catch (e) {} }
      }
    } catch (e) { webglVendor = ""; webglRenderer = ""; }

    var cdp = false;
    try {
      if (nav.webdriver) { cdp = true; }
      for (var k in window) {
        if (typeof k === "string" &&
            (k.indexOf("cdc_adoQpoasnfa76pfcZLmcfl_") === 0 ||
             k.indexOf("__playwright") === 0 ||
             k.indexOf("__puppeteer") === 0)) {
          cdp = true;
          break;
        }
      }
    } catch (e) { /* keep cdp as-is */ }

    var notification = "unavailable";
    try {
      notification = (typeof Notification !== "undefined") ? String(Notification.permission) : "unavailable";
    } catch (e) { notification = "unavailable"; }

    var tz = 0;
    try { tz = (new Date()).getTimezoneOffset(); } catch (e) { tz = 0; }

    return {
      webdriver: nav.webdriver === true,
      ua: String(nav.userAgent || ""),
      languages: languages,
      plugins: plugins,
      mimeTypes: mimeTypes,
      chrome: typeof window.chrome === "object" && window.chrome !== null,
      webglVendor: webglVendor,
      webglRenderer: webglRenderer,
      hardwareConcurrency: (typeof nav.hardwareConcurrency === "number") ? nav.hardwareConcurrency : null,
      deviceMemory: (typeof nav.deviceMemory === "number") ? nav.deviceMemory : null,
      screenW: (window.screen && typeof window.screen.width === "number") ? window.screen.width : 0,
      screenH: (window.screen && typeof window.screen.height === "number") ? window.screen.height : 0,
      outerW: window.outerWidth || 0,
      outerH: window.outerHeight || 0,
      timezoneOffset: tz,
      notification: notification,
      pdfViewer: !!(nav.pdfViewerEnabled),
      touchPoints: (typeof nav.maxTouchPoints === "number") ? nav.maxTouchPoints : 0,
      cdp: cdp
    };
  }

  function retryReload() {
    try {
      var n = parseInt(window.sessionStorage.getItem("agentwall_pow_retry") || "0", 10) || 0;
      if (n < 1) {
        window.sessionStorage.setItem("agentwall_pow_retry", String(n + 1));
        window.location.reload();
        return;
      }
    } catch (e) { /* storage unavailable -> show message below */ }
    show("The security check could not be completed. Please reload the page.");
  }

  function postVerify(nonce) {
    var report = collectReport();
    var payload = JSON.stringify({ id: CHAL_ID, nonce: String(nonce), report: report });
    window.fetch("/__agentwall_verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: payload
    }).then(function (r) {
      return r.json().then(function (j) {
        return { status: r.status, data: j };
      }).catch(function () {
        return { status: r.status, data: null };
      });
    }).then(function (res) {
      if (res.status === 200 && res.data && res.data.ok === true) {
        try { window.sessionStorage.removeItem("agentwall_pow_retry"); } catch (e) {}
        var next = res.data.next;
        if (typeof next === "string" && next.charAt(0) === "/" && next.charAt(1) !== "/") {
          window.location.replace(next);
        } else {
          window.location.reload();
        }
        return;
      }
      if (res.status === 403) {
        show("Access denied: automated browser detected. If you believe this is a mistake, " +
             "please contact the site operator.");
        return;
      }
      /* 429 or anything else: one automatic reload to fetch a fresh challenge. */
      retryReload();
    }).catch(function () {
      retryReload();
    });
  }

  var nonce = 0;
  function attempt() {
    if (nonce > MAX_ATTEMPTS) {
      show("Proof-of-work took too long. Please reload to try again.");
      return;
    }
    var n = String(nonce++);
    sha1Hex(CHAL_ID + ":" + n).then(function (hex) {
      var ok = true;
      for (var i = 0; i < DIFF; i++) {
        if (hex.charAt(i) !== "0") { ok = false; break; }
      }
      if (!ok) {
        if (nonce % 4096 === 0) { show("Solving proof-of-work\u2026 (" + nonce + " attempts)"); }
        attempt();
        return;
      }
      postVerify(n);
    }).catch(function () {
      show("Your browser could not complete the security check. Please reload the page.");
    });
  }
  attempt();
})();
</script>
</body>
</html>
]]

local function render_interstitial(chal_id, diff)
    local html = INTERSTITIAL:gsub("__AGENTWALL_ID__", function() return chal_id end)
    html = html:gsub("__AGENTWALL_DIFF__", function() return tostring(diff) end)
    return html
end

local function serve_interstitial(chal_id, diff)
    ngx.status = ngx.HTTP_TOO_MANY_REQUESTS
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.header["Pragma"] = "no-cache"
    ngx.header["Retry-After"] = "1"
    ngx.header["X-Robots-Tag"] = "noindex, nofollow"
    ngx.print(render_interstitial(chal_id, diff))
    return ngx.exit(ngx.HTTP_TOO_MANY_REQUESTS)
end

-- Server-minted id: request_id is a per-request random 32-hex tag, so ids are
-- unpredictable and unique; md5 gives a URL/JS-safe fixed-width hex token.
local function make_chal_id(ip_key)
    local parts = {
        ip_key or "",
        ngx.var.request_id or "",
        tostring(ngx.now()),
        tostring(math.random(1, 2147483646)),
    }
    if ngx.worker and ngx.worker.pid then
        parts[#parts + 1] = tostring(ngx.worker.pid())
    end
    local id = ngx.md5(table.concat(parts, "|"))
    if not id then
        id = ngx.md5(tostring(ngx.now()) .. "|" .. tostring(math.random()))
    end
    return id
end

-- Mint + store a single-use challenge id and answer 429. The value binds the id
-- to the ip_key AND records the issue time (ms) for the server-side solve-time
-- signal. On a Redis write error we fail OPEN (allow) rather than serve a
-- challenge that can never be verified.
local function issue_challenge(red, ip_key, diff)
    local chal_id = make_chal_id(ip_key)
    local issued_ms = math.floor(ngx.now() * 1000)
    local value = ip_key .. "|" .. string.format("%d", issued_ms)
    local ok, err = red:set(common.KEY_CHAL .. chal_id, value, "EX", common.CHAL_ID_TTL)
    if not ok then
        red:close()
        log_limited("chal-id-set", ngx.ERR,
            "agentwall: redis SET agentwall:chal failed: " .. tostring(err) .. " (failing open)")
        return
    end
    red:set_keepalive(10000, 100)
    return serve_interstitial(chal_id, diff)
end

local function set_clearance_cookie(value, ttl)
    ngx.header["Set-Cookie"] =
        common.COOKIE_NAME .. "=" .. value ..
        "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" .. tostring(ttl)
end

-- =============================================================================
-- GET fallback redirect (same URI without agentwall_id/agentwall_pow)
-- =============================================================================
local function redirect_without_pow_args()
    local args = ngx.req.get_uri_args()
    args["agentwall_id"] = nil
    args["agentwall_pow"] = nil
    local encoded = ngx.encode_args(args)
    local target = ngx.var.uri
    if encoded ~= "" then
        target = target .. "?" .. encoded
    end
    return ngx.redirect(target, 302)
end

-- =============================================================================
-- Headless marker (debounced) + scanner/marker helpers
-- =============================================================================
-- Writes agentwall:headless:<ip_key>=1 EX <headless_ttl>, at most once per ~60s per
-- worker (so a bot hammering the proxy does not cause one Redis write/request).
local function mark_headless(red, ip_key, cfg, why)
    local cache_key = CACHE_HEADLESS_MARK .. ip_key
    if cache then
        local seen = cache:get(cache_key)
        if seen then return true end
    end
    local ok, err = red:set(common.KEY_HEADLESS .. ip_key, "1", "EX", cfg.headless_ttl)
    if not ok then
        log_limited("headless-marker-set", ngx.ERR,
            "agentwall: redis SET " .. common.KEY_HEADLESS .. ip_key .. " failed: " ..
            tostring(err) .. " (" .. why .. "; allowing)")
        return false
    end
    if cache then
        local debounce = 60
        if cfg.headless_ttl < debounce then debounce = cfg.headless_ttl end
        cache:set(cache_key, 1, debounce)
    end
    return true
end

-- =============================================================================
-- /__agentwall_verify handler
-- =============================================================================
local function verify_retry(red)
    red:set_keepalive(10000, 100)
    return json_response(ngx.HTTP_TOO_MANY_REQUESTS, { ok = false, reason = "retry" })
end

-- Infra failure: fail open without clearance (never 5xx, no cookie unless the
-- id+PoW were actually validated on a healthy Redis).
local function verify_fail_open(red, reason, level)
    if red then red:close() end
    log_limited("verify-failopen", level,
        "agentwall: /__agentwall_verify " .. reason .. " (failing open, no clearance)")
    return json_response(ngx.HTTP_OK, { ok = true, next = next_uri_from_referer() })
end

local function read_body_file(path)
    local f, err = io.open(path, "rb")
    if not f then return nil, err end
    local data = f:read("*a")
    f:close()
    return data
end

local function handle_verify(red, ip_key, cfg)
    local cjson = get_cjson()
    if not cjson then
        return verify_fail_open(red, "lua-cjson (cjson.safe) unavailable", ngx.CRIT)
    end
    if type(sha1_fn) ~= "function" or type(hmac_fn) ~= "function" then
        return verify_fail_open(red,
            "ngx.sha1_bin/ngx.hmac_sha1 unavailable (lua-nginx-module too old?)", ngx.CRIT)
    end

    if ngx.req.get_method() ~= "POST" then
        return verify_retry(red)
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body and ngx.req.get_body_file then
        local file = ngx.req.get_body_file()
        if file then
            local data = read_body_file(file)
            if data then body = data end
        end
    end
    if not body or body == "" then
        return verify_retry(red)
    end
    if #body > 4096 then
        return verify_retry(red)
    end

    local request = cjson.decode(body)
    if type(request) ~= "table" then
        return verify_retry(red)
    end
    local chal_id = request["id"]
    local nonce = request["nonce"]
    local report = request["report"]
    if type(chal_id) ~= "string" or type(nonce) ~= "string" or type(report) ~= "table" then
        return verify_retry(red)
    end
    if chal_id == "" or #chal_id > common.CHAL_ID_MAX then
        return verify_retry(red)
    end
    -- Partial/empty report objects are not rejected here: headless_score
    -- scores missing surfaces (+0.40 for <5 expected keys), so junk-but-valid
    -- JSON yields a high score instead of an endless 429 retry loop. Only a
    -- missing or non-object `report` is a 429 ("missing/invalid").

    -- Single use: GET then DEL before doing anything else with the value.
    local stored, gerr = red:get(common.KEY_CHAL .. chal_id)
    if not stored then
        if is_config_error(gerr) then
            return verify_fail_open(red,
                "redis GET agentwall:chal failed with a CONFIGURATION error: " ..
                tostring(gerr), ngx.CRIT)
        end
        return verify_fail_open(red,
            "redis GET agentwall:chal failed: " .. tostring(gerr), ngx.ERR)
    end

    local consumed, delerr = red:del(common.KEY_CHAL .. chal_id)
    if not consumed then
        return verify_fail_open(red,
            "redis DEL agentwall:chal failed: " .. tostring(delerr), ngx.ERR)
    end
    if consumed == 0 then
        -- Unknown/expired/already-consumed id (or a lost race): retry fresh.
        return verify_retry(red)
    end
    if stored == ngx.null then
        return verify_retry(red)
    end

    local bound_key, issued_ms = common.parse_chal_value(stored)
    if not bound_key or bound_key ~= ip_key then
        return verify_retry(red)
    end
    if not common.pow_ok(chal_id, nonce, cfg.pow_diff, sha1_fn) then
        return verify_retry(red)
    end

    -- Score the browser report. The server-side User-Agent is authoritative
    -- (overwrites the client-supplied report.ua) so a spoofed report cannot
    -- hide a HeadlessChrome/automation UA.
    local now_ms = math.floor(ngx.now() * 1000)
    local solve_ms = now_ms - issued_ms
    if solve_ms < 0 then solve_ms = 0 end
    local server_ua = ngx.var.http_user_agent
    if type(server_ua) == "string" and server_ua ~= "" then
        report.ua = server_ua
    end

    local score = common.headless_score(report, {
        min_solve_ms = cfg.min_solve_ms,
        solve_ms = solve_ms,
        sec_ch_ua = ngx.var.http_sec_ch_ua,
        scheme = ngx.var.scheme,
    })
    local automation = score >= cfg.headless_block

    if automation then
        mark_headless(red, ip_key, cfg, "verify automation")
        if cfg.headless_mode == common.HEADLESS_MODE_BLOCK then
            -- Consume/delete the challenge: never issue clearance in block mode.
            local delok, delerr = red:del(common.KEY_CHALLENGE .. ip_key)
            red:set_keepalive(10000, 100)
            if cache then cache:delete(CACHE_CHALLENGE .. ip_key) end
            if not delok then
                log_limited("chal-del-automation", ngx.ERR,
                    "agentwall: redis DEL " .. common.KEY_CHALLENGE .. ip_key ..
                    " failed: " .. tostring(delerr) .. " (still returning 403)")
            end
            log_limited("automation-block", ngx.WARN,
                "agentwall: automation detected ip_key=" .. ip_key ..
                " score=" .. string.format("%.2f", score) ..
                " mode=block -> 403")
            return json_response(ngx.HTTP_FORBIDDEN, { ok = false, reason = "automation" })
        end
        log_limited("automation-mark", ngx.WARN,
            "agentwall: automation detected ip_key=" .. ip_key ..
            " score=" .. string.format("%.2f", score) ..
            " mode=mark -> marker written, clearance still granted")
    elseif score >= cfg.headless_suspect then
        log_limited("headless-suspect", ngx.INFO,
            "agentwall: headless suspicion ip_key=" .. ip_key ..
            " score=" .. string.format("%.2f", score) .. " (below block threshold)")
    end

    -- Success path: record clearance for the scorer, drop the challenge, set
    -- the signed cookie, and tell the page where to go.
    local setok, seterr = red:set(common.KEY_CLEARED .. ip_key, "1", "EX", cfg.clr_ttl)
    local cdelok, cdelerr
    if setok then
        cdelok, cdelerr = red:del(common.KEY_CHALLENGE .. ip_key)
    end
    red:set_keepalive(10000, 100)
    if cache then cache:delete(CACHE_CHALLENGE .. ip_key) end
    if not setok then
        log_limited("cleared-set-verify", ngx.ERR,
            "agentwall: redis SET " .. common.KEY_CLEARED .. ip_key .. " failed: " ..
            tostring(seterr) .. " (allowing; challenge kept for retry)")
    end
    if setok and not cdelok then
        log_limited("chal-del-verify", ngx.ERR,
            "agentwall: redis DEL " .. common.KEY_CHALLENGE .. ip_key .. " failed: " ..
            tostring(cdelerr) .. " (allowing)")
    end

    local cookie_value, sign_err = common.cookie_sign(
        cfg.secret, ip_key, ngx.time() + cfg.clr_ttl, hmac_fn)
    if cookie_value then
        set_clearance_cookie(cookie_value, cfg.clr_ttl)
    else
        log_limited("cookie-sign", ngx.CRIT,
            "agentwall: failed to sign clearance cookie: " .. tostring(sign_err) ..
            " (allowing; visitor will be re-challenged)")
    end
    return json_response(ngx.HTTP_OK, { ok = true, next = next_uri_from_referer() })
end

-- =============================================================================
-- 1) fast path: cached positive hard block
-- =============================================================================
if cache and cache:get(CACHE_BLOCK .. ip_key) == 1 then
    if is_verify then
        return json_response(ngx.HTTP_FORBIDDEN, { ok = false, reason = "blocked" })
    end
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- =============================================================================
-- 2) Redis session: connect/auth/select once, keepalive on every success path
-- =============================================================================
local redis = require "resty.redis"
local red = redis:new()
red:set_timeout(redis_cfg.timeout_ms)

local r_ok, r_err = red:connect(redis_cfg.host, redis_cfg.port)
if not r_ok then
    log_limited("connect", ngx.ERR,
        "agentwall: redis connect failed host=" .. tostring(redis_cfg.host) ..
        " port=" .. tostring(redis_cfg.port) .. " err=" .. tostring(r_err) ..
        " (failing open)")
    if is_verify then
        return json_response(ngx.HTTP_OK, { ok = true, next = next_uri_from_referer() })
    end
    return
end

if redis_cfg.pass and redis_cfg.pass ~= "" then
    local aok, aerr = red:auth(redis_cfg.pass)
    if not aok then
        red:close()
        log_limited("auth", ngx.CRIT,
            "agentwall: redis AUTH failed (check AGENTWALL_REDIS_PASS / requirepass): " ..
            tostring(aerr) .. " (failing open)")
        if is_verify then
            return json_response(ngx.HTTP_OK, { ok = true, next = next_uri_from_referer() })
        end
        return
    end
end

if redis_cfg.db and redis_cfg.db ~= 0 then
    local sok, serr = red:select(redis_cfg.db)
    if not sok then
        red:close()
        log_limited("select", ngx.CRIT,
            "agentwall: redis SELECT " .. tostring(redis_cfg.db) .. " failed: " ..
            tostring(serr) .. " (failing open)")
        if is_verify then
            return json_response(ngx.HTTP_OK, { ok = true, next = next_uri_from_referer() })
        end
        return
    end
end

-- =============================================================================
-- 3) hard block (always wins, for both ordinary requests and /__agentwall_verify)
-- =============================================================================
local blocked, berr = red:get(common.KEY_BLOCK .. ip_key)
if not blocked then
    red:close()
    if is_config_error(berr) then
        log_limited("block-noauth", ngx.CRIT,
            "agentwall: redis GET " .. common.KEY_BLOCK .. ip_key ..
            " failed with a CONFIGURATION error: " .. tostring(berr) ..
            " (set AGENTWALL_REDIS_PASS and declare `env AGENTWALL_REDIS_PASS;`; failing open)")
    else
        log_limited("block-get", ngx.ERR,
            "agentwall: redis GET " .. common.KEY_BLOCK .. ip_key .. " failed: " ..
            tostring(berr) .. " (failing open)")
    end
    if is_verify then
        return json_response(ngx.HTTP_OK, { ok = true, next = next_uri_from_referer() })
    end
    return
end
if blocked ~= ngx.null then
    if cache then cache:set(CACHE_BLOCK .. ip_key, 1, CACHE_BLOCK_TTL) end
    red:set_keepalive(10000, 100)
    if is_verify then
        return json_response(ngx.HTTP_FORBIDDEN, { ok = false, reason = "blocked" })
    end
    return ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- =============================================================================
-- 4) /__agentwall_verify — special-cased top-of-script, JSON only
-- =============================================================================
if is_verify then
    return handle_verify(red, ip_key, cfg)
end

-- =============================================================================
-- 5) challenged?
-- =============================================================================
local challenged
if cache then
    local ch = cache:get(CACHE_CHALLENGE .. ip_key)
    if ch == 0 then
        challenged = false
    elseif ch == 1 then
        challenged = true
    end
end

if challenged == nil then
    local val, cerr = red:get(common.KEY_CHALLENGE .. ip_key)
    if not val then
        red:close()
        if is_config_error(cerr) then
            log_limited("chal-noauth", ngx.CRIT,
                "agentwall: redis GET " .. common.KEY_CHALLENGE .. ip_key ..
                " failed with a CONFIGURATION error: " .. tostring(cerr) ..
                " (set AGENTWALL_REDIS_PASS and declare `env AGENTWALL_REDIS_PASS;`; failing open)")
        else
            log_limited("chal-get", ngx.ERR,
                "agentwall: redis GET " .. common.KEY_CHALLENGE .. ip_key ..
                " failed: " .. tostring(cerr) .. " (failing open)")
        end
        return
    end
    challenged = (val ~= ngx.null)
    if cache then
        cache:set(CACHE_CHALLENGE .. ip_key, challenged and 1 or 0, CACHE_CHALLENGE_TTL)
    end
end

-- =============================================================================
-- 6) mode=block: a PRE-EXISTING headless marker denies the challenged request
-- =============================================================================
-- (Marker alone in mode=mark never blocks, so this GET is block-mode only.)
-- This read happens BEFORE this request's UA detection below on purpose: the
-- request that first discovers an automation User-Agent must still receive the
-- 429 interstitial (that interstitial is what drives /__agentwall_verify); later
-- challenged requests from that IP see the marker and get 403.
if challenged and cfg.headless_mode == common.HEADLESS_MODE_BLOCK then
    local marker, herr = red:get(common.KEY_HEADLESS .. ip_key)
    if not marker then
        red:close()
        if is_config_error(herr) then
            log_limited("headless-noauth", ngx.CRIT,
                "agentwall: redis GET " .. common.KEY_HEADLESS .. ip_key ..
                " failed with a CONFIGURATION error: " .. tostring(herr) ..
                " (failing open)")
        else
            log_limited("headless-get", ngx.ERR,
                "agentwall: redis GET " .. common.KEY_HEADLESS .. ip_key ..
                " failed: " .. tostring(herr) .. " (failing open)")
        end
        return
    end
    if marker ~= ngx.null then
        red:set_keepalive(10000, 100)
        log_limited("headless-marker-block", ngx.WARN,
            "agentwall: challenged request from marked-headless ip_key=" .. ip_key ..
            " mode=block -> 403")
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

-- =============================================================================
-- 7) server-side automation User-Agent on EVERY request
-- =============================================================================
-- In block mode a known automation/scanner UA is denied immediately (there is
-- no legitimate reason for curl/nuclei/ARTEX markers to reach the app); in mark
-- mode we only write the marker + WARN so the false-positive rate can be
-- measured before enforcing. Stealth tooling that hides its UA is handled by
-- the browser-environment report at /__agentwall_verify.
local server_ua = ngx.var.http_user_agent
if common.is_automation_ua(server_ua) then
    mark_headless(red, ip_key, cfg, "automation UA")
    log_limited("ua-mark", ngx.WARN,
        "agentwall: automation User-Agent ip_key=" .. ip_key ..
        " ua=" .. tostring(server_ua) .. " mode=" .. cfg.headless_mode ..
        " -> marker written")
    if cfg.headless_mode == common.HEADLESS_MODE_BLOCK then
        red:set_keepalive(10000, 100)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

if not challenged then
    red:set_keepalive(10000, 100)
    return
end

-- =============================================================================
-- A challenge we cannot sign/verify is worse than no challenge: loud + fail open.
-- =============================================================================
if cfg.secret == nil or cfg.secret == "" then
    red:set_keepalive(10000, 100)
    log_limited("no-secret", ngx.CRIT,
        "agentwall: AGENTWALL_CHAL_SECRET is not set; cannot issue or verify challenges - " ..
        "failing open. Declare `env AGENTWALL_CHAL_SECRET;` in nginx.conf main context " ..
        "and restart/reload nginx.")
    return
end
if type(hmac_fn) ~= "function" or type(sha1_fn) ~= "function" then
    red:set_keepalive(10000, 100)
    log_limited("no-crypto", ngx.CRIT,
        "agentwall: ngx.hmac_sha1 / ngx.sha1_bin unavailable (lua-nginx-module too old?) - " ..
        "failing open. Upgrade OpenResty/ngx_lua.")
    return
end

-- =============================================================================
-- 9) valid clearance cookie for THIS ip_key -> clear challenge, mark cleared
-- =============================================================================
local cookie = ngx.var.cookie_agentwall_clr
if cookie and cookie ~= "" then
    local valid, why = common.cookie_verify(
        cfg.secret, ip_key, cookie, ngx.time(), cfg.clr_ttl, hmac_fn)
    if valid then
        -- Persist the scorer-visible cleared key FIRST; only delete the
        -- challenge once that succeeded (so a failed write is retried).
        local setok, seterr = red:set(common.KEY_CLEARED .. ip_key, "1", "EX", cfg.clr_ttl)
        local delok, delerr
        if setok then
            delok, delerr = red:del(common.KEY_CHALLENGE .. ip_key)
        end
        red:set_keepalive(10000, 100)
        if cache then cache:delete(CACHE_CHALLENGE .. ip_key) end
        if setok and not delok then
            log_limited("chal-del", ngx.ERR,
                "agentwall: redis DEL " .. common.KEY_CHALLENGE .. ip_key .. " failed: " ..
                tostring(delerr) .. " (allowing; cookie was valid)")
        end
        if not setok then
            log_limited("cleared-set", ngx.ERR,
                "agentwall: redis SET " .. common.KEY_CLEARED .. ip_key .. " failed: " ..
                tostring(seterr) .. " (allowing; challenge kept for retry)")
        end
        return
    end
    -- Don't flood logs with random/expired cookies, but leave a trail at INFO.
    log_limited("bad-cookie", ngx.INFO,
        "agentwall: ignoring clearance cookie (ip_key=" .. ip_key ..
        "): " .. tostring(why))
end

-- =============================================================================
-- 10) GET fallback: ?agentwall_id=&agentwall_pow= (no report -> no headless signal)
-- =============================================================================
local args = ngx.req.get_uri_args()
local chal_id = args["agentwall_id"]
local nonce = args["agentwall_pow"]
if type(chal_id) ~= "string" then chal_id = nil end
if type(nonce) ~= "string" then nonce = nil end

if chal_id and nonce then
    -- Bound before touching Redis (the verify endpoint already does this).
    if #chal_id > common.CHAL_ID_MAX or #nonce > 10 or not nonce:match("^%d+$") then
        return issue_challenge(red, ip_key, cfg.pow_diff)
    end
    local stored, cherr = red:get(common.KEY_CHAL .. chal_id)
    if not stored then
        red:close()
        if is_config_error(cherr) then
            log_limited("chalid-noauth", ngx.CRIT,
                "agentwall: redis GET agentwall:chal:<id> failed with a CONFIGURATION error: " ..
                tostring(cherr) .. " (failing open)")
        else
            log_limited("chalid-get", ngx.ERR,
                "agentwall: redis GET agentwall:chal:<id> failed: " .. tostring(cherr) ..
                " (failing open)")
        end
        return
    end

    local consumed, delerr = red:del(common.KEY_CHAL .. chal_id)
    if not consumed then
        red:close()
        log_limited("chalid-del", ngx.ERR,
            "agentwall: redis DEL agentwall:chal failed: " .. tostring(delerr) ..
            " (failing open, no clearance granted)")
        return
    end
    if consumed == 0 then
        return issue_challenge(red, ip_key, cfg.pow_diff)
    end

    local bound_key = nil
    if stored ~= ngx.null then
        bound_key = common.parse_chal_value(stored)
    end
    -- Backward compatibility: report-less verification only checks id binding
    -- and PoW. A missing report must NOT by itself mark automation.
    if bound_key == ip_key and common.pow_ok(chal_id, nonce, cfg.pow_diff, sha1_fn) then
        local setok, seterr = red:set(common.KEY_CLEARED .. ip_key, "1", "EX", cfg.clr_ttl)
        local cdelok, cdelerr
        if setok then
            cdelok, cdelerr = red:del(common.KEY_CHALLENGE .. ip_key)
        end
        red:set_keepalive(10000, 100)
        if cache then cache:delete(CACHE_CHALLENGE .. ip_key) end
        if not setok then
            log_limited("cleared-set-pow", ngx.ERR,
                "agentwall: redis SET " .. common.KEY_CLEARED .. ip_key .. " failed: " ..
                tostring(seterr) .. " (allowing; PoW was valid, challenge kept for retry)")
        end
        if setok and not cdelok then
            log_limited("chal-del-pow", ngx.ERR,
                "agentwall: redis DEL " .. common.KEY_CHALLENGE .. ip_key .. " failed: " ..
                tostring(cdelerr) .. " (allowing; PoW was valid)")
        end
        local cookie_value, sign_err = common.cookie_sign(
            cfg.secret, ip_key, ngx.time() + cfg.clr_ttl, hmac_fn)
        if cookie_value then
            set_clearance_cookie(cookie_value, cfg.clr_ttl)
        else
            log_limited("cookie-sign", ngx.CRIT,
                "agentwall: failed to sign clearance cookie: " .. tostring(sign_err) ..
                " (allowing; PoW was valid, but the visitor will be re-challenged)")
        end
        return redirect_without_pow_args()
    end
    -- Invalid/replayed/stale id or wrong nonce: fresh challenge.
end

-- =============================================================================
-- 11) no usable submission: mint a fresh single-use id and serve the challenge
-- =============================================================================
return issue_challenge(red, ip_key, cfg.pow_diff)
