-- =============================================================================
-- tests/lua/test_agentwall_common.lua — dependency-free unit tests
-- -----------------------------------------------------------------------------
-- Run from the repo root (or anywhere):
--     lua tests/lua/test_agentwall_common.lua
--
-- Pure Lua 5.1-compatible; no external modules, no `ngx`, no bit library.
-- Exit code 0 = all green, 1 = at least one failure.
-- =============================================================================

local script_path = (arg and arg[0]) or "tests/lua/test_agentwall_common.lua"
local script_dir = script_path:match("^(.*)[/\\]") or "."
-- Allow both "lua tests/lua/test_agentwall_common.lua" and an absolute invocation.
package.path = script_dir .. "/../../nginx-lua/?.lua;" .. package.path

local C = require "agentwall_common"

local pass, fail = 0, 0

local function report(ok, name, detail)
    if ok then
        pass = pass + 1
        print("PASS  " .. name)
    else
        fail = fail + 1
        local line = "FAIL  " .. name
        if detail ~= nil then
            line = line .. "  [" .. tostring(detail) .. "]"
        end
        print(line)
    end
end

local function eq(name, got, want)
    if got == want then
        report(true, name)
    else
        report(false, name, "got=" .. tostring(got) .. " want=" .. tostring(want))
    end
end

local function truthy(name, v)
    if v then report(true, name) else report(false, name, "expected truthy") end
end

local function falsy(name, v)
    if not v then report(true, name) else report(false, name, "expected falsy") end
end

local section = function(title)
    print("")
    print("-- " .. title .. " " .. string.rep("-", math.max(0, 68 - #title)))
end

-- =============================================================================
-- Deterministic stubs for the injected crypto primitives
-- =============================================================================
local ZERO = string.char(0)

local function fake_bin(s)
    local t = {}
    for i = 1, #s do
        t[#t + 1] = string.char((s:byte(i) * 31 + i * 7 + 11) % 256)
    end
    return table.concat(t)
end

-- Fake HMAC: 20+ byte deterministic digest derived from secret and data.
local function hmac_fn(secret, data)
    return fake_bin(secret .. "|" .. data)
end

local function bin_from_hex(h)
    local bin = C.unhex(h)
    assert(bin, "test setup: invalid hex")
    return bin
end

-- =============================================================================
-- Constants / ip_key (must match Python normalization exactly)
-- =============================================================================
section("constants")
eq("cookie name", C.COOKIE_NAME, "agentwall_clr")
eq("cookie version", C.COOKIE_VERSION, "v1")
eq("block key prefix", C.KEY_BLOCK, "agentwall:block:")
eq("challenge key prefix", C.KEY_CHALLENGE, "agentwall:challenge:")
eq("cleared key prefix", C.KEY_CLEARED, "agentwall:cleared:")
eq("challenge id key prefix", C.KEY_CHAL, "agentwall:chal:")
eq("challenge id ttl", C.CHAL_ID_TTL, 180)

section("ip_key: IPv4")
eq("ipv4 canonical", C.ip_key("1.2.3.4"), "1.2.3.4")
eq("ipv4 ignores prefix", C.ip_key("10.1.2.3", 64), "10.1.2.3")
eq("ipv4 mapped dotted", C.ip_key("::ffff:1.2.3.4"), "1.2.3.4")
eq("ipv4 mapped uppercase", C.ip_key("::FFFF:1.2.3.4", 128), "1.2.3.4")
eq("ipv4 mapped hex groups", C.ip_key("0:0:0:0:0:ffff:102:304", 96), "1.2.3.4")
eq("ipv4 mapped loopback", C.ip_key("::ffff:127.0.0.1", 64), "127.0.0.1")
eq("ipv4 mapped zero", C.ip_key("::ffff:0:0", 64), "0.0.0.0")

section("ip_key: IPv6 canonicalization (matches Python ip_network str)")
-- Expected values generated with Python 3:
--   str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False).network_address)
eq("ipv6 /64 lowercase/compressed", C.ip_key("2001:0DB8:0:0:1:0:0:1", 64), "2001:db8::")
eq("ipv6 loopback /64", C.ip_key("::1", 64), "::")
eq("ipv6 /64 example", C.ip_key("2a00:1450:4001:82b::200e", 64), "2a00:1450:4001:82b::")
eq("ipv6 zero /64", C.ip_key("::", 64), "::")
eq("ipv6 zero /0", C.ip_key("2001:db8::1", 0), "::")
eq("ipv6 /128 keeps host bits", C.ip_key("2001:db8::1", 128), "2001:db8::1")
eq("ipv6 link-local /64", C.ip_key("fe80::1", 64), "fe80::")
eq("ipv6 /64 middle zero group stays", C.ip_key("2001:db8:0:1:1:1:1:1", 64), "2001:db8:0:1::")
eq("ipv6 /65 non-nibble mask", C.ip_key("2001:db8:0:0:8000::1", 65), "2001:db8:0:0:8000::")
eq("ipv6 /65 high bit clear", C.ip_key("2001:db8:abcd:1234:5678:9abc:def0:1234", 65),
   "2001:db8:abcd:1234::")
eq("ipv6 /68 nibble mask", C.ip_key("2001:db8:abcd:1234:5678:9abc:def0:1234", 68),
   "2001:db8:abcd:1234:5000::")
eq("ipv6 default prefix is /64", C.ip_key("2001:db8::1"), "2001:db8::")
eq("ipv6 invalid prefix -> /64", C.ip_key("2001:db8::1", 200), "2001:db8::")
eq("ipv6 bogus prefix -> /64", C.ip_key("2001:db8::1", "bogus"), "2001:db8::")
eq("ipv6 string prefix accepted", C.ip_key("2001:db8:0:0:8000::1", "65"),
   "2001:db8:0:0:8000::")
eq("ipv6 embedded ipv4 tail", C.ip_key("2001:db8::1.2.3.4", 128), "2001:db8::102:304")
eq("ipv6 compressed zeros from dotted tail", C.ip_key("::1.2.3.4", 128), "::102:304")
eq("ipv6 compression tie -> leftmost", C.ip_key("1:0:0:2:0:0:3:4", 128), "1::2:0:0:3:4")
eq("ipv6 single zero not compressed", C.ip_key("1:0:2:3:4:5:6:7", 128), "1:0:2:3:4:5:6:7")
eq("ipv6 trailing zeros compressed", C.ip_key("1:2:3:4:5:6:0:0", 128), "1:2:3:4:5:6::")
eq("ipv6 leading zeros stripped", C.ip_key("2001:0DB8:0000:0000:0000:0000:0000:0001", 128),
   "2001:db8::1")

section("ip_key: invalid inputs -> nil")
eq("invalid text", C.ip_key("not-an-ip"), nil)
eq("invalid ipv4 octet", C.ip_key("999.1.1.1"), nil)
eq("short ipv4", C.ip_key("1.2.3"), nil)
eq("long ipv4", C.ip_key("1.2.3.4.5"), nil)
eq("ipv4 leading zero", C.ip_key("01.2.3.4"), nil)
eq("ipv4 trailing space", C.ip_key("1.2.3.4 "), nil)
eq("empty string", C.ip_key(""), nil)
eq("nil ip", C.ip_key(nil), nil)
eq("number ip", C.ip_key(12345), nil)
eq("triple colon", C.ip_key(":::"), nil)
eq("double double-colon", C.ip_key("2001:db8:::1"), nil)
eq("group too long", C.ip_key("12345::"), nil)
eq("too many groups", C.ip_key("1:2:3:4:5:6:7:8:9"), nil)
eq("dots inside ipv6", C.ip_key("1.2.3.4::1"), nil)
eq("zone id rejected", C.ip_key("fe80::1%en0"), nil)
eq("bracketted ipv6 rejected", C.ip_key("[::1]"), nil)

-- =============================================================================
-- hex / unhex
-- =============================================================================
section("hex / unhex")
eq("hex empty", C.hex(""), "")
eq("hex one byte", C.hex(string.char(255)), "ff")
eq("hex mixed", C.hex(string.char(0, 1, 255)), "0001ff")
eq("unhex empty", C.unhex(""), "")
eq("unhex basic", C.unhex("0001ff"), string.char(0, 1, 255))
eq("unhex mixed case", C.unhex("0a0B"), string.char(10, 11))
falsy("unhex odd length", C.unhex("abc"))
falsy("unhex non-hex", C.unhex("zz"))
falsy("unhex nil", C.unhex(nil))
falsy("unhex number", C.unhex(100))

do
    local bytes = {}
    for i = 0, 255 do bytes[#bytes + 1] = string.char(i) end
    local all = table.concat(bytes)
    eq("hex/unhex roundtrip all 256 bytes", C.unhex(C.hex(all)), all)
end

-- =============================================================================
-- hmac_hex
-- =============================================================================
section("hmac_hex")
eq("hmac hex with injected fn",
   C.hmac_hex("sekrit", "hello", hmac_fn),
   C.hex(fake_bin("sekrit" .. "|" .. "hello")))
falsy("hmac empty secret", C.hmac_hex("", "hello", hmac_fn))
falsy("hmac nil fn", C.hmac_hex("sekrit", "hello", nil))
do
    local v, err = C.hmac_hex("sekrit", "hello", function() return nil, "boom" end)
    falsy("hmac fn failure -> nil", v)
    eq("hmac fn failure -> reason", err, "boom")
end

-- =============================================================================
-- clearance cookie
-- =============================================================================
section("clearance cookie: format + verify")
local NOW = 1700000000
local SECRET = "unit-test-secret"
local IP = "203.0.113.9"
local EXP = NOW + 120
local TTL = 600

local cookie = C.cookie_sign(SECRET, IP, EXP, hmac_fn)
eq("cookie format", cookie,
   "v1:" .. tostring(EXP) .. ":" ..
   C.hmac_hex(SECRET, IP .. "|" .. tostring(EXP), hmac_fn))
truthy("valid cookie verifies", C.cookie_verify(SECRET, IP, cookie, NOW, TTL, hmac_fn))
truthy("valid cookie at max exp boundary",
       C.cookie_verify(SECRET, IP, C.cookie_sign(SECRET, IP, NOW + TTL, hmac_fn),
                       NOW, TTL, hmac_fn))

do
    local serialized, sig = cookie:match("^(v1:%d+:)(%x+)$")
    truthy("serialized shape", serialized and sig)

    local _, tampered_sig = serialized, sig:sub(1, -2) .. ((sig:sub(-1) == "a") and "b" or "a")
    falsy("tampered signature rejected",
          C.cookie_verify(SECRET, IP, serialized .. tampered_sig, NOW, TTL, hmac_fn))

    local upper = serialized .. sig:upper()
    truthy("uppercase signature accepted",
           C.cookie_verify(SECRET, IP, upper, NOW, TTL, hmac_fn))

    local exp_s = tostring(EXP)
    local noncanonical = "v1:0" .. exp_s .. ":" .. sig
    falsy("non-canonical expiry rejected",
          C.cookie_verify(SECRET, IP, noncanonical, NOW, TTL, hmac_fn))

    local extended = "v1:" .. tostring(EXP + 10) .. ":" .. sig
    falsy("re-encoded expiry rejected (sig mismatch)",
          C.cookie_verify(SECRET, IP, extended, NOW, TTL, hmac_fn))
end

falsy("wrong ip rejected",
      C.cookie_verify(SECRET, "198.51.100.7", cookie, NOW, TTL, hmac_fn))
falsy("wrong secret rejected",
      C.cookie_verify("other-secret", IP, cookie, NOW, TTL, hmac_fn))
falsy("expired cookie rejected",
      C.cookie_verify(SECRET, IP, C.cookie_sign(SECRET, IP, NOW - 1, hmac_fn),
                      NOW, TTL, hmac_fn))
falsy("exp == now rejected",
      C.cookie_verify(SECRET, IP, C.cookie_sign(SECRET, IP, NOW, hmac_fn),
                      NOW, TTL, hmac_fn))
falsy("exp too far in future rejected",
      C.cookie_verify(SECRET, IP, C.cookie_sign(SECRET, IP, NOW + TTL + 1, hmac_fn),
                      NOW, TTL, hmac_fn))
falsy("zero ttl rejected", C.cookie_verify(SECRET, IP, cookie, NOW, 0, hmac_fn))
falsy("nil ttl rejected", C.cookie_verify(SECRET, IP, cookie, NOW, nil, hmac_fn))
falsy("nil cookie rejected", C.cookie_verify(SECRET, IP, nil, NOW, TTL, hmac_fn))
falsy("empty cookie rejected", C.cookie_verify(SECRET, IP, "", NOW, TTL, hmac_fn))
falsy("oversized cookie rejected",
      C.cookie_verify(SECRET, IP, string.rep("a", 300), NOW, TTL, hmac_fn))
falsy("nil secret rejected", C.cookie_verify(nil, IP, cookie, NOW, TTL, hmac_fn))
falsy("nil ip_key rejected", C.cookie_verify(SECRET, nil, cookie, NOW, TTL, hmac_fn))
falsy("cookie_sign nil secret", C.cookie_sign(nil, IP, EXP, hmac_fn))
falsy("cookie_sign nil ip", C.cookie_sign(SECRET, nil, EXP, hmac_fn))
falsy("cookie_sign nil fn", C.cookie_sign(SECRET, IP, EXP, nil))

for _, bad in ipairs({
    "1:1700000000:abcdef",
    "v2:1700000000:abcdef",
    "v1:1700000000",
    "v1:1700000000:",
    "v1:abc:abcdef",
    "v1:1700000000:zz",
    "v1:1700000000:abc",
    "v1:-1:abcdef",
    "v1: 1700000000:abcdef",
    "v1:1700000000:abcdef ",
}) do
    falsy("malformed cookie rejected: " .. bad,
          C.cookie_verify(SECRET, IP, bad, NOW, TTL, hmac_fn))
end

-- =============================================================================
-- pow_ok
-- =============================================================================
section("pow_ok")
local ZERO40 = string.rep("0", 40)

do
    local calls = 0
    local function sha_zero20(_)
        calls = calls + 1
        return string.rep(ZERO, 20)
    end
    truthy("valid pow (diff 4)", C.pow_ok("abc123", "42", 4, sha_zero20))
    eq("exactly one sha1 per check", calls, 1)
end

do
    local seen = nil
    local function sha_capture(data)
        seen = data
        return string.rep(ZERO, 20)
    end
    truthy("nonce '0' valid", C.pow_ok("id", "0", 3, sha_capture))
    eq("sha1 input format", seen, "id:0")
    truthy("10-digit nonce valid", C.pow_ok("id", "1234567890", 3, sha_capture))
    truthy("leading-zero nonce valid", C.pow_ok("id", "00042", 3, sha_capture))
    eq("sha1 input keeps leading zeros", seen, "id:00042")
end

truthy("diff 2 with 00 prefix",
       C.pow_ok("id", "7", 2, function() return bin_from_hex("001" .. string.rep("0", 37)) end))
falsy("diff 3 with 001 prefix fails",
      C.pow_ok("id", "7", 3, function() return bin_from_hex("001" .. string.rep("0", 37)) end))
falsy("wrong prefix rejected",
      C.pow_ok("id", "7", 1, function()
          return bin_from_hex("1" .. string.rep("0", 39))
      end))
falsy("digest longer than difficulty never all-zero",
      C.pow_ok("id", "7", 40, function()
          return bin_from_hex(ZERO40:sub(1, 39) .. "1")
      end))
falsy("difficulty 41 impossible", C.pow_ok("id", "7", 41,
      function() return string.rep(ZERO, 20) end))

falsy("nonce with letter rejected", C.pow_ok("id", "12a", 4,
      function() return string.rep(ZERO, 20) end))
falsy("nonce empty rejected", C.pow_ok("id", "", 4,
      function() return string.rep(ZERO, 20) end))
falsy("nonce with space rejected", C.pow_ok("id", " 1", 4,
      function() return string.rep(ZERO, 20) end))
falsy("nonce with dot rejected", C.pow_ok("id", "1.0", 4,
      function() return string.rep(ZERO, 20) end))
falsy("nonce negative rejected", C.pow_ok("id", "-1", 4,
      function() return string.rep(ZERO, 20) end))
falsy("nonce too long rejected", C.pow_ok("id", "12345678901", 4,
      function() return string.rep(ZERO, 20) end))
falsy("nonce non-string rejected", C.pow_ok("id", 42, 4,
      function() return string.rep(ZERO, 20) end))
falsy("empty id rejected", C.pow_ok("", "42", 4,
      function() return string.rep(ZERO, 20) end))
falsy("nil id rejected", C.pow_ok(nil, "42", 4,
      function() return string.rep(ZERO, 20) end))
falsy("oversized id rejected", C.pow_ok(string.rep("a", 65), "42", 4,
      function() return string.rep(ZERO, 20) end))
falsy("nil sha1 rejected", C.pow_ok("id", "42", 4, nil))
falsy("sha1 failure rejected", C.pow_ok("id", "42", 4,
      function() return nil, "boom" end))

-- No SHA-1 call should happen when the nonce fails validation first.
do
    local calls = 0
    C.pow_ok("id", "12a", 4, function() calls = calls + 1; return string.rep(ZERO, 20) end)
    eq("no sha1 for invalid nonce", calls, 0)
end

-- =============================================================================
-- log_limited (shared-dict rate limiting, absent-dict fallback)
-- =============================================================================
section("log_limited")
do
    local fake_cache = { seen = {} }
    function fake_cache:add(k)
        if self.seen[k] then return nil, "exists" end
        self.seen[k] = true
        return true
    end
    local logs = 0
    local function fake_log(_level, _msg) logs = logs + 1 end

    truthy("first log passes", C.log_limited(fake_cache, "k", 5, fake_log, 4, "m"))
    eq("first log emitted", logs, 1)
    falsy("second log suppressed", C.log_limited(fake_cache, "k", 5, fake_log, 4, "m"))
    eq("second log suppressed count", logs, 1)
    truthy("absent cache always logs", C.log_limited(nil, "k", 5, fake_log, 4, "m"))
    eq("absent cache always logs count", logs, 2)
end

-- =============================================================================
-- challenge-id value: "<ip_key>|<issued_ms>"
-- =============================================================================
section("parse_chal_value")
do
    local k, ms = C.parse_chal_value("1.2.3.4|1700000000123")
    eq("chal value ip_key", k, "1.2.3.4")
    eq("chal value issued_ms", ms, 1700000000123)
    local k6, ms6 = C.parse_chal_value("2a00:1450:4001:82b::|1700000000000")
    eq("chal value ipv6 key", k6, "2a00:1450:4001:82b::")
    eq("chal value ipv6 ms", ms6, 1700000000000)
end
falsy("chal value no pipe", C.parse_chal_value("1.2.3.4"))
falsy("chal value empty ms", C.parse_chal_value("1.2.3.4|"))
falsy("chal value empty key", C.parse_chal_value("|123"))
falsy("chal value non-numeric ms", C.parse_chal_value("1.2.3.4|12a"))
falsy("chal value extra pipe", C.parse_chal_value("1.2.3.4|123|456"))
falsy("chal value empty", C.parse_chal_value(""))
falsy("chal value nil", C.parse_chal_value(nil))
falsy("chal value number", C.parse_chal_value(42))

-- =============================================================================
-- URI stripping for verify {"next": ...}
-- =============================================================================
section("strip_pow_args")
eq("strip plain path", C.strip_pow_args("/page"), "/page")
eq("strip both args", C.strip_pow_args("/page?agentwall_id=abc&agentwall_pow=12"), "/page")
eq("strip args keeps others", C.strip_pow_args("/page?agentwall_id=abc&x=1&agentwall_pow=12&y=2"),
   "/page?x=1&y=2")
eq("strip no args", C.strip_pow_args("/page?x=1"), "/page?x=1")
eq("strip root", C.strip_pow_args("/"), "/")
eq("strip empty", C.strip_pow_args(""), "/")
eq("strip nil", C.strip_pow_args(nil), "/")
eq("strip bare question mark", C.strip_pow_args("/page?"), "/page")
eq("strip fragment", C.strip_pow_args("/page?agentwall_id=abc#frag"), "/page")
eq("strip trailing arg", C.strip_pow_args("/page?a=b&agentwall_id=1"), "/page?a=b")
eq("strip percent-encoded key", C.strip_pow_args("/page?agentwall%5Fid=1&x=2"), "/page?x=2")
eq("strip preserves other encoding", C.strip_pow_args("/p?q=a%20b&agentwall_pow=1"), "/p?q=a%20b")

-- =============================================================================
-- automation UA detection
-- =============================================================================
section("is_automation_ua")
local AUTOMATION_UAS = {
    "HeadlessChrome",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 Playwright/1.40.0",
    "Mozilla/5.0 puppeteer/21.0",
    "Mozilla/5.0 Selenium/4.0",
    "Mozilla/5.0 WebDriver",
    "HtmlUnit/2.50",
    "jsdom/22.1.0",
    "Cypress/13.0",
    "PhantomJS/2.1.1",
    "SlimerJS/1.0",
}
for _, ua in ipairs(AUTOMATION_UAS) do
    truthy("automation UA: " .. ua:sub(1, 40), C.is_automation_ua(ua))
end
truthy("automation UA case-insensitive", C.is_automation_ua("HEADLESSCHROME/1.0"))
falsy("real Chrome UA is not automation",
      C.is_automation_ua("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"))
falsy("real Firefox UA is not automation",
      C.is_automation_ua("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"))
falsy("real Safari UA is not automation",
      C.is_automation_ua("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15"))
falsy("empty UA", C.is_automation_ua(""))
falsy("nil UA", C.is_automation_ua(nil))
falsy("number UA", C.is_automation_ua(123))
falsy("unrelated UA", C.is_automation_ua("Artemis/1.0 (compatible)"))
falsy("Electron desktop app UA is not automation (Slack/Teams/VS Code embed sites)",
      C.is_automation_ua("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Electron/28.0.0 Chrome/120.0.0.0 Safari/537.36"))

section("is_mobile_ua")
truthy("Android Chrome is mobile", C.is_mobile_ua(
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"))
truthy("Android WebView is mobile", C.is_mobile_ua(
    "Mozilla/5.0 (Linux; Android 13; SM-A536E; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/124.0.0.0 Mobile Safari/537.36 Instagram 330.0"))
truthy("iPhone is mobile", C.is_mobile_ua(
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"))
falsy("desktop Chrome is not mobile", C.is_mobile_ua(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"))
falsy("nil UA is not mobile", C.is_mobile_ua(nil))

-- =============================================================================
-- safe_relative_path (server-side redirect validation)
-- =============================================================================
section("safe_relative_path")
eq("valid path preserved", C.safe_relative_path("/account?tab=1"), "/account?tab=1")
eq("absolute url rejected", C.safe_relative_path("https://evil.example/"), "/")
eq("protocol-relative rejected", C.safe_relative_path("//evil.example/x"), "/")
eq("backslash trick rejected", C.safe_relative_path("/\\evil.example"), "/")
eq("control char rejected", C.safe_relative_path("/ok\t/evil"), "/")
eq("empty rejected", C.safe_relative_path(""), "/")
eq("strip_pow_args backslash rejected", C.strip_pow_args("/\\evil.example?agentwall_id=x"), "/")
eq("strip_pow_args keeps safe query", C.strip_pow_args("/page?a=1&agentwall_id=x&agentwall_pow=2"), "/page?a=1")

-- =============================================================================
-- headless_score
-- =============================================================================
section("headless_score")
local function score_of(report, opts)
    return C.headless_score(report, opts)
end
local function approx(a, b, eps)
    return math.abs(a - b) <= (eps or 1e-9)
end

-- A normal desktop Chrome: must NOT be marked (score < 0.2).
local REAL_CHROME = {
    webdriver = false,
    cdp = false,
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " ..
         "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    languages = { "en-US", "en" },
    plugins = 5,
    mimeTypes = 2,
    chrome = true,
    webglVendor = "Google Inc. (NVIDIA)",
    webglRenderer = "NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0",
    hardwareConcurrency = 8,
    deviceMemory = 8,
    screenW = 1920,
    screenH = 1080,
    outerW = 1280,
    outerH = 800,
    timezoneOffset = -420,
    notification = "default",
    pdfViewer = true,
    touchPoints = 0,
}
local real_score = score_of(REAL_CHROME, { min_solve_ms = 250, solve_ms = 1200 })
truthy("real Chrome not marked (score < 0.2)", real_score < 0.2)
eq("real Chrome score is 0", real_score, 0)

-- Default Playwright/Puppeteer headless Chromium: must be marked.
local PLAYWRIGHT_HEADLESS = {
    webdriver = true,
    cdp = true,
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " ..
         "(KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36",
    languages = {},
    plugins = 0,
    mimeTypes = 0,
    chrome = false,
    webglVendor = "Google Inc. (Google)",
    webglRenderer = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) " ..
                    "(0x0000C0DE)), SwiftShader driver)",
    hardwareConcurrency = 2,
    deviceMemory = nil,
    screenW = 1280,
    screenH = 720,
    outerW = 0,
    outerH = 0,
    timezoneOffset = 0,
    notification = "denied",
    pdfViewer = false,
    touchPoints = 0,
}
local pw_score = score_of(PLAYWRIGHT_HEADLESS, { min_solve_ms = 250, solve_ms = 120 })
truthy("default Playwright headless marked (score >= 0.9)", pw_score >= 0.9)
truthy("default Playwright headless above default block threshold", pw_score >= 0.60)

-- Medium: no direct automation flag, but empty plugin surface + software WebGL.
local MEDIUM = {
    webdriver = false,
    cdp = false,
    ua = REAL_CHROME.ua,
    languages = { "en-US" },
    plugins = 0,
    mimeTypes = 0,
    chrome = true,
    webglVendor = "Google Inc. (Google)",
    webglRenderer = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)",
    hardwareConcurrency = 4,
    screenW = 1920,
    screenH = 1080,
    outerW = 1280,
    outerH = 800,
}
local medium_score = score_of(MEDIUM, { min_solve_ms = 250, solve_ms = 1200 })
truthy("correlated headless surfaces block (>= 0.60)", medium_score >= 0.60, medium_score)

-- A single weak surface (empty plugin list, hardware WebGL, PDF enabled) must
-- not be enough on its own.
local SINGLE_WEAK = {
    webdriver = false, cdp = false, ua = REAL_CHROME.ua,
    languages = { "en-US" }, plugins = 0, mimeTypes = 0, chrome = true,
    webglVendor = "Google Inc. (NVIDIA)",
    webglRenderer = "NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0",
    hardwareConcurrency = 8, screenW = 1920, screenH = 1080,
    outerW = 1280, outerH = 800, pdfViewer = true,
}
local single_score = score_of(SINGLE_WEAK, { min_solve_ms = 250, solve_ms = 1200 })
truthy("single weak surface < suspect", single_score < 0.35, single_score)

-- Strix's default sandbox browser (containers/Dockerfile, agent-browser):
-- normal Chrome UA, --disable-blink-features=AutomationControlled (webdriver
-- false), empty plugin surface, SwiftShader rasterizer, PDF viewer disabled.
local STRIX = {
    webdriver = false, cdp = false,
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 " ..
         "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    languages = { "en-US" }, plugins = 0, mimeTypes = 0, chrome = true,
    webglVendor = "Google Inc. (Google)",
    webglRenderer = "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)",
    hardwareConcurrency = 4, screenW = 800, screenH = 600,
    outerW = 800, outerH = 600, pdfViewer = false,
}
local strix_score = score_of(STRIX, { min_solve_ms = 250, solve_ms = 1200 })
truthy("Strix default headless profile blocked (>= 0.60)", strix_score >= 0.60, strix_score)

-- Client Hints consistency (server-side signals passed via opts).
local ch_ok = score_of(REAL_CHROME, {
    min_solve_ms = 250, solve_ms = 1200,
    sec_ch_ua = 'Chromium";v="120", "Google Chrome";v="120', scheme = "https" })
eq("matching Client Hints keep real Chrome at 0", ch_ok, 0)
local ch_bad = score_of(REAL_CHROME, {
    min_solve_ms = 250, solve_ms = 1200,
    sec_ch_ua = 'Chromium";v="140", "Google Chrome";v="140', scheme = "https" })
truthy("mismatched Client Hints add signal (>= 0.2)", ch_bad >= 0.2, ch_bad)
local ch_missing_https = score_of(REAL_CHROME, {
    min_solve_ms = 250, solve_ms = 1200, scheme = "https" })
truthy("missing Client Hints on HTTPS add signal", ch_missing_https >= 0.1)
local ch_missing_http = score_of(REAL_CHROME, {
    min_solve_ms = 250, solve_ms = 1200, scheme = "http" })
eq("missing Client Hints on plain HTTP is not penalised", ch_missing_http, 0)

-- Real browsers with HARDWARE GPUs that report ANGLE / Mesa renderer strings
-- (the normal Chrome/Edge strings on Windows/macOS, and Mesa on Linux) must
-- stay at 0: "ANGLE" and "Mesa" are not software rasterizers.
local function with(base, overrides)
    local t = {}
    for k, v in pairs(base) do t[k] = v end
    for k, v in pairs(overrides) do t[k] = v end
    return t
end
local GOOD = { min_solve_ms = 250, solve_ms = 1500 }
eq("Windows Chrome with ANGLE/D3D11 hardware renderer scores 0", score_of(with(REAL_CHROME, {
    webglVendor = "Google Inc. (NVIDIA)",
    webglRenderer = "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 (0x00002503) Direct3D11 vs_5_0 ps_5_0, D3D11)",
}), GOOD), 0)
eq("macOS Chrome with ANGLE Metal renderer scores 0", score_of(with(REAL_CHROME, {
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    webglVendor = "Google Inc. (Apple)",
    webglRenderer = "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)",
}), GOOD), 0)
eq("Linux Chrome with Mesa Intel hardware driver scores 0", score_of(with(REAL_CHROME, {
    ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    webglVendor = "Google Inc. (Intel)",
    webglRenderer = "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)",
}), GOOD), 0)

-- Mobile browsers legitimately have no plugins/MIME types/PDF viewer, and
-- Android WebView (Instagram/Facebook/TikTok/LINE in-app browsers) has no
-- window.chrome. None of these may reach the suspect threshold.
local ANDROID_CHROME = {
    webdriver = false, cdp = false,
    ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) " ..
         "Chrome/124.0.0.0 Mobile Safari/537.36",
    languages = { "id-ID", "id", "en-US" },
    plugins = 0, mimeTypes = 0, chrome = true,
    webglVendor = "Google Inc. (Qualcomm)",
    webglRenderer = "ANGLE (Qualcomm, Adreno (TM) 740, OpenGL ES 3.2)",
    hardwareConcurrency = 8, deviceMemory = 8,
    screenW = 412, screenH = 915, outerW = 412, outerH = 839,
    pdfViewer = false, touchPoints = 5,
}
local ch124 = { min_solve_ms = 250, solve_ms = 1500,
                sec_ch_ua = '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                scheme = "https" }
local android_score = score_of(ANDROID_CHROME, ch124)
truthy("Android Chrome (ANGLE, no plugins, no PDF viewer) below suspect", android_score < 0.35, android_score)
local WEBVIEW = with(ANDROID_CHROME, {
    ua = "Mozilla/5.0 (Linux; Android 13; SM-A536E; wv) AppleWebKit/537.36 (KHTML, like Gecko) " ..
         "Version/4.0 Chrome/124.0.0.0 Mobile Safari/537.36 Instagram 330.0.0.40.92 Android",
    chrome = false,
})
local webview_score = score_of(WEBVIEW, ch124)
truthy("Android WebView in-app browser below suspect", webview_score < 0.35, webview_score)
truthy("Android WebView without Client Hints still below block",
       score_of(WEBVIEW, { min_solve_ms = 250, solve_ms = 1500, scheme = "https" }) < 0.60)
local IPHONE = {
    webdriver = false, cdp = false,
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 " ..
         "(KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    languages = { "id-ID" }, plugins = 0, mimeTypes = 0, chrome = false,
    webglVendor = "Apple Inc.", webglRenderer = "Apple GPU",
    hardwareConcurrency = 4, screenW = 390, screenH = 844, outerW = 390, outerH = 844,
    pdfViewer = false, touchPoints = 5,
}
eq("iPhone Safari scores 0", score_of(IPHONE, GOOD), 0)
-- A desktop headless browser that only spoofs a phone UA still renders with
-- SwiftShader and keeps its automation flags: it must still be caught.
local SPOOFED_PHONE = with(PLAYWRIGHT_HEADLESS, { ua = ANDROID_CHROME.ua })
truthy("headless Chromium spoofing an Android UA still blocked",
       score_of(SPOOFED_PHONE, { min_solve_ms = 250, solve_ms = 120 }) >= 0.60)
local SPOOFED_PHONE_NO_FLAGS = with(SPOOFED_PHONE, { webdriver = false, cdp = false })
truthy("SwiftShader + empty plugins behind a phone UA is at least suspect",
       score_of(SPOOFED_PHONE_NO_FLAGS, GOOD) >= 0.35)

-- Report missing / not a table -> high score.
truthy("nil report scores high", score_of(nil) >= 0.4)
truthy("string report scores high", score_of("nope") >= 0.4)
truthy("number report scores high", score_of(42) >= 0.4)

-- Impossible solve timing adds EXACTLY +0.30 versus a normal solve.
local fast_report = {}
for k, v in pairs(REAL_CHROME) do fast_report[k] = v end
fast_report.solve_ms = nil
local normal_solve = score_of(fast_report, { min_solve_ms = 250, solve_ms = 1200 })
local too_fast = score_of(fast_report, { min_solve_ms = 250, solve_ms = 249 })
local missing_solve = score_of(fast_report, { min_solve_ms = 250 })
truthy("fast solve delta is exactly +0.30", approx(too_fast - normal_solve, 0.30), too_fast - normal_solve)
truthy("missing solve delta is exactly +0.30",
       approx(missing_solve - normal_solve, 0.30), missing_solve - normal_solve)
eq("solve_ms == min is not penalized",
   score_of(fast_report, { min_solve_ms = 250, solve_ms = 250 }), normal_solve)
eq("solve_ms == min-1 is penalized",
   score_of(fast_report, { min_solve_ms = 250, solve_ms = 249 }), normal_solve + 0.30)

-- Clamping.
local pathological = {
    webdriver = true, cdp = true,
    ua = "HeadlessChrome/1.0 Electron/1.0 playwright",
    languages = {}, plugins = 0, mimeTypes = 0, chrome = false,
    webglVendor = "SwiftShader", webglRenderer = "llvmpipe Mesa ANGLE",
    hardwareConcurrency = 0, screenW = 0, outerW = 0, outerH = 0,
}
local path_score = score_of(pathological, { min_solve_ms = 250, solve_ms = 1 })
truthy("pathological clamped to <= 1", path_score <= 1, path_score)
truthy("pathological >= 0", path_score >= 0)
local empty_score = score_of({}, { min_solve_ms = 250, solve_ms = 5000 })
truthy("empty report score in [0,1]", empty_score >= 0 and empty_score <= 1)
truthy("empty report is at least suspect", empty_score >= 0.35)

-- Sparse-but-benign report must not cross the block threshold.
local sparse = { webdriver = false, cdp = false, ua = REAL_CHROME.ua,
                 languages = { "en-US" }, plugins = 5, mimeTypes = 2,
                 chrome = true, hardwareConcurrency = 8 }
truthy("sparse-but-benign report not blocked",
       score_of(sparse, { min_solve_ms = 250, solve_ms = 1200 }) < 0.35)

-- =============================================================================
-- v3 config defaults / clamping (env overridden deterministically)
-- =============================================================================
section("v3 config defaults and clamping")
do
    local real_getenv = os.getenv
    os.getenv = function() return nil end
    local cfg = C.load_challenge_config()
    eq("default headless mode", cfg.headless_mode, "mark")
    eq("default headless ttl", cfg.headless_ttl, 3600)
    eq("default headless block", cfg.headless_block, 0.60)
    eq("default headless suspect", cfg.headless_suspect, 0.35)
    eq("default min solve ms", cfg.min_solve_ms, 250)
    eq("GET fallback on by default in mark mode", cfg.get_fallback, true)

    local values = {
        AGENTWALL_HEADLESS_MODE = "BLOCK",
        AGENTWALL_HEADLESS_TTL = "1",
        AGENTWALL_HEADLESS_BLOCK = "5",
        AGENTWALL_HEADLESS_SUSPECT = "-1",
        AGENTWALL_POW_DIFF = "99",
        AGENTWALL_MIN_SOLVE_MS = "not-a-number",
    }
    os.getenv = function(name) return values[name] end
    cfg = C.load_challenge_config()
    eq("mode is case-insensitive", cfg.headless_mode, "block")
    eq("headless ttl clamped low", cfg.headless_ttl, 60)
    eq("headless block ratio clamped high", cfg.headless_block, 1)
    eq("headless suspect ratio clamped low", cfg.headless_suspect, 0)
    eq("pow diff still clamped 3..6", cfg.pow_diff, 6)
    eq("bad int env falls back to default", cfg.min_solve_ms, 250)
    eq("GET fallback auto -> off in block mode", cfg.get_fallback, false)
    values.AGENTWALL_GET_FALLBACK = "ON"
    eq("GET fallback can be forced on in block mode",
       C.load_challenge_config().get_fallback, true)
    values.AGENTWALL_GET_FALLBACK = "off"
    values.AGENTWALL_HEADLESS_MODE = "mark"
    eq("GET fallback can be forced off in mark mode",
       C.load_challenge_config().get_fallback, false)
    values.AGENTWALL_GET_FALLBACK = "garbage"
    eq("unknown GET fallback value means auto",
       C.load_challenge_config().get_fallback, true)
    values.AGENTWALL_GET_FALLBACK = nil
    values.AGENTWALL_HEADLESS_MODE = "BLOCK"

    values.AGENTWALL_HEADLESS_MODE = "wat"
    values.AGENTWALL_HEADLESS_TTL = "999999999"
    cfg = C.load_challenge_config()
    eq("unknown mode falls back to mark", cfg.headless_mode, "mark")
    eq("headless ttl clamped high", cfg.headless_ttl, 86400 * 7)
    os.getenv = real_getenv
end

-- =============================================================================
-- summary
-- =============================================================================
print("")
print(string.format("SUMMARY: %d passed, %d failed, %d total", pass, fail, pass + fail))
if fail > 0 then
    os.exit(1)
end
os.exit(0)
