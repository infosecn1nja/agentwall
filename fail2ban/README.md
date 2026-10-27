# fail2ban — behavioural layer against autonomous LLM/AI pentest agents

The static WAF/rate-limit rules catch single noisy requests. fail2ban catches the
*behaviour* that is hardest to hide: **a single source that keeps
probing past 403/404/401/429** and **enumeration bursts**. It reads the proxy
access log, counts flagged responses per IP in a sliding window, and bans for a
bounded time.

Three jails ship here:

| Jail | File | What it does |
|------|------|--------------|
| `agentwall-behavior` | `jail.d/agentwall.local` | broad persistence/enumeration: many 4xx/429 in a short window |
| `agentwall-auth` | `jail.d/agentwall.local` | credential stuffing: 401/403 on auth routes |
| `agentwall-ml` | `jail.d/agentwall-ml.local` | **manual-ban jail** the ML scorer writes to — never auto-matches |

Tune `maxretry`/`findtime`/`bantime` to your real baseline before enabling —
start loose, watch `fail2ban-client status`, then tighten.

---

## 0) THE IP-SOURCE TRAP — read this before enabling anything

**fail2ban extracts `<HOST>` from the FIRST field of the access log**
(`nginx $remote_addr` / Apache `%a`). The ML scorer should normally read that
same first field. If XFF parsing is enabled (`--use-xff`), it now **requires**
`--trust-proxies` and walks the chain right-to-left, skipping trusted hops — the
left-most value is never trusted.

That mismatch is a foot-gun behind a CDN/L7 load balancer:

```
client 203.0.113.7 -> CDN -> your nginx (logs 198.51.100.23 = CDN)
```

- the scorer (with real_ip, no `--use-xff`) scores the first field — good;
- fail2ban sees only the first field **198.51.100.23** and bans the **CDN** —
  every user behind it is blocked, i.e. self-inflicted outage.

**Mandatory fix: recover the real client IP at the edge**, so the first field is
already the client:

```nginx
# nginx / OpenResty — set_real_ip_from MUST list only your CDN/LB ranges
real_ip_header    X-Forwarded-For;
set_real_ip_from  198.51.100.0/24;   # your CDN egress ranges
```

```apache
# Apache — waf/apache-agentwall.conf §5
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 198.51.100.0/24
```

Then in **Mode A** (recommended) the first log field is the real client, fail2ban
bans the right IP, and the scorer should be run **without** `--use-xff`. In
**Mode B** (no real_ip) fail2ban is **unsafe** — do not
point these jails at that log.

Also: your edge must **overwrite** (not blindly append) client-supplied XFF, and
the trusted-proxy list must be only CDN ranges. Otherwise anyone spoofs XFF and
chooses who gets banned.

> Do **not** put CDN ranges in `ignoreip` to "fix" this — that whitelists all
> traffic arriving via the CDN, attackers included. Fix `real_ip` instead.

`ignoreip` is for loopback + your own monitoring/scanner/office ranges; both
`agentwall.local` and `agentwall-ml.local` ship `ignoreip = 127.0.0.1/8 ::1` with a
placeholder comment for adding yours (per-jail, not `[DEFAULT]` — see below).

---

## 1) Filters

`filter.d/agentwall-behavior.conf` — any 400/401/403/404/429. On its own each is
normal; the jail threshold (many in a short window from one IP) is the signal.

```ini
[Definition]
failregex = ^<HOST> -.*"(?:GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS)[^"]*" (?:400|401|403|404|429)\s
ignoreregex =
```

`filter.d/agentwall-auth.conf` — only 401/403 on authentication routes. Map the path
group to your real auth + auxiliary/partner/recruitment endpoints.

```ini
[Definition]
failregex = ^<HOST> -.*"(?:GET|POST)[^"]*/(?:login|signin|auth|oauth|token|verify|otp|mfa|2fa|password/(?:reset|forgot))[^"]*" (?:401|403)\s
ignoreregex =
```

Both filters are anchored on the **combined-log leading fields**, so the
`agentwall` log format (`waf/nginx-agentwall.conf`,
`waf/apache-agentwall.conf` §6) keeps those fields first. The extra
`ua_flag=`/`probe=`/`rt=`/`xff="..."` tails after them do not affect the match.

`filter.d/agentwall-ml.conf` — deliberately **never matches**: the ML scorer bans
manually. It uses a valid-but-impossible regex instead of an empty one, because
fail2ban versions differ on empty `failregex` (some warn/error and refuse to
start the jail), plus `ignoreregex = .*` as a second belt so even a contrived
line can never auto-ban:

```ini
[Definition]
failregex = ^<HOST> - - \[[^\]]*\] "(?:GET|POST) /__agentwall_ml_never_match__ HTTP/[0-9.]+" 599\s
ignoreregex = .*
```

---

## 2) Jails

### Behavioural jails — `jail.d/agentwall.local`

```ini
# nginx default; Apache: /var/log/apache2/agentwall_access.log
logpath  = /var/log/nginx/agentwall_access.log

[agentwall-behavior]
enabled  = true
filter   = agentwall-behavior
logpath  = /var/log/nginx/agentwall_access.log
# 40 flagged responses within 60s from one IP = 30 min ban (== scorer block TTL)
maxretry = 40
findtime = 60
bantime  = 1800
bantime.increment = true
bantime.factor    = 2
bantime.maxtime   = 1d
ignoreip = 127.0.0.1/8 ::1
# fail2ban >= 0.11 on nftables hosts:
#banaction = nftables-multiport

[agentwall-auth]
enabled  = true
filter   = agentwall-auth
logpath  = /var/log/nginx/agentwall_access.log
maxretry = 10
findtime = 120
bantime  = 1800
bantime.increment = true
ignoreip = 127.0.0.1/8 ::1
```

- **`backend = auto`** (fail2ban default): uses pyinotify/gamin when available,
  else polling. Don't force `polling` unless you must.
- **`bantime` ≡ the scorer's `--block-ttl` (Redis `agentwall:block:*` TTL, default
  1800s).** If a fail2ban ban is longer than the Redis block, the IP stays
  packet-banned after the Lua would have let it back in — and vice versa. Change
  both together. `bantime.increment` escalates repeat offenders up to `maxtime`.
- **Syntax gotcha (validated on fail2ban 0.11.2 and 1.0.2):** fail2ban does
  **not** strip a trailing `#` comment from an option line — only `;` is an
  inline comment. `maxretry = 40  # reason` is parsed as a string, which logs
  `Wrong value for 'maxretry'` and silently falls back to the default
  `3/600/600`; nested jails can even fail to start (`int(None)`). Keep all `#`
  comments on their own lines. `deploy/validate-linux.sh` asserts the effective
  values (`40/60/1800`, `10/120/1800`, `9999/10/1800`) and that all three jails
  load.
- **`ignoreip` per jail, not `[DEFAULT]`:** files in `jail.d/*.local` load last,
  so a `[DEFAULT] ignoreip` here would silently override the operator's own
  setting in `jail.local`. Append your monitoring/scanner/office CIDRs on each
  jail's line.
- **nftables:** fail2ban ≥ 0.11 ships `nftables-multiport`; on an nftables host
  set it per jail and verify rules land in `nft list ruleset` (not iptables).

### Manual-ban jail — `jail.d/agentwall-ml.local`

```ini
[agentwall-ml]
enabled   = true
filter    = agentwall-ml
backend   = auto
logpath   = /var/log/nginx/agentwall_access.log
maxretry  = 9999        # never auto-ban: bans come only from the scorer
findtime  = 10
bantime   = 1800        # == scorer --block-ttl
bantime.increment = true
bantime.maxtime   = 1d
ignoreip  = 127.0.0.1/8 ::1
banaction = iptables-multiport      # nftables: nftables-multiport
```

`maxretry = 9999` plus the never-matching filter means the jail produces **no**
automatic bans; it only exists as the target for the scorer's `banip` calls.
`logpath` must exist and be readable by the fail2ban daemon (root) or the jail
fails to start.

---

## 3) How the ML scorer's manual bans work

The scorer acts on a source IP only when run with `--enforce`, e.g.:

```bash
python3 agentwall_scorer.py --log /var/log/nginx/agentwall_access.log \
    --enforce --backend fail2ban --jail agentwall-ml
```

Each block runs:

```bash
fail2ban-client set agentwall-ml banip <ip>
```

The process must be allowed to run that as root. The systemd unit runs as
`User=agentwall`, so without help the call fails with a permission error. Options:

1. **`--fail2ban-sudo` (recommended):** the scorer prefixes the call with
   `sudo -n` (non-interactive — a password prompt would hang it) and
   `deploy/sudoers.d-agentwall` allows **exactly** this command, nothing else:
   ```
   Cmnd_Alias AGENTWALL_ML_BAN = /usr/bin/fail2ban-client set agentwall-ml banip *
   agentwall ALL=(root) NOPASSWD: AGENTWALL_ML_BAN
   ```
   Install:
   ```bash
   sudo install -m 0440 deploy/sudoers.d-agentwall /etc/sudoers.d/agentwall-ml
   sudo visudo -cf /etc/sudoers.d/agentwall-ml
   ```
   If `fail2ban-client` is not at `/usr/bin/fail2ban-client`, pass
   `--fail2ban-cmd /path/to/fail2ban-client` (or `AGENTWALL_FAIL2BAN_CMD`) **and**
   update the path in the sudoers rule to match exactly.

2. **Run the scorer as root** — simplest but least privilege; the scorer only
   needs logs + Redis, so prefer option 1.

> **systemd gotcha:** the shipped unit sets `NoNewPrivileges=true`, which blocks
> setuid binaries — **`sudo` will fail**. For `--fail2ban-sudo` you must set
> `NoNewPrivileges=false` on that unit (and keep the narrow sudoers rule as the
> privilege boundary). The **preferred backend is `--backend redis`** (no sudo):
> the Lua in the proxy reads `agentwall:block:*` and enforces inline. Use
> `--backend both` only if you understand both paths.

**IPv6:** the scorer normalizes IPv6 to a **/64 network key** for Redis (the Lua
reads the same `/64` key). For fail2ban it deliberately passes the **raw client
address** to `banip` (banning the /64 network address would ban almost nobody),
but `banip` still bans **one address** — so an attacker rotating inside one /64
evades per-address bans. If you enforce IPv6 at the edge, prefer the Redis
backend or add an explicit `ip6tables`/nftables rule for the /64.

---

## 4) Install without breaking an existing fail2ban

These files are drop-ins; do not overwrite `jail.local`:

```bash
sudo install -m 0644 fail2ban/filter.d/agentwall-behavior.conf /etc/fail2ban/filter.d/
sudo install -m 0644 fail2ban/filter.d/agentwall-auth.conf     /etc/fail2ban/filter.d/
sudo install -m 0644 fail2ban/filter.d/agentwall-ml.conf       /etc/fail2ban/filter.d/
sudo install -m 0644 fail2ban/jail.d/agentwall.local           /etc/fail2ban/jail.d/
sudo install -m 0644 fail2ban/jail.d/agentwall-ml.local        /etc/fail2ban/jail.d/
sudo fail2ban-client -t          # config test: must say OK
sudo fail2ban-client reload
```

If you already run fail2ban elsewhere, check `fail2ban-client -t` output for
conflicts and mirror only what you need. `jail.d/*.local` overrides
`jail.conf`/`jail.local`.

---

## 5) Verify (do not trust a jail you have not tested)

```bash
# 1) config parses and jails exist
sudo fail2ban-client -t
sudo fail2ban-client reload
sudo fail2ban-client status
sudo fail2ban-client status agentwall-behavior
sudo fail2ban-client status agentwall-auth
sudo fail2ban-client status agentwall-ml

# 2) filter matches what you expect — on REAL log lines, BEFORE relying on it
sudo fail2ban-regex /var/log/nginx/agentwall_access.log /etc/fail2ban/filter.d/agentwall-behavior.conf
sudo fail2ban-regex /var/log/nginx/agentwall_access.log /etc/fail2ban/filter.d/agentwall-auth.conf
# manual-ban filter: expect 0 matched lines
sudo fail2ban-regex /var/log/nginx/agentwall_access.log /etc/fail2ban/filter.d/agentwall-ml.conf

# 3) manual-ban path (what the scorer does) + confirm the ban is real
sudo fail2ban-client set agentwall-ml banip 203.0.113.7
sudo fail2ban-client status agentwall-ml          # Banned IP list: 203.0.113.7
sudo iptables -S | grep f2b                   # (nftables: sudo nft list ruleset | grep f2b)
sudo fail2ban-client set agentwall-ml unbanip 203.0.113.7

# 4) end-to-end: run the scorer with --enforce --backend fail2ban and watch for
#    "BLOCK ip=..." in its logs, then confirm the IP appears in `status agentwall-ml`.
#    Run deploy/preflight.sh for the automated go-live checks.

# 5) watch it work
sudo journalctl -u fail2ban -f
sudo fail2ban-client status agentwall-behavior
```

If a ban does not appear in the firewall, the jail may be using an action that
your firewall backend ignores — switch `banaction` (iptables vs nftables) and
retest step 3.

---

## 6) Tuning

- **Start loose.** Run in shadow first: enable the jails with a high `maxretry`
  (or `enabled = false`) and inspect `fail2ban-regex` counts + `status` for a
  few days. The ML scorer's dry-run (`BLOCK(dry-run)`) tells you which IPs *would*
  be banned before you let either layer act.
- **`findtime`/`maxretry`:** a burst is what you are measuring. 40 flagged 4xx in
  60s is deliberately conservative; tighten to your real noise floor once you
  know it. Auth abuse can be tighter (10 in 120s).
- **`bantime.increment`:** keeps repeat offenders out longer; cap with
  `bantime.maxtime`. Keep the base equal to the scorer's block TTL.
- **Allowlist aggressively:** monitoring, internal scanners, office/VPN egress,
  and known partner integrations belong in `ignoreip` (behavioural jails) and in
  the scorer's `--allowlist`/`--allowlist-file`. A false ban of your own
  monitoring is the most common self-inflicted outage.
- **Good bots:** verify via FCrDNS (the scorer does; fail2ban cannot) — a Googlebot
  IP that trips the jail is a real user-facing failure. Keep bot ranges out of
  the ban path.
- **After changing jails:** `fail2ban-client -t && fail2ban-client reload`; keep
  `fail2ban-regex` output as evidence the filter still matches.
- **Log lifecycle:** logrotate is fine; `backend = auto` handles rotation. If you
  use `backend = polling`, verify rotation is detected (no bans after truncate).

---

## Why this (and what it still can't do)

- **Catches:** the adaptive agent's refusal to stop after failures, and the
  enumeration fan-out — behaviour that survives UA/payload changes.
- **Doesn't catch:** a slow, low-and-wide run spread across many rotating source
  IPs (the guide warns IP-based blocking ages fast against rotating origins).
  That gap is closed at the SIEM layer with same-source multi-stage correlation
  (enumerate → probe → auth within one window), not at the reverse proxy.
- **Don't** drop unofficial "attacker IP lists" into permanent bans — rotating
  origins make them stale and risk false-blocking CDNs/shared ranges. Temporary,
  behaviour-triggered bans (above) + fast patching + MFA are what hold up.
