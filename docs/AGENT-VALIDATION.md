# Agent-default validation (Strix & ARTEX)

> **Authorization warning.** Only run these profiles against systems you own or
> have written permission to test. The profiles below are *traffic emulations
> derived from public source code*; the real agents were **not** executed against
> any external system in this repository's test suite.

AgentWall's primary detection is behavioural. This document records how the
shipped tests map **default traffic profiles of two public AI-pentest agents** to
AgentWall controls, and what remains out of scope.

| Agent | Source | What we derive from it |
|-------|--------|------------------------|
| **Strix** | <https://github.com/usestrix/strix> (Apache-2.0) | sandbox browser flags/UA, scanner toolchain defaults |
| **ARTEX** | <https://github.com/jiwoochris/artex-global> (AGPL-3.0; detection/defense guide only) | enrichment/WebFetch/self-update UAs, tool-default attack traffic |
| **CyberStrikeAI** | <https://github.com/aipentest/cyberstrikeai> | default WebShell/FOFA User-Agents, Kali-tool defaults, OOB (dnslog) verification |

> **Behaviour over signatures.** The UA/tool lists below are a cheap first cut
> that any operator can rotate away. The durable controls against all three
> agents are the **edge behavioural layer** (`nginx-lua/agentwall_behavior_log.lua`:
> OOB-callback → block, probe/4xx-enumeration/credential-stuffing bursts →
> block/challenge, scripted-client header inconsistency) and the out-of-band
> scorer. Those act on the *pattern*, not the name, and are what the e2e
> `G1–G6` assertions exercise.

No upstream code or rule files are copied into this MIT project. Only public
observable facts (UA strings, launch flags, documented tool names) are used to
build independent emulations; source links are provided for verification.

## Strix

From `containers/Dockerfile` (sandbox image) and `docs/tools/browser.mdx`:

- Headless Chromium via `agent-browser`, launched with
  `AGENT_BROWSER_USER_AGENT` = a **normal Chrome/131 UA** and
  `--disable-blink-features=AutomationControlled` (so `navigator.webdriver` is
  false). All browser traffic is proxied through Caido.
- Kali toolchain installed: `nmap`, `sqlmap`, `nuclei`, `subfinder`, `naabu`,
  `ffuf`, `dirsearch`, `wafw00f`, `arjun`, ProjectDiscovery `httpx`/`katana`,
  `gospider`, `interactsh-client`, plus curl/python.

How AgentWall sees that:

| Strix behaviour | AgentWall control | Test |
|-----------------|-------------------|------|
| Headless Chromium with normal Chrome UA, empty plugin surface, SwiftShader, PDF viewer disabled | Correlated headless score (`plugins=0` + software WebGL + PDF disabled, even with `webdriver=false`) → `agentwall:headless` marker → 403 | `B16–B17` |
| `nuclei`, `sqlmap`, `ffuf`, `nmap`, `dirsearch`, `wafw00f`, `arjun`, `katana`, `subfinder`, `naabu`, `gospider`, `interactsh`, `nikto`, `gobuster`, `feroxbuster`, `wpscan`, `masscan`, `zgrab`, `httpx` defaults | Server-side automation-UA check (immediate 403 in `block` mode) + WAF UA map + scorer UA hard signal | `F1–F22` |
| Caido proxy | Does not change the target-side UA; the UA/behavior checks still apply | — |
| Generic `curl` / Python `httpx` (also used by legitimate clients) | **Not** blocked by UA (false-positive controls) — the behavioural layer (enumeration bursts, 4xx persistence, multi-stage) is what catches it | `F0b–F0c` |
| Real user-like navigation | Allowed | `F0` |

## ARTEX

From the repository's source and its [defense & detection guide](https://github.com/jiwoochris/artex-global/blob/main/docs/defense-en.md):

- `enrich/enrich.go` sends asset-enrichment GETs with UA **`artex-enrich/1.0`**
  (no redirects, keep-alive disabled, reads the title).
- Worker WebFetch (via the `norma` SDK) carries **`norma/0.4`**.
- `selfupdate/` uses **`artex-selfupdate`** (egress only, not target traffic).
- Attack traffic uses the **real tools' default UAs** (Bash: nmap, nuclei,
  sqlmap, ffuf, curl, …) and has **no ARTEX-specific UA**. ARTEX injects
  `HTTP_PROXY`/CA vars into tools but does not force a UA.
- No built-in rate limit; 3 workers per task run in parallel; it persists past
  403/404/429 and re-targets.

How AgentWall sees that:

| ARTEX behaviour | AgentWall control | Test |
|-----------------|-------------------|------|
| `artex-enrich/1.0` enrichment GETs | Immediate 403 (automation UA) + `agentwall:headless` marker | `F1` |
| `norma/0.4` WebFetch | Immediate 403 | `F2` |
| `artex-selfupdate` (egress IoC, not target-side) | Documented only; not target-scope | — |
| Tool-default attack traffic (nuclei/sqlmap/ffuf/nmap/…) | Immediate 403 (UA) + behavioural scoring | `F4–F22` |
| Enumeration → probe → auth, persistence past 4xx | Scorer `multistage` hard signal, fail2ban behavioural jail, per-key windows | `D1–D11` |
| UA rotated by the operator | Behaviour layer remains; static signature is explicitly *supporting only* | documented limit |

ARTEX's own detection material also states the durable signal is **behaviour**,
not the UA. AgentWall follows the same principle: the UA lists are a cheap first
cut, and the scorer/fail2ban layer is what catches rotated tooling.

## CyberStrikeAI

From the repository source (`internal/handler/webshell.go`,
`internal/handler/fofa.go`, `tools/*.yaml`):

- WebShell interaction GET/POSTs default to **`Mozilla/5.0 (compatible;
  CyberStrikeAI-WebShell/1.0)`**; the FOFA search client sends
  **`CyberStrikeAI/1.7.4`**. Both carry the `cyberstrikeai` token.
- Attack traffic otherwise runs the **real tools' defaults** (nuclei, sqlmap,
  ffuf, katana, dirsearch, nmap, masscan, gobuster, wafw00f, hydra, …) — the
  same defaults already covered for Strix/ARTEX.
- Blind-vuln verification uses an OOB **dnslog** helper (`tools/dnslog.yaml`,
  `dnslog.cn`), the canonical interaction-callback pattern.

How AgentWall sees that:

| CyberStrikeAI behaviour | AgentWall control | Test |
|-------------------------|-------------------|------|
| `CyberStrikeAI-WebShell/1.0` / `CyberStrikeAI/1.7.4` UAs | `cyberstrikeai` UA marker: immediate 403 (block mode) + scorer hard signal + WAF map | `F23–F24`, Lua `is_automation_ua` |
| dnslog / OOB callback in a request it induces the target to make | `is_oob_callback` → edge behavioural **block**; scorer `OOB_RE` hard signal | `G1–G2` |
| nuclei/sqlmap/ffuf/katana/… defaults | UA markers + behavioural scoring | `F4–F22` |
| Enumeration → probe → persistence past 4xx | Edge 4xx-burst challenge; scorer `multistage` hard signal; fail2ban | `G3–G5`, `D1–D11` |
| WebShell/C2 beaconing on a fixed interval | Out of HTTP scope here — detect at the host/EDR and egress layer | documented limit |

## Shipped test evidence

`tests/e2e-real/run.sh` contains the source-derived profiles and asserts:

```
D1b spoofed xff=127.0.0.1 did not become the verdict key        PASS
B16 Strix default sandbox browser profile blocked (403)          PASS
B17 Strix profile marked headless                                PASS
F0  normal browser UA allowed                                    PASS
F0b python-httpx library allowed (false-positive control)        PASS
F0c ordinary curl UA allowed (false-positive control)            PASS
F1–F22  ARTEX + Strix scanner/agent default UAs blocked (403)    PASS
F23–F24  CyberStrikeAI WebShell/FOFA UAs blocked (403)            PASS
G1–G6  edge behavioural prevention (OOB/probe/4xx/auth/header)    PASS
RESULT: PASS=72 FAIL=0
```

The same stack is also exercised against real Redis + OpenResty + the real
scorer (river model), including block/challenge/clearance and IPv6 `/64`.

## What this does **not** prove

- **Not a full agent run.** A complete Strix/ARTEX campaign needs an LLM API
  key, Docker sandbox, and an authorized target. The profiles above reproduce
  the *observable defaults* documented in the upstream source, not the LLM's
  adaptive decisions.
- **UA rotation / custom toolchains** defeat the static signatures (they are
  supporting signals; behaviour scoring remains).
- **Stealth browsers** can patch the plugin/WebGL/PDF surfaces; the correlated
  score is a signal, not proof of humanity.
- **Distributed low-and-slow** remains a SIEM/correlation problem
  ([THREAT-MODEL.md](THREAT-MODEL.md)).

## Running an authorized real-agent validation

1. Use an isolated lab target you own (never a third party), behind AgentWall.
2. Allowlist the agent host IP in `--allowlist`/fail2ban `ignoreip` if you want
   to observe phases without packet bans (optional; remove for enforcement).
3. Start AgentWall in `mark` mode first; capture `agentwall_headless_total`,
   `agentwall_challenge_total`, `agentwall_block_total`, and error-log WARN lines.
4. Run the agent with a tight scope; record which requests were challenged,
   blocked, or passed.
5. Repeat with `AGENTWALL_HEADLESS_MODE=block` and `--enforce --backend redis`.
6. Rotate secrets and clean lab credentials afterwards.

Report improvements as an issue/discussion; **do not** include third-party
targets, real client data, or secrets.
