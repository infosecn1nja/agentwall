# Threat model

AgentWall is a defense-in-depth layer against **automated and agentic AI
penetration tooling**. This document states what it is expected to catch, what
it cannot, and how to measure whether it is working. It is intentionally
pessimistic — read it before deploying or filing a bypass report.

## Scope

**In scope**

- Automated scanners and LLM-driven agents probing an internet-facing web app:
  enumeration, injection probes, authentication abuse, persistence after
  errors, headless-browser automation.
- HTTP(S) traffic through the reverse proxy (or a CDN/LB in front of it).
- Operator tooling: configs, rollout, verdict store, observability, CI.

**Out of scope**

- Volumetric L3/L4 DDoS (use a scrubbing/CDN layer), TLS-termination flaws,
  supply-chain attacks on the proxy/OS, application business-logic bugs that
  require valid authenticated access.
- "No AI pentest can ever succeed" — no proxy stack provides that. The goal is
  to raise cost, catch noisy legs, and generate actionable signal while the
  application-level controls (MFA, authz, patching) close the durable gaps.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Application availability | over-blocking/fail-closed is itself an outage risk |
| Customer accounts/data | credential stuffing, IDOR/authz, enumeration |
| Verdict store (Redis) | decides who is blocked; a compromise is an availability risk |
| Clearance secrets | forging cookies bypasses the challenge |
| Access/audit logs | incident reconstruction |
| Scorer integrity | it is not in the request path, but bad verdicts cause FPs |

## Adversary profiles

| Profile | Capabilities | What AgentWall buys |
|---------|--------------|---------------------|
| Classic scanner | fixed UA, high rate, signature payloads | rate limits, UA/marker maps, fail2ban |
| LLM/agentic scanner | mutates payloads/UA, multi-stage, persists past errors | multistage/persistence signals, behaviour bans, telemetry |
| Distributed scanner | rotating IPs (residential/cloud), low-and-slow | partial (per-IP blind spot); needs SIEM correlation |
| Headless browser | solves JS/PoW, loads assets, posts real reports | headless environment detection (default Playwright/Puppeteer) |
| Stealth browser | patches webdriver/CDP/WebGL surfaces, spoofs report | mostly not caught; advisory only |
| Credential attacker | valid-looking auth requests | tight auth rate limits, auth jail, behavioural ML |
| Public AI agent (Strix default) | headless Chromium + Kali toolchain (nuclei/sqlmap/ffuf/…) | headless surface correlation (B16) + automation-UA/scanner blocking (F) |
| Public AI agent (ARTEX default) | `artex-enrich/1.0`, `norma/0.4`, tool-default attack traffic | immediate UA block + behavioural multistage/persistence |

## Trust boundaries

1. **Edge trust:** `real_ip` accepts client IPs only from configured CDN/LB
   ranges. If misconfigured, XFF spoofing can evade limits or cause bans of
   innocent IPs/CDNs.
2. **Client truth:** the headless report is client-supplied. It is scored, not
   trusted. The server overwrites `report.ua` with the actual request UA.
3. **Verdict store trust:** Redis is a control-plane component; private network,
   `requirepass`, TTL-only keys. Compromise implies enforcement tampering.
4. **Tooling trust:** `tests/e2e-real/` trusts all XFF and uses ephemeral
   credentials. Never deploy its config.

## Detection inventory

| Technique | Layer | Confidence |
|-----------|-------|------------|
| Rate/connection floods | nginx `limit_req/conn` | high for high-rate only |
| Enumeration bursts (4xx) | fail2ban `agentwall-behavior` | medium |
| Credential stuffing on auth routes | fail2ban `agentwall-auth` + scorer | medium |
| Persistence after 403/404/429 | scorer `persistence` feature | medium |
| Multi-stage within one window | scorer `multistage` (hard) | medium-high |
| Non-human session shape | scorer human-ness + population percentiles | medium |
| Explicit automation UA | nginx map + Lua UA check | low (spoofable) |
| Default Playwright/Puppeteer/headless Chromium | Lua report + timing | high for *default* headless |
| Stealth-patched browser | — | not caught |
| Distributed low-and-slow | — | not caught (SIEM gap) |

## Evasion paths (known, accepted)

- Rotating source IPs, especially IPv6 within a /64 (aggregation helps, but
  rotate across /64s).
- Low-and-slow request pacing below window thresholds; spread stages across
  windows/IPs.
- Signature evasion: custom UA, encoded/body-only payloads (WAF marker maps are
  coarse; CRS raises the bar but is also evadable).
- Solving the PoW with a real/headless browser; spoofing the headless report.
- Abusing `return`-phase locations or direct origin access if the origin is not
  firewalled to the edge.
- Staying under the ML threshold; slow baseline drift can teach an attack as
  normal (acknowledged streaming trade-off).

## Compensating controls

- Application: MFA, session binding, server-side authorization (anti-IDOR),
  per-account rate limits, fast n-day patching, reduced attack surface.
- Edge: CDN/bot management with TLS/HTTP fingerprinting, firewall origin to
  accept only the edge, managed WAF rules in blocking mode.
- Detection: SIEM correlation across rotating IPs and long windows, honeytokens,
  egress/DNS controls, retention for reconstruction.
- Process: rehearsed incident response, automatic blocking (no human approval
  loop for time-critical verdicts), red-team validation.

## Success metrics

Do not measure "AI blocked = 100%". Measure:

- **Detection rate** of noisy legs and headless automation in red-team tests.
- **Time to block** after first suspicious behavior (target: seconds-minutes).
- **False-positive rate** on known-good traffic during shadow (near zero before
  enforcing).
- **Attacker cost**: requests/IPs/time needed to stay under thresholds.
- **MTTD/MTTR** from alert to containment; residual vulnerabilities closed at
  the app layer.

## Validation methodology

1. Shadow mode on real traffic for a full weekly cycle (including peaks).
2. `tests/run-tests.sh` + `tests/e2e-real/run.sh` for behavior/contracts.
3. `deploy/validate-linux.sh` for OS-level config (systemd/fail2ban/Apache/nginx).
4. Authorized adversarial exercise (scope + allowlist agreed): default
   Playwright/Puppeteer, then stealth-patched, then distributed/low-and-slow.
   Record what is caught, what is not, and the FP impact.
5. Rotate secrets after the exercise; review `agentwall_headless_total`,
   block/challenge ratios and support tickets.

Source-derived default profiles for **Strix** and **ARTEX** are shipped in
`tests/e2e-real/` (see [AGENT-VALIDATION.md](AGENT-VALIDATION.md)). They emulate
the defaults visible in the upstream source — they are not full LLM runs, and
UA rotation/stealth tooling remain documented limits.

## Reporting

Private security reports: [SECURITY.md](../SECURITY.md). Documented limits above
are intentional; send improvements as a discussion with a concrete proposal.
