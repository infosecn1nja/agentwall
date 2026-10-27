# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue:

1. Open a [GitHub private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
   for this repository (Security → Advisories → "Report a vulnerability"), or
2. Contact the maintainers through the repository's listed security contact.

Include: affected file/version, a minimal reproduction (sanitized logs),
impact, and whether the issue is in the shipped config, the Lua challenge
layer, the scorer, or the tooling. Do not include real client IPs, cookies,
keys or customer data.

We aim to acknowledge within 5 business days and to agree on a disclosure
timeline (default 90 days) after triage. There is no bug bounty.

## Scope and design limits

AgentWall is a **cost/detection/response** layer, not a guarantee. The
following are documented design characteristics, not vulnerabilities (see
[docs/THREAT-MODEL.md](docs/THREAT-MODEL.md)):

- Per-IP controls can be evaded by distributed/rotating sources; low-and-slow
  traffic can stay under windows.
- The headless/automation report is client-provided and can be spoofed by
  stealth-patched browsers; it is advisory signal.
- All enforcement fails **open** on Redis/scorer outages by design.
- Signature-style markers (UA, query patterns) are trivially evaded; they are
  supporting signals.
- `tests/e2e-real/` trusts all `X-Forwarded-For` values (test-only) and must
  never be deployed as a production config.
- fail2ban bans one address; rotating inside an IPv6 /64 is only aggregated on
  the Redis/Lua path, not by fail2ban.

Reports that a documented design limit exists are welcome as **discussions**
with a concrete improvement proposal. Reports that a documented protection is
bypassed on a real deployment (for example: a block key does not produce 403,
a clearance cookie is forgeable, an effective fail2ban option is silently
ignored, secrets leak into logs) are in scope.

## Deploying safely

- Start in dry-run (`mark` headless mode), baseline, then enforce.
- Keep `real_ip`/`mod_remoteip` trusted ranges correct; a wrong edge config can
  cause fail2ban to ban your CDN.
- Generate secrets with `deploy/gen-secrets.sh` (mode 0600); never commit them.
- Keep the metrics endpoint on loopback/private networks.
- Rebuild and re-run the full gates (`tests/run-tests.sh`, `tests/e2e-real`,
  `deploy/validate-linux.sh`) when upgrading dependencies.

## Supported versions

| Version | Status |
|---------|--------|
| 0.1.x   | Supported (current public line) |
| < 0.1   | Pre-release snapshots, unsupported |
