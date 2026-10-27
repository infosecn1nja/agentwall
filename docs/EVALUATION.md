# Evaluation

This document answers three questions with the current code and a reproducible
multi-seed benchmark:

1. What is the new mechanism (formula, state, transition rules)?
2. Does it lower false positives or detect faster at the same compute cost?
3. Does the combination exceed the sum of WAF + anomaly detector + browser challenge?

**Bottom line (after the fixes below):**

- **Mechanism:** a composite design plus a concrete learning-policy fix — only
  human-like, non-hard events update the online model and the population
  percentile. This prevents an attacker from teaching the model that its own
  traffic is normal.
- **Effect:** full-stack recall rises from **28.1% (WAF-only) to 40.5%** with
  **0 benign blocks, 0 benign challenges**, and **+26 attack keys found after
  WAF**. A separate benign stress gate (7 adversarial-benign families, **2,610
  benign key-seeds**) also measured **0 false blocks, 0 benign challenges, 0
  challenge failures** at production defaults. But it costs ~**25×** the WAF-only
  CPU and is **not faster**; both WAF and full measured 0 FPs, so this is a
  safety result, not evidence of better FP reduction.
- **Combination:** at an **equal benign-challenge budget (0%)**, full is the best
  strategy (40.5% vs 28.1%). Challenge-only/union have higher raw recall
  (78.6%/81.9%) but challenge **100%** of benign keys and make **10.3%** of
  them fail; that violates an equal-disruption comparison. So the combination
  beats its components at equal user disruption, but is not super-additive in
  raw recall and still misses distributed low-and-slow and spoofed-human
  headless agents.

These are synthetic results; see §2.5 for what would make them production
evidence.

Reproduce (real river dependency):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
bash benchmarks/run.sh          # 3 seeds + aggregation
# or: python benchmarks/agentwall_bench.py
```

Artifacts: [`benchmarks/RESULTS.md`](../benchmarks/RESULTS.md),
[`benchmarks/results.json`](../benchmarks/results.json).

---

## 1. Mechanism: formula, state, transitions

### 1.1 State

| State | Representation | Lifetime |
|---|---|---|
| Per-key window | deque of parsed events (path/status/auth/probe/UA flags/human-ness inputs), 60 s | idle eviction / LRU cap |
| Online model | `river.anomaly.HalfSpaceTrees` (10 trees, height 8, window 250): fixed nodes + left/right mass counters | checkpointed atomically |
| Population | rolling deque of suspicion scores (4000) + cached P95/P99 | process |
| Challenge | Redis `agentwall:chal:<id> = <ip_key>\|<issued_ms>`, single-use, TTL 180 s; `agentwall:challenge:<ip_key>` TTL 600 s | TTL |
| Clearance/automation | HMAC-SHA1 IP-bound cookie + Redis `agentwall:cleared:<key>` / `agentwall:headless:<key>` | TTL 600 s / 3600 s |
| Enforcement | Redis `agentwall:block:<key>` TTL 1800 s read by OpenResty | TTL |

### 1.2 Formulas

Features per key/window:

```
x = { req_rate, miss_ratio, deny_ratio, auth_ratio, uniq_ratio, path_entropy,
      nonstatic_ratio, probe_ratio, regularity, persistence, ua_flag_ratio,
      multistage }
```

Human-ness (`web`; `api` re-weights static/referer to 0 and clean to 0.8):

```
H = 0.45·static + 0.25·referer + 0.20·browser + 0.10·(1−miss)
    − 0.50·tool − 0.30·probe,  clamped [0,1]
```

Suspicion and population cutoffs:

```
S = 0.6·Anomaly(x)·(1−H) + 0.4·(0.3·persistence + 0.3·probe
                               + 0.2·miss + 0.2·multistage)
C_block = max(0.55, Q99(buffer))
C_watch = max(0.40, Q95(buffer))
```

**Learning policy (new fix):** only events with `H ≥ human_floor` and no hard
signal update the HST and the population buffer:

```
if (not hard) and H >= human_floor:
    model.learn_one(x)
    pop.update(S)
```

Scoring still happens on every event; attack traffic can trigger hard signals,
absolute floors and the challenge, but cannot move the model or the percentile.
This closes two evasion paths found by tracing the benchmark:

- **model poisoning:** online `learn_one` on every event made repeated headless
  traffic familiar (anomaly fell from 0.92 to 0.35 within the same key);
- **percentile poisoning:** high-scoring attack events raised P99 from ~0.12 to
  0.648, above the headless key's 0.59 suspicion, suppressing the challenge.

Headless verification score (server-side, client report + timing + Client Hints):

```
headless = 0.50·webdriver + 0.50·cdp + 0.60·headlessUA + 0.40·automationUA
         + 0.20·(plugins==0 ∧ mime==0 ∧ browserUA)
         + 0.25·(chrome==false ∧ chromeUA) + 0.20·softwareWebGL
         + 0.25·(plugins==0 ∧ mime==0 ∧ softwareWebGL)   # correlated
         + 0.15·(pdfViewer==false ∧ plugins==0)
         + 0.15·emptyLanguages + 0.20·outerGeometryAnomaly
         + 0.30·solve_ms<min_solve_ms
         + 0.25·ClientHintsVersion≠UA/Chrome version
         + 0.15·noClientHints on HTTPS
```

Block if `≥0.60` (writes `agentwall:headless`), log-only if `≥0.35`.

### 1.3 Transitions (per key)

| From | Event | To |
|---|---|---|
| allow | `H ≥ human_floor` | allow |
| allow/watch | `S ≥ C_block`, `H < human_floor`, cooldown elapsed | **challenge** |
| allow/watch | `S ≥ C_watch`, cooldown elapsed | watch |
| any | hard signal, cooldown elapsed | **block** |
| challenge | grace elapsed and still `S ≥ C_block` (or hard) | **block** |
| challenge | valid PoW + human report | **cleared** (cookie + cleared key; non-hard blocks suppressed) |
| challenge | automation report (`headless ≥0.60`) | block + `agentwall:headless` |
| block | TTL expiry / operator delete | allow |

All enforcement paths fail open on Redis/scorer faults; configuration faults are
CRIT-visible.

### 1.4 What is different from prior anti-bot?

Not a new primitive. Rate limits, WAF signatures, PoW, JS challenges,
HMAC/IP-bound cookies and online anomaly detectors predate this project. The
differences are:

1. Per-key session-shape anomaly feeding a graduated verdict.
2. Population percentiles with absolute floors **plus** a human-ness floor.
3. Verified challenge whose browser-environment report becomes a durable Redis
   marker read by the scorer (challenge ↔ ML state sharing both ways).
4. One TTL verdict store shared by the edge (Lua) and optional packet bans
   (fail2ban), with cooldowns/grace and instant rollback.
5. **Learning separation** (new): model/population only learn from human-like,
   non-hard traffic, so repeated attack traffic cannot normalise itself.

Whether this composition is useful is empirical; the benchmark below shows a
real recall gain at equal disruption, but not free.

## 2. Controlled benchmark

Synthetic, labelled stream; **model training and evaluation use different RNG
seeds**; three evaluation seeds; thresholds are production defaults (no test-set
tuning). 42,795 evaluation events + 6,000 baseline per seed; 970 benign keys
(including 100 non-JS API clients) and 210 attack keys.

Families: browser users, flash crowd, power users, non-JS API clients; fast
scanner, HTTP agent (ARTEX-like), slow browser-like agent; headless enumeration
(default automation report), spoofed-human headless; encoded probes that the raw
WAF map cannot see; distributed low-and-slow (4 requests/rotating IP).

Strategies:

| Strategy | Definition |
|---|---|
| `waf-only` | static UA/marker filter + nginx-like rate/4xx thresholds |
| `anomaly-only` | real HST, fixed threshold 0.80, learns every event, no gating |
| `challenge-only` | JS challenge every new key; JS clients pass, non-JS fail, automated reports block |
| `agentwall-full` | WAF + HST + human floor + benign-only learning/population + hard signals + targeted challenge/headless |
| `union-naive` | OR of WAF/anomaly/challenge |
| ablations | full without human floor / hard signals / headless verification / WAF |

Detectors never read the ground-truth labels. Labels are used only to compute
metrics; JS capability/report outcome is a modelled *environment response* after
the detector acts (like a real browser/client would answer).

### 2.1 Multi-seed results (mean [min-max])

Full table: [`benchmarks/RESULTS.md`](../benchmarks/RESULTS.md).

| Strategy | False block | Benign challenged | Challenge failure | Challenge completion | Recall | Missed | Med. events* | Marginal over WAF | ms/10k |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| waf-only | 0.0% | 0.0% | 0.0% | – | 28.1% [27.6–28.6] | 151 | 12 | 0 | **38** |
| anomaly-only | 0.0% | 0.0% | 0.0% | – | 22.9% [21.0–23.8] | 162 | 24 | 11 | 992 |
| challenge-only | 0.0% | **100.0%** | **10.3%** | 89.7% | 78.6% | 45 | 1 | 206 | **2.3** |
| **agentwall-full** | **0.0%** | **0.0%** | **0.0%** | – | **40.5%** | **125** | **12** | **26** | **940** |
| union-naive | 0.0% | **100.0%** | **10.3%** | 89.7% | 81.9% | 38 | 1 | 213 | 913 |
| full no human floor | 0.0% | 0.0% | 0.0% | – | 31.0% | 145 | 12 | 6 | 1035 |
| full no headless | 0.0% | 0.0% | 0.0% | – | 31.0% | 145 | 12 | 6 | 910 |
| full no hard signals | 0.0% | 0.0% | 0.0% | – | 40.5% | 125 | 12 | 26 | 933 |
| full no WAF | 0.0% | 0.0% | 0.0% | – | 40.5% | 125 | 12 | 26 | 872 |

`med. events*` is computed **only over detected attacks**; the `missed` column
shows the denominator problem. Detections by family:

| Strategy | encoded | HTTP agent | slow stealth | distributed | headless enum | headless spoofed | scanner |
|---|---:|---:|---:|---:|---:|---:|---:|
| waf-only | 14/20 | 25/25 | 0/25 | 0/80 | 0/20 | 0/20 | 20/20 |
| anomaly-only | 18/20 | 25/25 | 5/25 | 0/80 | 0/20 | 0/20 | 0/20 |
| challenge-only | 20/20 | 25/25 | 0/25 | 80/80 | 20/20 | 0/20 | 20/20 |
| **agentwall-full** | **20/20** | **25/25** | **0/25** | **0/80** | **20/20** | **0/20** | **20/20** |
| union-naive | 20/20 | 25/25 | 7/25 | 80/80 | 20/20 | 0/20 | 20/20 |

### 2.2 Benign false-positive stress gate

`benchmarks/fp_stress.py` runs 870 benign keys per seed across seven families
designed to trip cheap heuristics: direct navigation with no referer, stale 404
links, privacy browsers (referer stripped), slow mobile, long non-JS API clients,
health checks, and a high-volume shared corporate/NAT IP. Production defaults,
three seeds (2,610 benign key-seeds total):

| Family | Keys/seed | False blocks | Benign challenges | Challenge failures |
|---|---:|---:|---:|---:|
| direct navigation | 150 | 0 | 0 | 0 |
| broken 404 links | 150 | 0 | 0 | 0 |
| privacy browser | 150 | 0 | 0 | 0 |
| slow mobile | 150 | 0 | 0 | 0 |
| long API client | 150 | 0 | 0 | 0 |
| health check | 100 | 0 | 0 | 0 |
| shared corporate IP | 20 | 0 | 0 | 0 |
| **Total** | **870/seed** | **0** | **0** | **0** |

This is a synthetic guardrail, not a production FP rate. It does show that the
gating does not fire on these adversarial-benign shapes; production still needs a
shadow week with real traffic and an allowlist for API/monitoring clients.

### 2.3 Equal-disruption comparison

Benign-challenge budget = benign challenged / **all 970** benign keys:

| Budget | Best strategy | Recall |
|---|---|---:|
| ≤0% | **agentwall-full** | **40.5%** |
| ≤1% | agentwall-full | 40.5% |
| ≤5% | agentwall-full | 40.5% |
| ≤10% | agentwall-full | 40.5% |

Challenge-only/union are not comparable at these budgets: they challenge 100% of
benign keys and make 100/970 = **10.3%** of them fail (the non-JS API clients).
That is why "raw recall" alone is misleading.

### 2.4 Layer contributions (after WAF)

- **Full vs WAF:** +26 attack keys (20 headless enumeration, 6 encoded probes
  missed by the raw WAF map) at +12.4 recall points, **0** benign challenge.
- **Challenge/headless contribution:** removing verification drops recall from
  40.5% to 31.0% (−20 headless keys).
- **Learning-policy/human-floor contribution:** removing the floor (so attacks
  train the model) drops recall to 31.0% — poisoning reproduces the original
  failure.
- **Hard signals:** no marginal effect in this synthetic set (ablation 40.5%);
  their contribution is unproven here.
- **WAF:** 0 marginal detections after the ML layer, but it is ~25× cheaper and
  provides immediate signature handling; the benchmark does not measure its
  defence-in-depth value. It is kept for cost/latency, not unique recall.

### 2.5 Why the missed cases are missed (traced)

Run `BENCH_TRACE_IP=<ip> python benchmarks/agentwall_bench.py` to reproduce.

- **Headless enumeration (before fix):** anomaly 0.92 initially, but learning
  every event pulled anomaly down to ~0.35 by event 12; population P99 was 0.648
  so suspicion 0.37 never reached the cut. After the learning/population fix:
  anomaly stays ~0.92, suspicion 0.621 > cut 0.55 at event 12 → challenge →
  automation report → block (`20/20`).
- **Slow browser-like stealth:** suspicion ≈0.50–0.56 (below 0.55) and, even
  when challenged, the spoofed human report clears it (`cleared` suppresses
  non-hard blocks). Anomaly-only's fixed 0.80 threshold catches ~5/25; full
  trusts the verified challenge, so it does not block. This is a deliberate
  trade-off, and a residual risk.
- **Distributed low-and-slow:** per key there are only 4 events and the
  `min-events=12` gate prevents any action, although first-event suspicion is
  0.57–0.64. This is a per-key architecture limit; it needs first-contact or
  cross-key correlation, not a threshold tweak.
- **Headless with spoofed human report:** same as stealth — no observable signal
  distinguishes it after a successful challenge.

### 2.6 Threats to validity

This is **not production evidence**:

- Synthetic, hand-written families; simplified WAF; challenge outcomes modelled
  from client profiles; no real browser/TLS/network or end-to-end challenge
  cost. The 2.3 ms/10k for challenge-only is **decision CPU only**, not the
  browser challenge round-trip.
- Three seeds reduce noise but do not replace real traffic; no temporal drift or
  confidence intervals.
- Attack-heavy stream (210 attack vs 970 benign keys); benign-dominant real
  traffic may favour ML further.
- WAF marginal recall is 0 in this set; real WAF signature coverage differs.
- No real Strix/ARTEX campaign (needs LLM keys and an authorized target); the
  e2e suite covers default fingerprints only.
- The learning-policy fix is evaluated only on this generator; it must be
  validated on production-like traffic before claiming general effectiveness.

To make claims production-grade: benign-dominant traffic with temporal split,
lab runs of real agents (default and stealth, with authorization), end-to-end
challenge cost/completion, multiple independent traffic sources, confidence
intervals, and ablations on real data.

### 2.7 Answers

1. **Mechanism:** specific composite formula/state/transition design plus a
   concrete **benign-only learning policy**. The novelty is compositional and
   operational; no new anomaly algorithm is claimed.
2. **False positives / faster detection at equal cost:** **0 false blocks and 0
   benign challenges** across 2,610 benign key-seeds in the stress gate (and
   0/970 in the main benchmark); no *advantage* over WAF is claimed because both
   measured 0. It is **not faster** (median 12 vs 12) and costs ~25× WAF-only
   CPU. The measured benefit is **+12.4 recall points at zero benign
   challenge**, not FP or latency.
3. **Beyond the sum:** **yes at equal benign-challenge budget** — full 40.5% vs
   WAF 28.1% at 0% benign challenge; challenge-only/union exceed full raw recall
   but only by challenging everyone (100%) and failing 10.3% of benign clients.
   The combination is a gated composition with real complementarity
   (headless/encoded), not super-additivity and not a replacement for
   cross-key/SIEM coverage.

The remaining honest position: AgentWall is a **cost/detection layer** with a
measured improvement over WAF-only at equal user disruption, but it does not
stop distributed low-and-slow or spoofed-human headless agents, and its FP/
latency claims are not supported by this benchmark.
