# Evaluation

This document answers three questions with the current code and a reproducible
controlled benchmark:

1. What is the new mechanism (formula, state representation, transition rules)?
2. Does it lower false positives or detect faster at the same compute cost?
3. Does the combination exceed the sum of WAF + anomaly detector + browser challenge?

**Bottom line:** (1) the mechanism is a specific *composition* of known
primitives, not a new algorithm; (2) the current evidence does **not** show a
false-positive or latency advantage, and the ML layer costs ~28× the WAF-only
CPU in the benchmark; (3) the combination is a **gated composition** that trades
recall for much lower challenge friction — it does not outperform a naive union
on detection. Details and threats to validity below.

Reproduce:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python benchmarks/agentwall_bench.py
```

Artifacts: [`benchmarks/RESULTS.md`](../benchmarks/RESULTS.md),
[`benchmarks/results.json`](../benchmarks/results.json).

---

## 1. Mechanism: formula, state, transitions

### 1.1 State representation

| State | Representation | Lifetime |
|---|---|---|
| Per-key session window | `deque` of parsed events (path/status/auth/probe/UA flags/human-ness inputs), 60 s | until idle eviction / LRU cap |
| Anomaly model | `river.anomaly.HalfSpaceTrees` (10 trees, height 8, window 250): fixed-size tree nodes + per-node left/right mass counters | checkpointed atomically |
| Population reference | rolling `deque` of recent suspicion scores (4000) + cached P95/P99, recomputed every 200 updates | process |
| Challenge state | Redis `agentwall:chal:<id> = <ip_key>\|<issued_ms>`, single-use, TTL 180 s; `agentwall:challenge:<ip_key>` TTL 600 s | TTL |
| Clearance / automation | HMAC-SHA1 signed IP-bound cookie + Redis `agentwall:cleared:<ip_key>` / `agentwall:headless:<ip_key>` | TTL (600 s / 3600 s) |
| Enforcement | Redis `agentwall:block:<ip_key>` TTL 1800 s, read by OpenResty access phase | TTL |

### 1.2 Formulas

Feature vector (per key, over the current window):

```
x = { req_rate, miss_ratio, deny_ratio, auth_ratio, uniq_ratio, path_entropy,
      nonstatic_ratio, probe_ratio, regularity, persistence, ua_flag_ratio,
      multistage }
```

Human-ness (`web` profile; `api` re-weights static/referer to 0 and clean to 0.8):

```
H = 0.45·static + 0.25·referer + 0.20·browser + 0.10·(1−miss)
    − 0.50·tool − 0.30·probe,  clamped to [0,1]
```

Suspicion:

```
S = 0.6 · Anomaly(x) · (1−H) + 0.4 · (0.3·persistence + 0.3·probe
                                        + 0.2·miss + 0.2·multistage)
```

Population-relative cutoffs:

```
C_block = max(0.55, Q99(suspicion buffer))
C_watch = max(0.40, Q95(suspicion buffer))
```

Hard signals (bypass cutoffs, still subject to cooldown): multi-stage
(enumerate + probe + auth in one window), explicit automation UA, repeated
probe with persistence, or the Lua `agentwall:headless` marker for a challenged
key.

Headless verification score (server-side; client report + timing + Client Hints):

```
headless = 0.50·webdriver + 0.50·cdp + 0.60·headlessUA + 0.40·automationUA
         + 0.20·(plugins==0 ∧ mime==0 ∧ browserUA)
         + 0.25·(chrome==false ∧ chromeUA) + 0.20·softwareWebGL
         + 0.25·(plugins==0 ∧ mime==0 ∧ softwareWebGL)   # correlated surfaces
         + 0.15·(pdfViewer==false ∧ plugins==0)
         + 0.15·emptyLanguages + 0.20·outerGeometryAnomaly
         + 0.30·solve_ms<min_solve_ms
         + 0.25·ClientHintsVersion≠UA/Chrome version   # server-side
         + 0.15·noClientHints on HTTPS
```

Threads: block if `headless ≥ 0.60` (prefix `agentwall:headless`), log-only if
`≥ 0.35`; in `mark` mode the score never blocks.

### 1.3 Transition rules (per key)

| From | Event | To |
|---|---|---|
| allow | `H ≥ human_floor` | allow |
| allow/watch | `S ≥ C_block`, `H < human_floor`, cooldown elapsed | **challenge** |
| allow/watch | `S ≥ C_watch`, cooldown elapsed | watch (log) |
| any | hard signal, cooldown elapsed | **block** |
| challenge | grace elapsed and still `S ≥ C_block` (or hard) | **block** |
| challenge | valid PoW + human report | **cleared** (cookie + cleared key; non-hard blocks suppressed) |
| challenge | automation report (`headless ≥ 0.60`) | block + `agentwall:headless` marker |
| block | Redis TTL expiry / operator delete | allow |

Cooldown (120 s) limits action churn; grace (120 s) is the escalation window
after the first challenge. All enforcement paths fail **open** on Redis/scorer
faults; configuration faults are CRIT-visible.

### 1.4 What is actually different from prior anti-bot?

**Not a new primitive.** Rate limits, WAF signatures, PoW, JS challenges,
HMAC/IP-bound cookies and online anomaly detectors all predate this project.
The specific differences are compositional:

1. **Per-key session-shape anomaly** feeding a graduated verdict, instead of
   per-request signatures or global volume thresholds.
2. **Population-relative percentiles with an absolute floor plus a human-ness
   floor**, intended to keep a flash crowd from being flagged for volume.
3. **A verified challenge whose browser-environment report becomes a durable
   Redis marker that the scorer treats as a hard signal** (the challenge and the
   ML layer share state both ways: `challenge` → verify → `cleared`/`headless` →
   block).
4. **One TTL verdict store shared by the edge (Lua) and the optional packet-ban
   layer (fail2ban)**, with explicit state-machine cooldowns/grace and instant
   rollback.
5. **Source-derived regression profiles** for real agents (Strix/ARTEX) that pin
   the contract, not just synthetic unit tests.

Whether that composition is *useful* is an empirical question; §2 shows the
current evidence is not favourable.

## 2. Controlled benchmark

Synthetic but labelled stream (single seed, 41,395 evaluation events + 6,000
baseline events) with eight traffic families:

- benign browser, benign flash crowd, benign power users;
- fast scanner, HTTP-only multi-stage agent, slow browser-like agent;
- headless enumeration (default automation report), headless with spoofed human
  report;
- distributed low-and-slow (4 requests per rotating IP).

Detectors (implemented in [`benchmarks/agentwall_bench.py`](../benchmarks/agentwall_bench.py)):

| Detector | Definition |
|---|---|
| `waf-only` | static UA/marker filter + per-IP rate/4xx threshold (nginx-like) |
| `anomaly-only` | real HST score, fixed threshold 0.80, no human floor/population/hard signals |
| `challenge-only` | JS challenge to **every new key**; JS clients pass; HTTP tools fail; headless automated reports block |
| `agentwall-full` | shipped pipeline: WAF + HST + human-ness + population quantiles + hard signals + targeted challenge/headless |
| `union-naive` | OR of the three single layers ("sum of parts" baseline) |
| ablations | full without human floor / hard signals / headless verification / WAF |

### 2.1 Results

| Detector | Benign FP keys | FP rate | Recall | Median events to action | Benign keys challenged | ms / 10k events |
|---|---:|---:|---:|---:|---:|---:|
| waf-only | 0 / 870 | 0.0% | 23.7% | 9 | 0 | **33** |
| anomaly-only | 0 / 870 | 0.0% | 18.9% | 25.5 | 0 | 956 |
| challenge-only | 0 / 870 | 0.0% | 76.3% | 1 | **870 (100%)** | **2** |
| agentwall-full | 0 / 870 | 0.0% | **23.7%** | 9 | 0 | 900 |
| full (challenge at watch cut) | 0 / 870 | 0.0% | 24.2% | 9.5 | 0 | 914 |
| union-naive | 0 / 870 | 0.0% | **80.0%** | 1 | 870 (100%) | 1011 |
| full without WAF | 0 / 870 | 0.0% | 16.8% | 16 | 0 | 892 |
| full without human floor | 0 / 870 | 0.0% | 23.7% | 9 | 0 | 898 |
| full without hard signals | 0 / 870 | 0.0% | 23.7% | 9 | 0 | 903 |
| full without headless | 0 / 870 | 0.0% | 23.7% | 9 | 0 | 928 |

Detection by attack family (`detected/total`):

| Detector | HTTP agent | Slow browser-like | Distributed low-and-slow | Headless enum | Headless spoofed | Fast scanner |
|---|---:|---:|---:|---:|---:|---:|
| waf-only | 25/25 | 0/25 | 0/80 | 0/20 | 0/20 | 20/20 |
| anomaly-only | 25/25 | 4/25 | 0/80 | 0/20 | 0/20 | 7/20 |
| challenge-only | 25/25 | 0/25 | **80/80** | **20/20** | 0/20 | 20/20 |
| agentwall-full | 25/25 | 0/25 | 0/80 | 0/20 | 0/20 | 20/20 |
| full + challenge-at-watch | 25/25 | 0/25 | 0/80 | 1/20 | 0/20 | 20/20 |

### 2.2 Interpretation (honest)

- **False positives:** all detectors scored 0/870 on the benign families, so
  this benchmark provides **no evidence** that the human floor or population
  logic reduces false positives. The ablation without the human floor is
  identical. A test that can separate them needs benign traffic that actually
  trips the anomaly detector (e.g., an organic traffic shift), which this
  synthetic set does not contain.
- **Detection speed:** full has median 9 events, identical to WAF-only
  (9) and slower than challenge-only (1). No latency advantage.
- **Cost:** full spends ~900 ms/10k events vs 33 ms for WAF-only (~28×) and
  2 ms for challenge-only. At equal cost there is no measured gain; the ML
  layer's only measured contribution in this stream is +0 net detections over
  WAF (and it alone reaches 16.8% without WAF).
- **The combination is not super-additive.** The naive union reaches 80%
  recall but challenges **100% of benign keys**; full reaches 23.7% with **zero**
  benign challenges. That is a recall-vs-friction trade, not a synergy that
  exceeds the sum.
- **Concrete failure mode:** headless enumeration is only caught by the
  challenge layer. In full, the rolling P99 cut was **0.648** while the headless
  key's suspicion peaked at **0.59**, so it was never challenged (only 1/20 was
  caught even with challenge-at-watch). High-scoring attack traffic poisons the
  population percentile, raising the bar for quieter attack families. This is a
  real design issue, not a benchmark artefact: any attack-heavy window does it.
- **Distributed low-and-slow** is missed by every per-key layer in full; only
  challenge-every-new-key catches the non-JS variant (at 100% benign challenge
  friction). This confirms the documented SIEM gap.
- **Stealth headless** (spoofed human report) is missed by every detector,
  including challenge-only — as documented.

### 2.3 Answers

1. **Mechanism:** a specific composite formula/state/transition design (§1).
   The novelty is compositional and operational, not a new algorithm. Claims of
   algorithmic novelty would not be defensible.
2. **False positives / faster detection at equal cost:** **not demonstrated.**
   The benchmark shows equal FP, equal latency, and higher cost; the human-floor
   benefit is untested because benign traffic did not trip the detector.
3. **Beyond the sum of WAF + anomaly + challenge:** **not demonstrated.** The
   measured result is a gated trade-off (much lower friction, lower recall), not
   a super-additive combination. Challenge-only and naive union have higher
   recall only by challenging every key.

### 2.4 Threats to validity

This is a synthetic, single-seed benchmark, not production evidence:

- Hand-written traffic families and a simplified WAF; no TLS/browser execution;
  challenge outcomes are modelled from client profiles.
- Attack-heavy population (190 attack keys vs 870 benign keys), which
  over-represents high-scoring events and poisons rolling percentiles; a
  benign-dominant stream would likely favour the ML layer.
- No confidence intervals, temporal train/test split, or real user behaviour.
- Latency is "events until action", not wall-clock detection time; CPU excludes
  model training and Redis/network costs.
- No real Strix/ARTEX runs (needs LLM keys and an authorized target); the
  agent-profile e2e suite covers default fingerprints only.

To make claims 2–3 defensible, the next evaluation should run on real
benign-dominant traffic with a temporal split, labelled authorized red-team
agents (Strix/ARTEX/default and stealth), measured end-to-end cost, and
confidence intervals; plus ablations on the population policy.

### 2.5 What the evidence suggests to change

- **Baseline-anchored quantiles or a cap**: do not let attack events raise the
  P99 used to challenge quieter families (or compute quantiles from
  human-like/non-hard events only). Re-run the benchmark after the change.
- **Challenge policy:** consider first-contact or watch-level challenge for
  browser-like new keys (transparent to humans, catches non-JS/headless), and
  measure the friction cost.
- **Cross-key correlation** for distributed low-and-slow (SIEM layer), which no
  per-key detector in this repo covers.

Until those are implemented and measured on real traffic, the honest position
is: **AgentWall is a well-engineered, honest cost layer whose claimed
advantages over a WAF and over the sum of parts are not yet proven.**
