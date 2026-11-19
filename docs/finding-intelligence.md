# Finding Intelligence, Risk Prioritization & Correlation

## 1. Overview & Goals

Finding intelligence enhances raw static analysis findings with contextual,
evidence-backed risk prioritization, deduplication, and root-cause correlation.

Guiding principles:
1. **Explainable Scoring**: No opaque magic scores. Every risk score is computed from
   discrete, observable factors and explained in `RiskBreakdown`.
2. **Evidence Preservation**: Grouping and correlation NEVER discard findings, evidence
   items, or individual detector attribution.
3. **Conservative Reachability**: Unknown reachability is never assumed to be unreachable;
   it receives a conservative default factor ($0.70$).
4. **Deterministic Ranking**: Findings are stably ordered across runs regardless of file
   system iteration order.

---

## 2. Risk Scoring Formula & Factor Taxonomy

The final risk score ($0.1$ to $10.0$, rounded to 1 decimal place) is defined as:

$$\text{Score} = \min\left(10.0, \, \text{Base} \times C \times R \times E \times M\right)$$

### 1. Base Severity ($\text{Base}$)
- `critical`: $9.5$
- `high`: $8.0$
- `medium`: $5.5$
- `low`: $2.5$
- `info`: $0.8$

### 2. Confidence Factor ($C$)
- `proven` / `definite`: $1.00$
- `high`: $0.95$
- `medium` / `potential`: $0.75$
- `low` / `heuristic`: $0.50$
- Default / unstated: $0.70$

### 3. Reachability Factor ($R$)
- `reachable`: $1.00$
- `potentially_reachable` / `potential`: $0.85$
- `unknown` / unstated: $0.70$ (strictly greater than unreachable)
- `unreachable`: $0.20$

### 4. Exposure Factor ($E$)
- Public API, authentication, router, network server: $1.00$
- Internal core packages: $0.85$
- Test files, benchmarks, mocks, examples, fixtures: $0.35$

### 5. Evidence Multiplier ($M$)
- Corroborated by multiple independent analyzers or rich evidence traces: $1.15$
- Snippet or metadata present: $1.00$
- Single isolated heuristic match: $0.90$

---

## 3. Explainability (`RiskBreakdown`)

Every prioritized finding includes an attached `RiskBreakdown`:
```json
{
  "base_severity": 9.5,
  "confidence_factor": 1.0,
  "reachability_factor": 1.0,
  "exposure_factor": 1.0,
  "evidence_multiplier": 1.0,
  "explanation": "base=9.5 * conf=1.00 * reach=1.00 * expo=1.00 * evid=1.00 -> 9.5"
}
```
Developers and automated CI policies can audit the exact mathematical derivation of every
score without opaque heuristics.

---

## 4. Root-Cause Correlation & Grouping

`CorrelateFindings` groups findings sharing a target file and semantic rule domain into
logical clusters with a deterministic `CorrelationID` (e.g. `corr-secrets-internal_auth_login_go`).
All original findings, line numbers, severities, and evidence traces remain fully intact.
