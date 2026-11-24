> **Experimental status.** This feature is implemented and unit-tested but is not wired into the CLI. See `internal/experimental/README.md`.

# Differential Verification & Accuracy Measurement

## 1. Overview & Principles

Differential verification compares `m3tal-review` findings against independent tools
and curated, manually adjudicated benchmarks.

### Guiding Principles:
1. **No External Oracle**: No third-party linter or scanner is treated as infallible ground
   truth. Divergence indicates a triage event, not necessarily an error in `m3tal-review`.
2. **Normalized Findings**: Disparate finding representations are normalized into a common
   data model (`NormalizedFinding`) using normalized relative paths and rule identifiers.
3. **Line-Invariant Identity**: Correlating findings between tools relies on semantic keys
   (`filepath:rule_id`) rather than fragile single-line coordinates.
4. **Epistemic Honesty**: Metrics are reported alongside explicit denominators, known limits,
   and adjudication criteria.

---

## 2. Normalization & Disagreement Taxonomy

The comparison harness (`internal/experimental/differential/differential.go`) classifies every finding:

- **Agreement (`agreements`)**: Both `m3tal-review` and the reference tool identified the
  defect on the same normalized file and rule target.
- **M3tal Only (`m3tal_only`)**: Identified by `m3tal-review` but missed or unmodeled by the
  reference analyzer.
- **Reference Only (`reference_only`)**: Reported by the reference tool but absent from
  `m3tal-review` results (indicates potential false negative or out-of-scope rule).

---

## 3. Accuracy Metrics & Denominator Definitions

When evaluating against an adjudicated ground truth corpus:

- **True Positives ($TP$)**: Defects correctly flagged by the analyzer.
- **False Positives ($FP$)**: Clean constructs incorrectly flagged as violations.
- **False Negatives ($FN$)**: True defects missed by the analyzer.

Formulas:
- **Precision**: $\frac{TP}{TP + FP}$ (proportion of reported findings that are real defects).
- **Recall / Sensitivity**: $\frac{TP}{TP + FN}$ (proportion of all actual defects detected).
- **F1 Score**: $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$

*Note*: If $TP + FP = 0$, precision defaults to 0.0. If $TP + FN = 0$, recall defaults to 0.0.

---

## 4. Benchmark Corpus & Execution

The benchmark suite verifies differential behavior across categories:
- **Secrets & Credentials**: Evaluating entropy and pattern detectors against standard
  test suites.
- **Concurrency & Race Conditions**: Evaluating check-then-act and lock order inversions.
- **Typestate & Lifecycle**: Evaluating double-consume and use-after-free conditions.

Regression verification runs automatically via:
```bash
go test -v -race ./internal/experimental/differential/...
```
