package review

import (
	"fmt"
	"math"
	"path/filepath"
	"sort"
	"strings"
)

// ComputeRiskScore calculates a deterministic, explainable risk score (0.0 - 10.0)
// for a finding based on severity, confidence, reachability, exposure, and evidence.
func ComputeRiskScore(f Finding) (float64, *RiskBreakdown) {
	base := baseSeverityScore(f.Severity)
	confFactor := confidenceFactor(f.Confidence)
	reachFactor := reachabilityFactor(f.Reachability)
	expoFactor := exposureFactor(f.File)
	evidMult := evidenceMultiplier(f)

	rawScore := base * confFactor * reachFactor * expoFactor * evidMult
	finalScore := math.Min(10.0, math.Max(0.1, rawScore))
	finalScore = math.Round(finalScore*10.0) / 10.0

	explanation := fmt.Sprintf(
		"base=%.1f * conf=%.2f * reach=%.2f * expo=%.2f * evid=%.2f -> %.1f",
		base, confFactor, reachFactor, expoFactor, evidMult, finalScore,
	)

	breakdown := &RiskBreakdown{
		BaseSeverity:       base,
		ConfidenceFactor:   confFactor,
		ReachabilityFactor: reachFactor,
		ExposureFactor:     expoFactor,
		EvidenceMultiplier: evidMult,
		Explanation:        explanation,
	}

	return finalScore, breakdown
}

func baseSeverityScore(severity string) float64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return 9.5
	case "high":
		return 8.0
	case "medium":
		return 5.5
	case "low":
		return 2.5
	case "info":
		return 0.8
	default:
		return 1.0
	}
}

func confidenceFactor(confidence string) float64 {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "proven", "definite", "certain":
		return 1.0
	case "high":
		return 0.95
	case "medium", "potential":
		return 0.75
	case "low", "heuristic":
		return 0.5
	default:
		// Default conservative confidence
		return 0.7
	}
}

func reachabilityFactor(reachability string) float64 {
	norm := strings.ToLower(strings.TrimSpace(reachability))
	if norm == "reachable" {
		return 1.0
	}
	if norm == "potentially_reachable" || norm == "potential" {
		return 0.85
	}
	if norm == "unreachable" {
		return 0.2
	}
	// Unknown reachability must not be penalized down to unreachable
	return 0.7
}

func containsAny(s string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(s, term) {
			return true
		}
	}
	return false
}

func exposureFactor(filePath string) float64 {
	lower := strings.ToLower(filepath.ToSlash(filePath))

	// Test, fixture, mock, benchmark, and example paths have lower exposure
	if containsAny(lower, "test", "_test.go", "testdata/", "fixtures/", "mock", "bench", "example") {
		return 0.35
	}

	// Public network, api, auth, handler, or web code has high exposure
	if containsAny(lower, "api/", "auth", "handler", "router", "server", "http", "controller") {
		return 1.0
	}

	// Standard internal library/package code
	return 0.85
}

func evidenceMultiplier(f Finding) float64 {
	// Multi-analyzer or multi-evidence corroboration receives a boost
	if len(f.Evidence) > 1 || len(f.Analyzers) > 1 {
		return 1.15
	}
	if len(f.Snippet) > 0 || len(f.Metadata) > 0 {
		return 1.0
	}
	return 0.9
}

// CorrelateFindings tags related findings that share root cause or target context with a
// deterministic CorrelationID, without discarding any findings or evidence.
func CorrelateFindings(findings []Finding) []Finding {
	if len(findings) <= 1 {
		return findings
	}

	out := make([]Finding, len(findings))
	copy(out, findings)

	for i := range out {
		if out[i].CorrelationID != "" {
			continue
		}
		normFile := NormalizeFindingPath(out[i].File)
		domain := ruleSemanticDomain(out[i].Rule, InferAnalyzer(out[i]))
		cid := fmt.Sprintf("corr-%s-%s", domain, sanitizeCorrelationPath(normFile))

		out[i].CorrelationID = cid
		for j := i + 1; j < len(out); j++ {
			if out[j].CorrelationID != "" {
				continue
			}
			otherFile := NormalizeFindingPath(out[j].File)
			otherDomain := ruleSemanticDomain(out[j].Rule, InferAnalyzer(out[j]))
			if normFile == otherFile && domain == otherDomain {
				out[j].CorrelationID = cid
			}
		}
	}

	return out
}

func sanitizeCorrelationPath(path string) string {
	clean := strings.ReplaceAll(path, "/", "_")
	clean = strings.ReplaceAll(clean, "\\", "_")
	clean = strings.ReplaceAll(clean, ".", "_")
	return clean
}

// PrioritizeFindings computes risk scores, establishes correlation IDs, and deterministically
// sorts findings by risk score descending, severity rank, file, line, and ID.
func PrioritizeFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	processed := make([]Finding, len(findings))
	copy(processed, findings)

	for i := range processed {
		if processed[i].RiskScore == 0 || processed[i].Risk == nil {
			score, breakdown := ComputeRiskScore(processed[i])
			processed[i].RiskScore = score
			processed[i].Risk = breakdown
		}
	}

	correlated := CorrelateFindings(processed)

	sort.SliceStable(correlated, func(i, j int) bool {
		// 1. Risk score descending
		if correlated[i].RiskScore != correlated[j].RiskScore {
			return correlated[i].RiskScore > correlated[j].RiskScore
		}
		// 2. Severity rank descending
		si := severityRank(correlated[i].Severity)
		sj := severityRank(correlated[j].Severity)
		if si != sj {
			return si > sj
		}
		// 3. File ascending
		if correlated[i].File != correlated[j].File {
			return correlated[i].File < correlated[j].File
		}
		// 4. Line ascending
		if correlated[i].Line != correlated[j].Line {
			return correlated[i].Line < correlated[j].Line
		}
		// 5. Stable finding ID
		return correlated[i].ID < correlated[j].ID
	})

	for i := range correlated {
		if correlated[i].Explanation == nil {
			correlated[i].Explanation = ExplainFinding(correlated[i])
		}
	}

	return correlated
}

func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
