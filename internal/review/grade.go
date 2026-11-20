package review

// GradeResult holds the computed quality grade for a review run.
//
// The score (0–100) is computed by assigning a penalty for each finding based
// on its severity and confidence, summing all penalties (capped at 100), and
// subtracting from 100. A run with no findings earns a perfect 100 / A.
//
// Penalty weights:
//
//	critical: 25   high: 10   medium: 4   low: 1   info: 0
//
// Confidence multipliers:
//
//	high: 1.0   medium: 0.75   low: 0.5   empty: 0.75 (treat as medium)
//
// Grade thresholds:
//
//	A ≥ 90   B ≥ 75   C ≥ 60   D ≥ 40   F < 40
type GradeResult struct {
	Score         int            `json:"score"`
	Grade         string         `json:"grade"`
	TotalPenalty  int            `json:"total_penalty"`
	FindingCounts map[string]int `json:"finding_counts"`
}

// severityPenalty maps canonical severity levels to base penalty points.
var severityPenalty = map[string]int{
	"critical": 25,
	"high":     10,
	"medium":   4,
	"low":      1,
	"info":     0,
}

// confidenceMultiplier maps canonical confidence levels to a weighting factor
// (expressed as hundredths to avoid floating-point in the final score).
func confidenceWeight(conf string) int {
	switch conf {
	case "high":
		return 100 // 1.0×
	case "low":
		return 50 // 0.5×
	default:
		// "medium", "" (unset), or anything unrecognised → 0.75×
		return 75
	}
}

// scoreToGrade converts a 0–100 score to a letter grade.
func scoreToGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

// ComputeGrade derives a deterministic score and letter grade from a slice of
// findings. It is intentionally simple and reproducible: the same findings
// always produce the same score regardless of evaluation order.
func ComputeGrade(findings []Finding) GradeResult {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	totalPenalty := 0
	for _, f := range findings {
		sev := f.Severity
		if sev == "" {
			sev = "medium"
		}
		base, ok := severityPenalty[sev]
		if !ok {
			base = severityPenalty["medium"]
			sev = "medium"
		}
		counts[sev]++

		if base == 0 {
			continue // info findings carry no penalty
		}

		// Apply confidence multiplier (expressed in hundredths to stay integer).
		weight := confidenceWeight(f.Confidence)
		penalty := (base*weight + 50) / 100 // round half-up
		if penalty < 1 {
			penalty = 1 // even low-confidence findings carry at least 1 point
		}
		totalPenalty = totalPenalty + penalty
	}

	if totalPenalty > 100 {
		totalPenalty = 100
	}

	score := 100 - totalPenalty
	return GradeResult{
		Score:         score,
		Grade:         scoreToGrade(score),
		TotalPenalty:  totalPenalty,
		FindingCounts: counts,
	}
}
