package review

import (
	"math"
	"strconv"
	"strings"
)

// NormalizeSeverity maps scanner-specific severity strings into canonical
// severity levels ("critical", "high", "medium", "low", "info") while preserving
// the exact raw source severity for auditing.
func NormalizeSeverity(raw string) (normalized string, rawSeverity string) {
	trimmed := strings.Trim(strings.TrimSpace(raw), "\"'")
	if trimmed == "" {
		return "medium", ""
	}
	rawSeverity = strings.TrimSpace(raw)

	// Direct keyword mapping
	switch strings.ToLower(trimmed) {
	case "critical", "fatal", "blocker", "very_high", "very high":
		return "critical", rawSeverity
	case "high", "error", "major", "severe":
		return "high", rawSeverity
	case "medium", "moderate", "warn", "warning":
		return "medium", rawSeverity
	case "low", "minor":
		return "low", rawSeverity
	case "info", "informational", "note", "notice", "none", "negligible":
		return "info", rawSeverity
	}

	// Direct numeric score (e.g. "9.8" or "7.5")
	if score, err := strconv.ParseFloat(trimmed, 64); err == nil {
		return scoreToSeverity(score), rawSeverity
	}

	// Embedded numeric score after colon (e.g. "CVSS:3.1/...:9.8" or "score: 7.5")
	if idx := strings.LastIndex(trimmed, ":"); idx >= 0 {
		candidate := strings.TrimSpace(trimmed[idx+1:])
		if score, err := strconv.ParseFloat(candidate, 64); err == nil {
			return scoreToSeverity(score), rawSeverity
		}
	}

	// CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	if strings.HasPrefix(strings.ToUpper(trimmed), "CVSS:") {
		if score, ok := calculateCVSS3Score(trimmed); ok {
			return scoreToSeverity(score), rawSeverity
		}
	}

	return "medium", rawSeverity
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0.0:
		return "low"
	default:
		return "info"
	}
}

func calculateCVSS3Score(vector string) (float64, bool) {
	parts := strings.Split(vector, "/")
	metrics := make(map[string]string)
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[strings.ToUpper(strings.TrimSpace(kv[0]))] = strings.ToUpper(strings.TrimSpace(kv[1]))
		}
	}

	avMap := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acMap := map[string]float64{"L": 0.77, "H": 0.44}
	uiMap := map[string]float64{"N": 0.85, "R": 0.62}
	ciaMap := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

	av, okAV := avMap[metrics["AV"]]
	ac, okAC := acMap[metrics["AC"]]
	ui, okUI := uiMap[metrics["UI"]]
	cH, okC := ciaMap[metrics["C"]]
	iH, okI := ciaMap[metrics["I"]]
	aH, okA := ciaMap[metrics["A"]]
	scope := metrics["S"]

	if !okAV || !okAC || !okUI || !okC || !okI || !okA {
		return 0, false
	}

	var pr float64
	if scope == "C" {
		switch metrics["PR"] {
		case "N":
			pr = 0.85
		case "L":
			pr = 0.68
		case "H":
			pr = 0.50
		default:
			return 0, false
		}
	} else {
		switch metrics["PR"] {
		case "N":
			pr = 0.85
		case "L":
			pr = 0.62
		case "H":
			pr = 0.27
		default:
			return 0, false
		}
	}

	iss := 1.0 - ((1.0 - cH) * (1.0 - iH) * (1.0 - aH))
	if iss <= 0 {
		return 0, true
	}

	var impact float64
	if scope == "C" {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15.0)
	} else {
		impact = 6.42 * iss
	}

	exploitability := 8.22 * av * ac * pr * ui

	var score float64
	if scope == "C" {
		score = math.Min(1.08*(impact+exploitability), 10.0)
	} else {
		score = math.Min(impact+exploitability, 10.0)
	}

	// CVSS 3.1 Round up to 1 decimal place
	score = math.Ceil(score*10.0) / 10.0
	return score, true
}

// NormalizeConfidence maps scanner-specific confidence strings into canonical
// confidence levels ("high", "medium", "low") while preserving raw source confidence.
func NormalizeConfidence(raw string) (normalized string, rawConfidence string) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "medium", ""
	}
	rawConfidence = trimmed
	switch strings.ToLower(trimmed) {
	case "high", "certain", "definite":
		return "high", rawConfidence
	case "medium", "moderate", "likely":
		return "medium", rawConfidence
	case "low", "unconfirmed", "experimental":
		return "low", rawConfidence
	default:
		return "medium", rawConfidence
	}
}

// SeverityRank returns the integer priority of a severity (higher is more severe).
func SeverityRank(sev string) int {
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

// ConfidenceRank returns the integer priority of confidence (higher is more confident).
func ConfidenceRank(conf string) int {
	switch strings.ToLower(strings.TrimSpace(conf)) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// MaxSeverity returns whichever severity has higher priority.
func MaxSeverity(s1, s2 string) string {
	if SeverityRank(s1) >= SeverityRank(s2) {
		return s1
	}
	return s2
}

// MaxConfidence returns whichever confidence has higher priority.
func MaxConfidence(c1, c2 string) string {
	if ConfidenceRank(c1) >= ConfidenceRank(c2) {
		return c1
	}
	return c2
}
