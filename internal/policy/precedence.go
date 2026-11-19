package policy

import (
	"path/filepath"
	"strings"
)

var severityRank = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

var confidenceRank = map[string]int{
	"high":   3,
	"medium": 2,
	"low":    1,
}

// SeverityExceeds checks if actual meets or exceeds the threshold severity.
func SeverityExceeds(actual, threshold string) bool {
	actVal := severityRank[strings.ToLower(actual)]
	threshVal := severityRank[strings.ToLower(threshold)]
	return actVal >= threshVal
}

// ConfidenceMeets checks if actual confidence meets or exceeds the minimum.
func ConfidenceMeets(actual, minConf string) bool {
	actVal := confidenceRank[strings.ToLower(actual)]
	minVal := confidenceRank[strings.ToLower(minConf)]
	return actVal >= minVal
}

// matchPathPattern checks if target matches pattern via glob or prefix.
func matchPathPattern(target, pattern string) bool {
	if pattern == target || pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(target, prefix)
	}
	matched, err := filepath.Match(pattern, target)
	return err == nil && matched
}

// ResolveEffectiveRule computes the active max severity and disabled status for a path.
func ResolveEffectiveRule(
	policy QualityGatePolicy,
	filePath, ruleID string,
) (string, bool, string) {
	cleanPath := filepath.ToSlash(filePath)

	for _, override := range policy.PathOverrides {
		if !matchPathPattern(cleanPath, override.Pattern) {
			continue
		}
		for _, dis := range override.DisabledRules {
			if dis == ruleID || dis == "*" {
				return "", true, "path_override:" + override.Pattern
			}
		}
		if override.MaxSeverity != "" {
			return override.MaxSeverity, false, "path_override:" + override.Pattern
		}
	}

	return policy.MaxSeverity, false, "repository_default"
}
