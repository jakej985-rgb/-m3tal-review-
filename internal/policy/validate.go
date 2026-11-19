package policy

import (
	"fmt"
	"strings"
)

var validSeverities = map[string]bool{
	"":         true,
	"critical": true,
	"high":     true,
	"medium":   true,
	"low":      true,
	"info":     true,
}

var validConfidences = map[string]bool{
	"":       true,
	"high":   true,
	"medium": true,
	"low":    true,
}

func validatePathOverride(i int, override PathOverride) error {
	if strings.TrimSpace(override.Pattern) == "" {
		return fmt.Errorf("schema error: path_overrides[%d] missing 'pattern'", i)
	}
	if override.MaxSeverity != "" && !validSeverities[strings.ToLower(override.MaxSeverity)] {
		return fmt.Errorf(
			"schema error: path_overrides[%d] invalid 'max_severity' %q",
			i, override.MaxSeverity,
		)
	}
	return nil
}

// ValidatePolicySchema checks that a QualityGatePolicy configuration is syntactically sound.
func ValidatePolicySchema(policy QualityGatePolicy) error {
	if policy.Version == "" {
		return fmt.Errorf("schema error: policy 'version' field is required (e.g. \"1.0\")")
	}

	maxSev := strings.ToLower(policy.MaxSeverity)
	if !validSeverities[maxSev] {
		return fmt.Errorf(
			"schema error: invalid 'max_severity' %q; must be one of critical, high, medium, low, info",
			policy.MaxSeverity,
		)
	}

	minConf := strings.ToLower(policy.MinConfidence)
	if !validConfidences[minConf] {
		return fmt.Errorf(
			"schema error: invalid 'min_confidence' %q; must be one of high, medium, low",
			policy.MinConfidence,
		)
	}

	if policy.Suppression.MaxExpiryDays < 0 {
		return fmt.Errorf("schema error: 'max_expiry_days' cannot be negative")
	}

	for i, override := range policy.PathOverrides {
		if err := validatePathOverride(i, override); err != nil {
			return err
		}
	}
	return nil
}
