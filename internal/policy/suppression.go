package policy

import (
	"fmt"
	"strings"
	"time"
)

// ValidateSuppression checks if a suppression record meets policy standards.
func ValidateSuppression(
	rule SuppressionRule,
	rec SuppressionRecord,
	now time.Time,
) (bool, string) {
	if rule.RequireReason {
		trimmedReason := strings.TrimSpace(rec.Reason)
		if len(trimmedReason) < 5 {
			return false, "Suppression rejected: reason is missing or too brief (min 5 characters)"
		}
	}

	if rule.RequireOwner && strings.TrimSpace(rec.Owner) == "" {
		return false, "Suppression rejected: required owner/contact is missing"
	}

	if rule.RequireExpiry && rec.ExpiresAt == nil {
		return false, "Suppression rejected: required expiry date is missing"
	}

	if rec.ExpiresAt != nil {
		if now.After(*rec.ExpiresAt) {
			expiryStr := rec.ExpiresAt.Format(time.RFC3339)
			return false, fmt.Sprintf("Suppression rejected: expired on %s", expiryStr)
		}
		if rule.MaxExpiryDays > 0 {
			maxDuration := time.Duration(rule.MaxExpiryDays) * 24 * time.Hour
			if rec.ExpiresAt.Sub(now) > maxDuration {
				return false, fmt.Sprintf(
					"Suppression rejected: expiry exceeds maximum policy limit of %d days",
					rule.MaxExpiryDays,
				)
			}
		}
	}

	return true, ""
}
