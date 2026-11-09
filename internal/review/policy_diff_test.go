package review

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestPolicyDiff_Validation(t *testing.T) {
	// Valid policy
	validJSON := []byte(`{
		"risk_paths": ["internal/crypto/**", "auth/**"],
		"forbidden_paths": ["secrets/**"],
		"require_together": [
			{"when_changed": "api/schema.json", "also_change": ["docs/api.md"]}
		],
		"rules": {
			"code-slop": {"severity": "info"},
			"debug-leftover": {"enabled": false}
		},
		"paths": {
			"*_test.go": {
				"code-slop": {"enabled": false}
			}
		}
	}`)

	policy, valErrs, err := ParseReviewPolicy(validJSON)
	if err != nil || len(valErrs) > 0 {
		t.Fatalf("expected valid policy, got err: %v, valErrs: %+v", err, valErrs)
	}
	if len(policy.RiskPaths) != 2 || len(policy.ForbiddenPaths) != 1 {
		t.Errorf("unexpected parsed counts: risk=%d, forbidden=%d", len(policy.RiskPaths), len(policy.ForbiddenPaths))
	}

	// Invalid JSON
	_, _, err = ParseReviewPolicy([]byte(`{not valid`))
	if err == nil {
		t.Errorf("expected JSON parse error")
	}

	// Invalid empty path pattern
	invalidPatternJSON := []byte(`{"risk_paths": [""]}`)
	_, valErrs, _ = ParseReviewPolicy(invalidPatternJSON)
	if len(valErrs) == 0 {
		t.Errorf("expected validation error for empty pattern")
	}

	// Invalid require_together without also_change
	invalidCouplingJSON := []byte(`{"require_together": [{"when_changed": "a.go"}]}`)
	_, valErrs, _ = ParseReviewPolicy(invalidCouplingJSON)
	if len(valErrs) == 0 {
		t.Errorf("expected validation error for missing also_change")
	}

	// Invalid rule severity
	invalidSeverityJSON := []byte(`{"rules": {"code-slop": {"severity": "fatal"}}}`)
	_, valErrs, _ = ParseReviewPolicy(invalidSeverityJSON)
	if len(valErrs) == 0 {
		t.Errorf("expected validation error for invalid severity")
	}
}

func TestPolicyDiff_Diffing(t *testing.T) {
	base := ReviewPolicy{
		RiskPaths:      []string{"old_crypto/**", "shared/**"},
		ForbiddenPaths: []string{"legacy/**"},
		RequireTogether: []PathCoupling{
			{WhenChanged: "schema.sql", AlsoChange: []string{"models.go"}},
		},
		Rules: map[string]PolicyRuleTuning{
			"code-slop": {Severity: "medium"},
		},
		Paths: map[string]map[string]PolicyRuleTuning{
			"legacy/**": {"todo-marker": {Enabled: boolPtr(false)}},
		},
	}

	proposed := ReviewPolicy{
		RiskPaths:      []string{"shared/**", "new_crypto/**"},
		ForbiddenPaths: []string{"legacy/**", "raw_keys/**"},
		RequireTogether: []PathCoupling{
			{WhenChanged: "schema.sql", AlsoChange: []string{"models.go", "migration.sql"}},
			{WhenChanged: "proto/**", AlsoChange: []string{"gen/**"}},
		},
		Rules: map[string]PolicyRuleTuning{
			"code-slop":         {Severity: "info"},
			"command-injection": {Severity: "high", Enabled: boolPtr(true)},
		},
		Paths: map[string]map[string]PolicyRuleTuning{
			"legacy/**":   {"todo-marker": {Enabled: boolPtr(true)}},
			"internal/**": {"secret-material": {Severity: "critical"}},
		},
	}

	diff := DiffPolicies(base, proposed)
	if !diff.HasChanges {
		t.Fatalf("expected diff to have changes")
	}

	// 1. Risk paths
	if len(diff.RiskPaths.Added) != 1 || diff.RiskPaths.Added[0] != "new_crypto/**" {
		t.Errorf("unexpected risk_paths added: %+v", diff.RiskPaths.Added)
	}
	if len(diff.RiskPaths.Removed) != 1 || diff.RiskPaths.Removed[0] != "old_crypto/**" {
		t.Errorf("unexpected risk_paths removed: %+v", diff.RiskPaths.Removed)
	}

	// 2. Forbidden paths
	if len(diff.ForbiddenPaths.Added) != 1 || diff.ForbiddenPaths.Added[0] != "raw_keys/**" {
		t.Errorf("unexpected forbidden_paths added: %+v", diff.ForbiddenPaths.Added)
	}

	// 3. Require together
	if len(diff.RequireTogether.Added) != 1 || diff.RequireTogether.Added[0].WhenChanged != "proto/**" {
		t.Errorf("unexpected require_together added: %+v", diff.RequireTogether.Added)
	}
	if len(diff.RequireTogether.Modified) != 1 || diff.RequireTogether.Modified[0].WhenChanged != "schema.sql" {
		t.Errorf("unexpected require_together modified: %+v", diff.RequireTogether.Modified)
	}

	// 4. Rules
	if len(diff.Rules.Added) != 1 || diff.Rules.Added["command-injection"].Severity != "high" {
		t.Errorf("unexpected rules added: %+v", diff.Rules.Added)
	}
	if len(diff.Rules.Modified) != 1 || diff.Rules.Modified["code-slop"].Proposed.Severity != "info" {
		t.Errorf("unexpected rules modified: %+v", diff.Rules.Modified)
	}

	// 5. Paths
	if len(diff.Paths.Added) != 1 {
		t.Errorf("unexpected paths added: %+v", diff.Paths.Added)
	}
	if len(diff.Paths.Modified) != 1 {
		t.Errorf("unexpected paths modified: %+v", diff.Paths.Modified)
	}

	// Format text
	text := FormatPolicyDiff(diff)
	if !strings.Contains(text, "new_crypto/**") || !strings.Contains(text, "raw_keys/**") || !strings.Contains(text, "code-slop") {
		t.Errorf("expected formatted diff to show changed elements, got:\n%s", text)
	}
}

func TestPolicyDiff_Identical(t *testing.T) {
	p := ReviewPolicy{
		RiskPaths: []string{"a/**"},
	}
	diff := DiffPolicies(p, p)
	if diff.HasChanges {
		t.Errorf("expected no changes for identical policies")
	}
	text := FormatPolicyDiff(diff)
	if !strings.Contains(text, "No configuration differences") {
		t.Errorf("expected no differences message, got:\n%s", text)
	}
}
