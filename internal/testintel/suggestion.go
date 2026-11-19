package testintel

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// cleanIdentifier turns an arbitrary rule or symbol string into a valid Go test name fragment.
func cleanIdentifier(s string) string {
	var b strings.Builder
	capitalize := true
	for _, r := range s {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			if capitalize && r >= 'a' && r <= 'z' {
				b.WriteRune(r - ('a' - 'A'))
			} else {
				b.WriteRune(r)
			}
			capitalize = false
		default:
			capitalize = true
		}
	}
	res := b.String()
	if res == "" {
		return "Target"
	}
	return res
}

// SuggestRegressionTest generates a proposed regression test skeleton for a finding.
//
// Acceptance requirement: Suggestions are proposals for human review. They are NEVER
// automatically applied or executed without explicit user consent.
func SuggestRegressionTest(f review.Finding) TestSuggestion {
	sym := extractTargetSymbol(f.Message, f.Metadata)
	if sym == "" {
		sym = "Handler"
	}
	ruleID := FindingRuleID(f)
	cleanSym := cleanIdentifier(sym)
	cleanRule := cleanIdentifier(ruleID)

	testFuncName := fmt.Sprintf("Test%s_Regression_%s", cleanSym, cleanRule)

	targetFile := f.File
	if strings.HasSuffix(targetFile, ".go") && !strings.HasSuffix(targetFile, "_test.go") {
		targetFile = strings.TrimSuffix(targetFile, ".go") + "_test.go"
	} else if !strings.HasSuffix(targetFile, "_test.go") {
		targetFile = filepath.Join(filepath.Dir(targetFile), "regression_test.go")
	}

	code := fmt.Sprintf(`func %s(t *testing.T) {
	// Regression test for finding %s (%s).
	t.Run("boundary rejection", func(t *testing.T) {
		// Exercise %s with boundary inputs and verify rejection.
	})
}`, testFuncName, f.ID, ruleID, sym)

	rationale := fmt.Sprintf(
		"Proposed regression test to prevent recurrence of %s in %s.",
		ruleID, sym,
	)

	return TestSuggestion{
		FindingID:    f.ID,
		RuleID:       ruleID,
		TargetFile:   targetFile,
		FunctionName: testFuncName,
		ProposedCode: code,
		Rationale:    rationale,
		Disclaimer: "PROPOSAL ONLY: This test skeleton is suggested for human review. " +
			"It is never automatically committed or run without explicit approval.",
		CreatedAt: time.Now().UTC(),
	}
}
