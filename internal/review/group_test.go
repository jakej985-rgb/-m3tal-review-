package review

import (
	"testing"
)

func TestGroupFindingsMultipleAnalyzers(t *testing.T) {
	// Finding from built-in secret rule
	fBuiltin := Finding{
		Category:    "security",
		Rule:        "hardcoded-secret",
		Severity:    "high",
		RawSeverity: "HIGH",
		Confidence:  "medium",
		File:        "internal/db/conn.go",
		Line:        42,
		Message:     "Hardcoded database credentials detected",
		Remediation: "Use environment variables or secrets manager.",
	}

	// Duplicate finding from gitleaks on same file/line
	fGitleaks := Finding{
		Category:    "security",
		Rule:        "gitleaks-postgres-password",
		Severity:    "high",
		RawSeverity: "HIGH",
		Confidence:  "high",
		File:        "./internal/db/conn.go",
		Line:        42,
		Message:     "Possible secret detected: Postgres Password",
		Remediation: "Remove the secret and rotate it.",
	}

	// Another finding from gosec on same file/line
	fGosec := Finding{
		Category:    "security",
		Rule:        "gosec-G101",
		Severity:    "critical",
		RawSeverity: "CRITICAL",
		Confidence:  "high",
		AdvisoryID:  "CWE-798",
		AdvisoryIDs: []string{"CWE-798"},
		File:        "internal/db/conn.go",
		Line:        42,
		Message:     "Use of hardcoded credentials",
		Remediation: "Review the gosec rule guidance.",
	}

	// An unrelated finding on a different line
	fOther := Finding{
		Category: "slop",
		Rule:     "todo-marker",
		Severity: "low",
		File:     "internal/db/conn.go",
		Line:     100,
		Message:  "TODO: add connection pool tuning",
	}

	raw := []Finding{fBuiltin, fGitleaks, fGosec, fOther}
	grouped := GroupFindings(raw)

	if len(grouped) != 2 {
		t.Fatalf("expected 2 grouped findings (1 grouped security + 1 todo), got %d: %+v", len(grouped), grouped)
	}

	secFinding := grouped[0]
	if secFinding.Line != 42 {
		secFinding = grouped[1]
	}

	// Check max severity
	if secFinding.Severity != "critical" {
		t.Errorf("expected max severity critical, got %s", secFinding.Severity)
	}

	// Check confidence elevation (multiple analyzers confirmed)
	if secFinding.Confidence != "high" {
		t.Errorf("expected confidence elevated to high, got %s", secFinding.Confidence)
	}

	// Check preservation of individual rule identifiers
	wantRules := []string{"gitleaks-postgres-password", "gosec-G101", "hardcoded-secret"}
	if len(secFinding.Rules) != len(wantRules) {
		t.Fatalf("expected rules %v, got %v", wantRules, secFinding.Rules)
	}
	for i, r := range wantRules {
		if secFinding.Rules[i] != r {
			t.Errorf("rule[%d] = %s, want %s", i, secFinding.Rules[i], r)
		}
	}

	// Check preservation of analyzers
	wantAnalyzers := []string{"gitleaks", "gosec", "m3tal-review"}
	if len(secFinding.Analyzers) != len(wantAnalyzers) {
		t.Fatalf("expected analyzers %v, got %v", wantAnalyzers, secFinding.Analyzers)
	}
	for i, a := range wantAnalyzers {
		if secFinding.Analyzers[i] != a {
			t.Errorf("analyzer[%d] = %s, want %s", i, secFinding.Analyzers[i], a)
		}
	}

	// Check preservation of underlying analyzer evidence
	if len(secFinding.Evidence) != 3 {
		t.Fatalf("expected 3 evidence records, got %d", len(secFinding.Evidence))
	}
	evidenceAnalyzers := make(map[string]bool)
	for _, ev := range secFinding.Evidence {
		evidenceAnalyzers[ev.Analyzer] = true
		if ev.Line != 42 {
			t.Errorf("evidence line = %d, want 42", ev.Line)
		}
		if ev.Rule == "" || ev.Message == "" {
			t.Errorf("incomplete evidence record: %+v", ev)
		}
	}
	for _, a := range wantAnalyzers {
		if !evidenceAnalyzers[a] {
			t.Errorf("missing evidence for analyzer %s", a)
		}
	}

	// Check advisory ID preservation
	if secFinding.AdvisoryID != "CWE-798" {
		t.Errorf("expected advisory ID CWE-798, got %s", secFinding.AdvisoryID)
	}
}

func TestGroupFindingsSharedAdvisoryID(t *testing.T) {
	// Finding from osv-scanner
	f1 := Finding{
		Category:    "security",
		Rule:        "osv-GHSA-1234",
		Severity:    "high",
		AdvisoryID:  "GHSA-1234",
		AdvisoryIDs: []string{"GHSA-1234", "CVE-2023-9999"},
		File:        "go.mod",
		Message:     "Vulnerable dependency github.com/foo/bar@v1.0.0",
	}

	// Duplicate finding from OSV API vulnscan
	f2 := Finding{
		Category:    "security",
		Rule:        "dependency-cve",
		Severity:    "high",
		AdvisoryID:  "GHSA-1234",
		AdvisoryIDs: []string{"GHSA-1234"},
		File:        "./go.mod",
		Message:     "Go github.com/foo/bar@v1.0.0: GHSA-1234 SQL injection",
	}

	grouped := GroupFindings([]Finding{f1, f2})
	if len(grouped) != 1 {
		t.Fatalf("expected 1 grouped finding, got %d", len(grouped))
	}

	gf := grouped[0]
	if len(gf.Analyzers) != 2 {
		t.Fatalf("expected 2 analyzers in grouped finding, got %v", gf.Analyzers)
	}
	if len(gf.Rules) != 2 {
		t.Fatalf("expected 2 rules in grouped finding, got %v", gf.Rules)
	}
	if len(gf.Evidence) != 2 {
		t.Fatalf("expected 2 evidence entries, got %d", len(gf.Evidence))
	}
	if len(gf.AdvisoryIDs) < 2 {
		t.Fatalf("expected union of advisory IDs, got %v", gf.AdvisoryIDs)
	}
}

func TestGroupFindingsDistinctRulesSameLineNotGrouped(t *testing.T) {
	// 1. Two different rules from the SAME analyzer on the same line must NOT be grouped
	f1 := Finding{
		Rule:    "code-slop",
		File:    "main.go",
		Line:    10,
		Message: "empty block",
	}
	f2 := Finding{
		Rule:    "todo-marker",
		File:    "main.go",
		Line:    10,
		Message: "TODO item",
	}

	groupedSameAnalyzer := GroupFindings([]Finding{f1, f2})
	if len(groupedSameAnalyzer) != 2 {
		t.Fatalf("expected 2 distinct findings from same analyzer on line 10, got %d: %+v", len(groupedSameAnalyzer), groupedSameAnalyzer)
	}

	// 2. Two unrelated rules from DIFFERENT analyzers on the same line must NOT be grouped
	fGosecTraversal := Finding{
		Rule:      "gosec-G304",
		Analyzers: []string{"gosec"},
		File:      "main.go",
		Line:      20,
		Message:   "File path provided as taint input",
	}
	fBuiltinShell := Finding{
		Rule:      "risky-shell-execution",
		Analyzers: []string{"m3tal-review"},
		File:      "main.go",
		Line:      20,
		Message:   "Command execution with variable argument",
	}

	groupedDifferentRules := GroupFindings([]Finding{fGosecTraversal, fBuiltinShell})
	if len(groupedDifferentRules) != 2 {
		t.Fatalf("expected 2 distinct findings for unrelated rules on line 20, got %d", len(groupedDifferentRules))
	}
}

func TestGroupFindingsSingleFindingPopulatesMetadata(t *testing.T) {
	f := Finding{
		Rule:     "hardcoded-credential",
		Severity: "high",
		File:     "auth.go",
		Line:     15,
		Message:  "api key exposed",
	}

	grouped := GroupFindings([]Finding{f})
	if len(grouped) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(grouped))
	}
	gf := grouped[0]
	if len(gf.Analyzers) != 1 || gf.Analyzers[0] != "m3tal-review" {
		t.Errorf("expected analyzer m3tal-review, got %v", gf.Analyzers)
	}
	if len(gf.Rules) != 1 || gf.Rules[0] != "hardcoded-credential" {
		t.Errorf("expected rule hardcoded-credential, got %v", gf.Rules)
	}
	if len(gf.Evidence) != 1 {
		t.Fatalf("expected 1 evidence item for single finding, got %d", len(gf.Evidence))
	}
	if gf.ID == "" {
		t.Errorf("expected non-empty finding ID")
	}
}
