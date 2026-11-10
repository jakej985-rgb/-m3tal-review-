package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadValidCustomRules(t *testing.T) {
	// 1. YAML format
	yamlPath := filepath.Join("..", "..", "testdata", "custom-rules", "valid-rules.yaml")
	rules, err := LoadCustomRulesFile(yamlPath, "")
	if err != nil {
		t.Fatalf("failed to load valid YAML rules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Name() != "custom-disallow-eval" {
		t.Errorf("expected first rule ID 'custom-disallow-eval', got %q", rules[0].Name())
	}
	if rules[1].Name() != "custom-unsafe-token-log" {
		t.Errorf("expected second rule ID 'custom-unsafe-token-log', got %q", rules[1].Name())
	}

	// 2. JSON format
	jsonPath := filepath.Join("..", "..", "testdata", "custom-rules", "valid-rules.json")
	jsonRules, err := LoadCustomRulesFile(jsonPath, "")
	if err != nil {
		t.Fatalf("failed to load valid JSON rules: %v", err)
	}
	if len(jsonRules) != 1 {
		t.Fatalf("expected 1 rule in JSON, got %d", len(jsonRules))
	}
	if jsonRules[0].Name() != "custom-no-raw-sql" {
		t.Errorf("expected rule ID 'custom-no-raw-sql', got %q", jsonRules[0].Name())
	}
}

func TestInvalidSchemaValidation(t *testing.T) {
	testCases := []struct {
		name          string
		fixture       string
		expectedError string
	}{
		{
			name:          "invalid ID",
			fixture:       "invalid-schema-id.yaml",
			expectedError: "letters, numbers, underscores, and hyphens",
		},
		{
			name:          "invalid severity",
			fixture:       "invalid-schema-severity.yaml",
			expectedError: "invalid severity",
		},
		{
			name:          "regex pattern too long",
			fixture:       "invalid-schema-regex-length.yaml",
			expectedError: "exceeds maximum length of 1000",
		},
		{
			name:          "bad regex syntax",
			fixture:       "invalid-schema-bad-regex.yaml",
			expectedError: "invalid regex syntax",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join("..", "..", "testdata", "custom-rules", tc.fixture)
			_, err := LoadCustomRulesFile(path, "")
			if err == nil {
				t.Fatalf("expected error loading %s, got nil", tc.fixture)
			}
			if !strings.Contains(err.Error(), tc.expectedError) {
				t.Fatalf("expected error to contain %q, got: %v", tc.expectedError, err)
			}
		})
	}
}

func TestCustomRuleEdgeCaseValidation(t *testing.T) {
	cases := []struct {
		name        string
		cfg         CustomRulesConfig
		expectField string
	}{
		{
			name: "empty id",
			cfg: CustomRulesConfig{
				Rules: []CustomRuleDef{{
					ID:       "",
					Name:     "Test",
					Severity: "high",
					Category: "security",
					Message:  "msg",
					Pattern:  "pat",
				}},
			},
			expectField: "id",
		},
		{
			name: "duplicate id",
			cfg: CustomRulesConfig{
				Rules: []CustomRuleDef{
					{
						ID:       "dup-rule",
						Name:     "Test 1",
						Severity: "high",
						Category: "security",
						Message:  "msg 1",
						Pattern:  "pat 1",
					},
					{
						ID:       "dup-rule",
						Name:     "Test 2",
						Severity: "low",
						Category: "review",
						Message:  "msg 2",
						Pattern:  "pat 2",
					},
				},
			},
			expectField: "id",
		},
		{
			name: "empty name",
			cfg: CustomRulesConfig{
				Rules: []CustomRuleDef{{
					ID:       "valid-id",
					Name:     "",
					Severity: "high",
					Category: "security",
					Message:  "msg",
					Pattern:  "pat",
				}},
			},
			expectField: "name",
		},
		{
			name: "invalid category",
			cfg: CustomRulesConfig{
				Rules: []CustomRuleDef{{
					ID:       "valid-id",
					Name:     "Name",
					Severity: "high",
					Category: "unknown_category",
					Message:  "msg",
					Pattern:  "pat",
				}},
			},
			expectField: "category",
		},
		{
			name: "empty message",
			cfg: CustomRulesConfig{
				Rules: []CustomRuleDef{{
					ID:       "valid-id",
					Name:     "Name",
					Severity: "high",
					Category: "security",
					Message:  "",
					Pattern:  "pat",
				}},
			},
			expectField: "message",
		},
		{
			name: "unrecognized language",
			cfg: CustomRulesConfig{
				Rules: []CustomRuleDef{{
					ID:        "valid-id",
					Name:      "Name",
					Severity:  "high",
					Category:  "security",
					Message:   "msg",
					Languages: []string{"unsupported_lang"},
					Pattern:   "pat",
				}},
			},
			expectField: "languages",
		},
		{
			name: "no patterns",
			cfg: CustomRulesConfig{
				Rules: []CustomRuleDef{{
					ID:       "valid-id",
					Name:     "Name",
					Severity: "high",
					Category: "security",
					Message:  "msg",
				}},
			},
			expectField: "pattern",
		},
		{
			name: "timeout out of bounds",
			cfg: CustomRulesConfig{
				Rules: []CustomRuleDef{{
					ID:       "valid-id",
					Name:     "Name",
					Severity: "high",
					Category: "security",
					Message:  "msg",
					Pattern:  "pat",
					Timeout:  "50s",
				}},
			},
			expectField: "timeout",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			errs, _ := ValidateCustomRulesConfig(&tc.cfg)
			if len(errs) == 0 {
				t.Fatalf("expected validation errors, got none")
			}
			found := false
			for _, e := range errs {
				if e.Field == tc.expectField {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected error on field %q, got: %v", tc.expectField, errs)
			}
		})
	}
}

func TestCustomRulesMatching(t *testing.T) {
	yamlPath := filepath.Join("..", "..", "testdata", "custom-rules", "valid-rules.yaml")
	rules, err := LoadCustomRulesFile(yamlPath, "")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	engine := NewEngine(rules...)

	// Positive test case (positive-match.go diff)
	posDiff := `diff --git a/app.go b/app.go
--- a/app.go
+++ b/app.go
@@ -0,0 +1,5 @@
+package main
+import "log"
+func test() {
+	log.Printf("Token is %s", auth_token)
+}
`
	findings := engine.Run(posDiff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding on positive diff, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "custom-unsafe-token-log" {
		t.Errorf("expected finding rule 'custom-unsafe-token-log', got %q", findings[0].Rule)
	}
	if findings[0].Severity != "medium" || findings[0].Category != "security" {
		t.Errorf("unexpected severity/category: %s/%s", findings[0].Severity, findings[0].Category)
	}

	// Negative test case (safe code)
	negDiff := `diff --git a/app.go b/app.go
--- a/app.go
+++ b/app.go
@@ -0,0 +1,5 @@
+package main
+import "log"
+func test() {
+	log.Printf("Processing request successfully")
+}
`
	negFindings := engine.Run(negDiff)
	if len(negFindings) != 0 {
		t.Fatalf("expected 0 findings on safe diff, got %d: %+v", len(negFindings), negFindings)
	}

	// Test file exclude pattern: test files excluded
	testFileDiff := `diff --git a/app_test.go b/app_test.go
--- a/app_test.go
+++ b/app_test.go
@@ -0,0 +1,5 @@
+package main
+import "log"
+func TestSomething() {
+	log.Printf("Token is %s", auth_token)
+}
`
	testFindings := engine.Run(testFileDiff)
	if len(testFindings) != 0 {
		t.Fatalf("expected 0 findings on excluded test file, got %d: %+v", len(testFindings), testFindings)
	}
}

func TestCustomRuleTimeout(t *testing.T) {
	// Create a rule with an extremely short timeout and simulate timeout
	ruleDef := CustomRuleDef{
		ID:       "timeout-rule",
		Name:     "Timeout Test",
		Severity: "high",
		Category: "security",
		Message:  "Slow pattern",
		Pattern:  `\btest\b`,
		Timeout:  "1ms",
	}

	cr, err := buildCustomRule(ruleDef, "")
	if err != nil {
		t.Fatalf("build custom rule: %v", err)
	}

	// Override timeout to effectively 1 nanosecond to ensure timeout triggers reliably
	cr.timeout = 1 * time.Nanosecond

	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -0,0 +1,100 @@
+package main
+` + strings.Repeat("+func test() {}\n", 100)

	findings := cr.Check(diff)
	if len(findings) == 0 {
		t.Fatalf("expected timeout finding, got 0 findings")
	}
	if findings[0].Rule != "timeout-rule-timeout" {
		t.Errorf("expected finding rule 'timeout-rule-timeout', got %q", findings[0].Rule)
	}
	if findings[0].Category != "confidence" {
		t.Errorf("expected category 'confidence', got %q", findings[0].Category)
	}
}

func TestFindCustomRulesFile(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. None present
	if found := FindCustomRulesFile(tmpDir, ""); found != "" {
		t.Errorf("expected empty, got %q", found)
	}

	// 2. Discover .m3tal-review-rules.yaml
	rulesFile := filepath.Join(tmpDir, ".m3tal-review-rules.yaml")
	if err := os.WriteFile(rulesFile, []byte("version: '1.0'\nrules: []\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if found := FindCustomRulesFile(tmpDir, ""); found != rulesFile {
		t.Errorf("expected %q, got %q", rulesFile, found)
	}

	// 3. Explicit path
	explicit := filepath.Join(tmpDir, "custom.yaml")
	if err := os.WriteFile(explicit, []byte("version: '1.0'\nrules: []\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if found := FindCustomRulesFile(tmpDir, "custom.yaml"); found != explicit {
		t.Errorf("expected explicit %q, got %q", explicit, found)
	}
}

func TestLoadCustomRulesFileRejectsSymlink(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "target-rules.yaml")
	if err := os.WriteFile(targetPath, []byte("version: '1.0'\nrules: []\n"), 0644); err != nil {
		t.Fatalf("failed to write target rules: %v", err)
	}

	symlinkPath := filepath.Join(tmpDir, "symlink-rules.yaml")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Skipf("symlink creation not supported: %v", err)
	}

	_, err := LoadCustomRulesFile(symlinkPath, tmpDir)
	if err == nil {
		t.Fatalf("expected error loading custom rules from symlink, got nil")
	}
	if !strings.Contains(err.Error(), "must not be a symbolic link") {
		t.Fatalf("expected symlink rejection message, got: %v", err)
	}
}
