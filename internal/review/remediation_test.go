package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAllRulesPopulateRemediation(t *testing.T) {
	tests := []struct {
		name string
		rule Rule
		diff string
	}{
		{
			name: "TodoRule",
			rule: TodoRule{},
			diff: "--- a/f.go\n+++ b/f.go\n@@ -0,0 +1 @@\n+// TODO: fixme\n",
		},
		{
			name: "DebugRule",
			rule: DebugRule{},
			diff: "--- a/f.go\n+++ b/f.go\n@@ -0,0 +1 @@\n+fmt.Println(\"debug\")\n",
		},
		{
			name: "SecurityRule",
			rule: SecurityRule{},
			diff: "--- a/f.go\n+++ b/f.go\n@@ -0,0 +1 @@\n+password = \"secret12345\"\n",
		},
		{
			name: "ShellRule",
			rule: ShellRule{},
			diff: "--- a/f.go\n+++ b/f.go\n@@ -0,0 +1 @@\n+exec.Command(\"bash\", \"-c\", input)\n",
		},
		{
			name: "PermissionsRule",
			rule: PermissionsRule{},
			diff: "--- a/f.go\n+++ b/f.go\n@@ -0,0 +1 @@\n+os.OpenFile(\"f\", os.O_CREATE, 0777)\n",
		},
		{
			name: "TLSRule",
			rule: TLSRule{},
			diff: "--- a/f.go\n+++ b/f.go\n@@ -0,0 +1 @@\n+&tls.Config{InsecureSkipVerify: true}\n",
		},
		{
			name: "SlopRule",
			rule: SlopRule{},
			diff: "--- a/f.go\n+++ b/f.go\n@@ -0,0 +1 @@\n+if x == true {\n",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			findings := tc.rule.Check(tc.diff)
			if len(findings) == 0 {
				t.Fatalf("%s produced 0 findings", tc.name)
			}
			for _, f := range findings {
				if f.Remediation == "" {
					t.Errorf("%s finding has empty Remediation: %+v", tc.name, f)
				}
			}
		})
	}
}

func TestLintRulePopulatesRemediation(t *testing.T) {
	rule := LintRule{RepositoryRoot: ""}
	findings := rule.Check("")
	if len(findings) == 0 {
		t.Fatal("LintRule produced 0 findings for unconfigured root")
	}
	for _, f := range findings {
		if f.Remediation == "" {
			t.Errorf("LintRule finding has empty Remediation: %+v", f)
		}
	}
}

func TestReadReportWithoutRemediationField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy_report.json")

	// Simulate an older report JSON that lacked the "remediation" field
	legacyJSON := `{
		"run_id": "legacy0123456789",
		"repository": "/tmp/repo",
		"branch": "main",
		"summary": "Review failed.",
		"passed": false,
		"findings": [
			{
				"rule": "todo-marker",
				"severity": "low",
				"file": "main.go",
				"line": 42,
				"message": "Added line contains a TODO marker"
			}
		]
	}`

	if err := os.WriteFile(path, []byte(legacyJSON), 0644); err != nil {
		t.Fatalf("failed to write legacy report: %v", err)
	}

	report, err := ReadReport(path)
	if err != nil {
		t.Fatalf("ReadReport failed on legacy report: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	if f.Rule != "todo-marker" {
		t.Errorf("Rule = %q, want todo-marker", f.Rule)
	}
	if f.Remediation != "" {
		t.Errorf("expected empty Remediation for legacy finding, got %q", f.Remediation)
	}

	// Also verify that reserializing to JSON is clean
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("marshaled data is empty")
	}
}
