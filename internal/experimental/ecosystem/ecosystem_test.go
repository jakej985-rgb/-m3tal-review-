// Package ecosystem_test validates ecosystem and developer workflow integrations.
package ecosystem_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/experimental/ecosystem"
	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

func TestGitHubAnnotationFormatting(t *testing.T) {
	testToken := "ghp_" + strings.Repeat("x", 36)
	finding := model.Finding{
		Rule:     "sql-injection",
		Severity: "critical",
		File:     "internal/db/query.go",
		Line:     42,
		Message:  "User input with token " + testToken,
	}

	annotation := ecosystem.FormatGitHubAnnotation(finding)
	if !strings.HasPrefix(annotation, "::error ") {
		t.Errorf("expected ::error prefix, got %s", annotation)
	}
	if !strings.Contains(annotation, "file=internal/db/query.go,line=42,title=sql-injection::") {
		t.Errorf("annotation missing expected properties: %s", annotation)
	}
	if strings.Contains(annotation, "ghp_12345") {
		t.Errorf("expected GitHub PAT token to be redacted, got %s", annotation)
	}
}

func TestValidateTokenPermissions(t *testing.T) {
	badPerms := map[string]string{
		"all":            "write",
		"administration": "write",
	}
	warnings := ecosystem.ValidateTokenPermissions(badPerms)
	if len(warnings) != 2 {
		t.Errorf("expected 2 warnings for excessive permissions, got %d", len(warnings))
	}

	goodPerms := map[string]string{
		"contents":      "read",
		"pull-requests": "write",
	}
	goodWarnings := ecosystem.ValidateTokenPermissions(goodPerms)
	if len(goodWarnings) != 0 {
		t.Errorf("expected 0 warnings for least privilege, got %v", goodWarnings)
	}
}

func TestGenerateSARIFReport(t *testing.T) {
	findings := []model.Finding{
		{
			Rule:     "command-injection",
			Severity: "high",
			File:     "cmd/run.go",
			Line:     88,
			Message:  "Command executed from untrusted input",
			Explanation: &model.FindingExplanation{
				EvidenceSteps: []model.ExplainedStep{
					{StepNumber: 1, Location: "cmd/run.go:85", Statement: "Input read from request"},
					{StepNumber: 2, Location: "cmd/run.go:88", Statement: "Input passed to exec"},
				},
			},
			Remediation: "exec.Command(\"sh\", \"-c\", safeArg)",
		},
	}

	data, err := ecosystem.GenerateSARIFReport(findings, "1.0.0")
	if err != nil {
		t.Fatalf("failed to generate SARIF: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if parsed["version"] != "2.1.0" {
		t.Errorf("expected version 2.1.0, got %v", parsed["version"])
	}

	strOutput := string(data)
	if !strings.Contains(strOutput, "codeFlows") {
		t.Errorf("expected codeFlows in SARIF output")
	}
	if !strings.Contains(strOutput, "fixes") {
		t.Errorf("expected fixes in SARIF output")
	}
}

func TestExternalToolNormalization(t *testing.T) {
	normalizer := &ecosystem.GenericNormalizer{ProviderName: "sample-linter"}

	failedRes := ecosystem.ExternalToolResult{
		ToolName:    "sample-linter",
		ExitCode:    2,
		Failed:      true,
		ErrorOutput: "fatal: binary missing",
	}
	_, err := normalizer.Normalize(failedRes)
	if err == nil {
		t.Fatalf("expected error on failed external tool execution")
	}

	rawJSON := `[
		{"rule_id":"errcheck","file":"main.go","line":20,"severity":"high","message":"unchecked error"}
	]`
	successRes := ecosystem.ExternalToolResult{
		ToolName:    "sample-linter",
		ExitCode:    0,
		Failed:      false,
		RawFindings: []byte(rawJSON),
	}

	findings, err := normalizer.Normalize(successRes)
	if err != nil {
		t.Fatalf("unexpected error normalizing findings: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 normalized finding, got %d", len(findings))
	}
	if findings[0].Rule != "sample-linter/errcheck" {
		t.Errorf("unexpected rule ID: %s", findings[0].Rule)
	}
}

func TestLSPDiagnosticConversion(t *testing.T) {
	finding := model.Finding{
		Rule:     "tls-insecure",
		Severity: "critical",
		File:     "net/client.go",
		Line:     15,
		Message:  "InsecureSkipVerify is set to true",
		Explanation: &model.FindingExplanation{
			EvidenceSteps: []model.ExplainedStep{
				{StepNumber: 1, Location: "net/client.go:15", Statement: "Insecure TLS flag"},
			},
		},
	}

	diag := ecosystem.ConvertFindingToLSPDiagnostic(finding)
	if diag.Severity != ecosystem.LSPSeverityError {
		t.Errorf("expected error severity (1), got %d", diag.Severity)
	}
	if diag.Range.Start.Line != 14 || diag.Range.Start.Character != 0 {
		t.Errorf("expected 0-based coordinates (14, 0), got (%d, %d)",
			diag.Range.Start.Line, diag.Range.Start.Character)
	}
	if len(diag.RelatedInformation) != 1 {
		t.Errorf("expected 1 related information step, got %d", len(diag.RelatedInformation))
	}
}
