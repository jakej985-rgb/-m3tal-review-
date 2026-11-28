package protocol

import (
	"strings"
	"testing"
)

func TestDecodeDescribeValid(t *testing.T) {
	raw := `{
		"protocol": "review-app/1",
		"kind": "review-app",
		"app": {"name": "review-go", "version": "0.1.0"},
		"extensions": [".go"],
		"inputs": ["content"],
		"rules": [{"id": "go/security/ssrf", "category": "security", "severity": "high"}]
	}`
	res, err := DecodeDescribe([]byte(raw))
	if err != nil {
		t.Fatalf("DecodeDescribe failed: %v", err)
	}
	if res.App.Name != "review-go" {
		t.Fatalf("unexpected app name %q", res.App.Name)
	}
}

func TestDecodeDescribeRejectsUnknownFieldsAndBadVersion(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{
			name: "unknown_field",
			raw:  `{"protocol":"review-app/1","kind":"review-app","app":{"name":"review-go","version":"0.1.0"},"extensions":[".go"],"inputs":["content"],"extra":1}`,
		},
		{
			name: "bad_protocol",
			raw:  `{"protocol":"review-app/2","kind":"review-app","app":{"name":"review-go","version":"0.1.0"},"extensions":[".go"],"inputs":["content"]}`,
		},
		{
			name: "bad_rule_id",
			raw:  `{"protocol":"review-app/1","kind":"review-app","app":{"name":"review-go","version":"0.1.0"},"extensions":[".go"],"inputs":["content"],"rules":[{"id":"gin-missing-recovery","category":"security","severity":"medium"}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeDescribe([]byte(tc.raw)); err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

func TestDecodeOutputStrictness(t *testing.T) {
	sent := map[string]struct{}{"a/b.go": {}}

	valid := `{
		"protocol": "review-app/1",
		"app": {"name": "review-go", "version": "0.1.0"},
		"findings": [{
			"rule": "go/slop/single-call-wrapper",
			"category": "slop",
			"severity": "low",
			"confidence": "high",
			"file": "a/b.go",
			"line": 10,
			"message": "wrapper adds no abstraction",
			"evidence": "func wrap() { real() }"
		}],
		"stats": {"files": 1, "rules": 1}
	}`
	if _, err := DecodeOutput([]byte(valid), "review-go", sent); err != nil {
		t.Fatalf("expected valid output, got %v", err)
	}

	invalidCases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "foreign_file",
			raw:  `{"protocol":"review-app/1","app":{"name":"review-go","version":"0.1.0"},"findings":[{"rule":"go/bug/nil","category":"bug","severity":"high","file":"other.go","line":1,"message":"nil"}],"stats":{"files":1,"rules":1}}`,
			want: "$.findings[0].file",
		},
		{
			name: "traversal_path",
			raw:  `{"protocol":"review-app/1","app":{"name":"review-go","version":"0.1.0"},"findings":[{"rule":"go/bug/nil","category":"bug","severity":"high","file":"../a.go","line":1,"message":"nil"}],"stats":{"files":1,"rules":1}}`,
			want: "$.findings[0].file",
		},
		{
			name: "slop_missing_evidence",
			raw:  `{"protocol":"review-app/1","app":{"name":"review-go","version":"0.1.0"},"findings":[{"rule":"go/slop/x","category":"slop","severity":"low","confidence":"high","file":"a/b.go","line":1,"message":"slop"}],"stats":{"files":1,"rules":1}}`,
			want: "$.findings[0].evidence",
		},
		{
			name: "wrong_app_name",
			raw:  `{"protocol":"review-app/1","app":{"name":"review-ts","version":"0.1.0"},"findings":[],"stats":{"files":1,"rules":1}}`,
			want: "$.app.name",
		},
		{
			name: "category_mismatch",
			raw:  `{"protocol":"review-app/1","app":{"name":"review-go","version":"0.1.0"},"findings":[{"rule":"go/bug/nil","category":"security","severity":"high","file":"a/b.go","line":1,"message":"nil"}],"stats":{"files":1,"rules":1}}`,
			want: "$.findings[0].category",
		},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeOutput([]byte(tc.raw), "review-go", sent)
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateFixOutput(t *testing.T) {
	sent := map[string]struct{}{"a/b.go": {}}
	valid := FixOutput{
		Protocol: Version,
		App:      AppInfo{Name: "review-go", Version: "0.1.0"},
		Patches: []Patch{{
			Rule:        "go/slop/redundant-bool-compare",
			File:        "a/b.go",
			StartLine:   5,
			EndLine:     5,
			Replacement: "if ok {",
			Summary:     "Simplify boolean comparison",
		}},
	}
	if err := ValidateFixOutput(valid, "review-go", sent); err != nil {
		t.Fatalf("expected valid FixOutput, got %v", err)
	}
	invalid := valid
	invalid.Patches = []Patch{{Rule: "go/slop/x", File: "../escape.go", StartLine: 1, EndLine: 1, Summary: "bad"}}
	if err := ValidateFixOutput(invalid, "review-go", sent); err == nil {
		t.Fatalf("expected path traversal error in FixOutput")
	}
}

func TestRenderOutputFormats(t *testing.T) {
	out := Output{
		Protocol: Version,
		App:      AppInfo{Name: "review-go", Version: "0.1.0"},
		Findings: []Finding{{
			Rule:     "go/bug/empty-branch",
			Category: CategoryBug,
			Severity: SeverityMedium,
			File:     "main.go",
			Line:     12,
			Message:  "Empty if branch",
		}},
	}
	for _, fmtName := range []string{"json", "text", "sarif", "github"} {
		var buf strings.Builder
		if err := RenderOutput(&buf, out, fmtName); err != nil {
			t.Fatalf("RenderOutput(%s): %v", fmtName, err)
		}
		if buf.Len() == 0 {
			t.Fatalf("RenderOutput(%s) produced empty output", fmtName)
		}
	}
}

func TestValidateOutputAgainstDescribe(t *testing.T) {
	desc := DescribeResult{
		Protocol:   Version,
		Kind:       Kind,
		App:        AppInfo{Name: "review-go", Version: "0.1.0"},
		Extensions: []string{".go"},
		Inputs:     []string{"content"},
		Rules:      []RuleInfo{{ID: "go/bug/empty-branch", Category: CategoryBug, Severity: SeverityMedium}},
	}
	sent := map[string]struct{}{"main.go": {}}
	out := Output{
		Protocol: Version,
		App:      desc.App,
		Findings: []Finding{{Rule: "go/bug/undeclared", Category: CategoryBug, Severity: SeverityLow, File: "main.go", Line: 1, Message: "x"}},
	}
	if err := ValidateOutputAgainstDescribe(out, desc, sent); err == nil {
		t.Fatalf("expected error for undeclared runtime rule")
	}
}
