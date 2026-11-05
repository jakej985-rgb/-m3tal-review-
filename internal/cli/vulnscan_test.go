package cli

import (
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestParseGoMod(t *testing.T) {
	content := `module example.com/x

go 1.21

require github.com/foo/bar v1.2.3

require (
	github.com/baz/qux v0.9.1 // indirect
	golang.org/x/text v0.14.0
)
`
	deps := parseGoMod(content, "go.mod")
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}
	byName := map[string]depRef{}
	for _, d := range deps {
		byName[d.Name] = d
	}
	qux, ok := byName["github.com/baz/qux"]
	if !ok || qux.Ecosystem != "Go" || qux.Version != "v0.9.1" {
		t.Fatalf("unexpected dep: %+v", qux)
	}
}

func TestParsePackageJSON(t *testing.T) {
	content := `{"dependencies":{"lodash":"^4.17.21","react":"18.2.0"},"devDependencies":{"jest":"~29.7.0"}}`
	deps := parsePackageJSON(content, "package.json")
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d: %+v", len(deps), deps)
	}
	for _, d := range deps {
		if d.Ecosystem != "npm" {
			t.Fatalf("bad ecosystem: %+v", d)
		}
		if strings.ContainsAny(d.Version, "^~") {
			t.Fatalf("version not normalized: %+v", d)
		}
	}
}

func TestParsePackageJSONSkipsUnpinnable(t *testing.T) {
	content := `{"dependencies":{"local":"file:../x","latest":"*","range":"^1.0","pinned":"^1.0.3"}}`
	deps := parsePackageJSON(content, "package.json")
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d: %+v", len(deps), deps)
	}
}

func TestParseRequirements(t *testing.T) {
	content := `# comment
requests==2.31.0
flask>=2.0
-e git+https://example.com/x.git#egg=x
numpy==1.26.4 ; python_version >= "3.9"
`
	deps := parseRequirements(content, "requirements.txt")
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d: %+v", len(deps), deps)
	}
	if deps[0].Name != "requests" || deps[0].Version != "2.31.0" {
		t.Fatalf("unexpected dep: %+v", deps[0])
	}
	if deps[1].Version != "1.26.4" {
		t.Fatalf("env marker not stripped: %+v", deps[1])
	}
}

func TestCVSSSeverity(t *testing.T) {
	cases := []struct {
		score string
		want  string
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H:9.8", "critical"},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N:7.5", "high"},
		{"CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N:3.1", "low"},
		{"bogus", "medium"},
	}
	for _, c := range cases {
		got := cvssSeverity([]struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		}{{Type: "CVSS_V3", Score: c.score}})
		if got != c.want {
			t.Fatalf("score %q: got %q want %q", c.score, got, c.want)
		}
	}
	if got := cvssSeverity(nil); got != "medium" {
		t.Fatalf("empty severities: got %q", got)
	}
}

func TestBuildPRCommentBody(t *testing.T) {
	body := buildPRCommentBody(nil)
	if !strings.Contains(body, "No findings") {
		t.Fatal("empty findings body missing message")
	}
	findings := []review.Finding{
		{Rule: "ssrf", Severity: "high", File: "a.go", Line: 10, Message: "possible SSRF"},
		{Rule: "todo-marker", Severity: "info", File: "b.py", Line: 2, Message: "TODO left"},
	}
	body = buildPRCommentBody(findings)
	if !strings.Contains(body, "2 finding(s)") || !strings.Contains(body, "1 high") || !strings.Contains(body, "`a.go:10`") {
		t.Fatalf("body missing expected content:\n%s", body)
	}
}

func TestRuleAllowed(t *testing.T) {
	if !ruleAllowed(nil, nil, "x") {
		t.Fatal("nil filters should allow")
	}
	if !ruleAllowed([]string{"x", "y"}, nil, "x") {
		t.Fatal("only-list should allow listed rule")
	}
	if ruleAllowed([]string{"x"}, nil, "z") {
		t.Fatal("only-list should block unlisted rule")
	}
	if ruleAllowed(nil, []string{"x"}, "x") {
		t.Fatal("skip-list should block")
	}
}
