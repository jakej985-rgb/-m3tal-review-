package review

import (
	"strings"
	"testing"
)

func TestSnippetGeneratorFromDiffAddedLine(t *testing.T) {
	diff := `diff --git a/pkg/auth.go b/pkg/auth.go
index 1234567..89abcdef 100644
--- a/pkg/auth.go
+++ b/pkg/auth.go
@@ -10,5 +10,6 @@ func Authenticate(token string) bool {
 	if token == "" {
 		return false
 	}
+	apiKey := "sk-live-abcdef123456"
 	return checkToken(token)
 }
`
	finding := Finding{
		Rule:     "hardcoded-credential",
		Severity: "high",
		File:     "pkg/auth.go",
		Line:     13,
		Message:  "Possible hardcoded credential",
	}

	snip := GenerateFindingSnippet(diff, finding, 2)
	if snip == nil {
		t.Fatalf("expected snippet, got nil")
	}

	if snip.File != "pkg/auth.go" {
		t.Errorf("expected File pkg/auth.go, got %s", snip.File)
	}
	if snip.Line != 13 {
		t.Errorf("expected Line 13, got %d", snip.Line)
	}
	if snip.Language != "go" {
		t.Errorf("expected Language go, got %s", snip.Language)
	}

	foundTarget := false
	for _, l := range snip.Lines {
		if l.LineNumber == 13 {
			foundTarget = true
			if !l.IsFinding {
				t.Errorf("line 13 should be marked IsFinding")
			}
			if l.Kind != SnippetLineAdded {
				t.Errorf("line 13 should be SnippetLineAdded, got %s", l.Kind)
			}
			if !strings.Contains(l.Content, "apiKey :=") {
				t.Errorf("unexpected content: %s", l.Content)
			}
		}
	}
	if !foundTarget {
		t.Errorf("target line 13 not found in snippet lines")
	}

	// Verify formatted text has marker '>'
	text := snip.FormattedText
	if !strings.Contains(text, ">") {
		t.Errorf("expected text snippet to contain marker '>', got:\n%s", text)
	}
	if !strings.Contains(text, "+") {
		t.Errorf("expected text snippet to contain diff marker '+', got:\n%s", text)
	}
}

func TestSnippetGeneratorWithDeletedAndModifiedLines(t *testing.T) {
	diff := `diff --git a/service/client.py b/service/client.py
--- a/service/client.py
+++ b/service/client.py
@@ -5,4 +5,4 @@ def connect():
     timeout = 30
-    verify = False
+    verify = True
     return Client(timeout=timeout, verify=verify)
`
	finding := Finding{
		Rule:     "tls-verification",
		Severity: "medium",
		File:     "service/client.py",
		Line:     6,
		Message:  "TLS verification modified",
	}

	gen := NewSnippetGenerator(diff, WithContextRadius(2))
	snip := gen.GenerateSnippet(finding)
	if snip == nil {
		t.Fatalf("expected snippet, got nil")
	}

	if snip.Language != "python" {
		t.Errorf("expected python, got %s", snip.Language)
	}

	hasDeleted := false
	hasAdded := false
	for _, l := range snip.Lines {
		if l.Kind == SnippetLineDeleted {
			hasDeleted = true
			if !strings.Contains(l.Content, "verify = False") {
				t.Errorf("expected deleted line content 'verify = False', got %s", l.Content)
			}
		}
		if l.Kind == SnippetLineAdded {
			hasAdded = true
			if !strings.Contains(l.Content, "verify = True") {
				t.Errorf("expected added line content 'verify = True', got %s", l.Content)
			}
			if !l.IsFinding {
				t.Errorf("expected line 6 to be marked IsFinding")
			}
		}
	}

	if !hasDeleted {
		t.Errorf("expected snippet to include deleted line")
	}
	if !hasAdded {
		t.Errorf("expected snippet to include added line")
	}

	// Verify Markdown formatting
	md := snip.FormattedMarkdown
	if !strings.HasPrefix(md, "```python\n") {
		t.Errorf("markdown should start with ```python, got:\n%s", md)
	}
	if !strings.HasSuffix(md, "```\n") {
		t.Errorf("markdown should end with ```\\n, got:\n%s", md)
	}

	// Verify HTML formatting
	htmlOut := snip.FormattedHTML
	if !strings.Contains(htmlOut, `class="snippet" data-language="python"`) {
		t.Errorf("HTML should contain snippet data-language, got:\n%s", htmlOut)
	}
	if !strings.Contains(htmlOut, "snippet-deleted") {
		t.Errorf("HTML should contain snippet-deleted class")
	}
	if !strings.Contains(htmlOut, "snippet-finding") {
		t.Errorf("HTML should contain snippet-finding class")
	}
}

func TestSnippetGeneratorFileSourceFallback(t *testing.T) {
	fileContent := `package main

import "fmt"

func main() {
	x := 10
	y := 20
	z := x + y
	fmt.Println(z)
}
`
	finding := Finding{
		Rule:     "unused-var",
		Severity: "low",
		File:     "main.go",
		Line:     8,
		Message:  "Calculation result",
	}

	// Generate without diff, but with injected file source
	gen := NewSnippetGenerator("", WithContextRadius(2), WithFileSource("main.go", fileContent))
	snip := gen.GenerateSnippet(finding)
	if snip == nil {
		t.Fatalf("expected snippet from file source fallback, got nil")
	}

	if snip.Line != 8 {
		t.Errorf("expected line 8, got %d", snip.Line)
	}
	if len(snip.Lines) != 5 { // lines 6, 7, 8, 9, 10
		t.Errorf("expected 5 lines for radius 2 around line 8, got %d", len(snip.Lines))
	}

	for _, l := range snip.Lines {
		if l.LineNumber == 8 {
			if !l.IsFinding {
				t.Errorf("line 8 should be marked finding")
			}
			if !strings.Contains(l.Content, "z := x + y") {
				t.Errorf("unexpected content for line 8: %s", l.Content)
			}
		}
	}
}

func TestSnippetGeneratorLanguageDetection(t *testing.T) {
	cases := []struct {
		file     string
		expected string
	}{
		{"cmd/main.go", "go"},
		{"frontend/index.js", "javascript"},
		{"src/app.tsx", "typescript"},
		{"scripts/deploy.py", "python"},
		{"App.java", "java"},
		{"main.rs", "rust"},
		{"script.sh", "shell"},
		{"Dockerfile", "dockerfile"},
		{"config.yaml", "yaml"},
		{"schema.json", "json"},
		{"unknown.xyz", "text"},
	}

	for _, c := range cases {
		got := DetectLanguage(c.file)
		if got != c.expected {
			t.Errorf("DetectLanguage(%q) = %q, want %q", c.file, got, c.expected)
		}
	}
}

func TestAttachSnippets(t *testing.T) {
	diff := `diff --git a/config.go b/config.go
--- a/config.go
+++ b/config.go
@@ -1,3 +1,4 @@
 package config
+var Secret = "super-secret"
 func Get() string {
`
	findings := []Finding{
		{
			Rule:     "secret-material",
			Severity: "high",
			File:     "config.go",
			Line:     2,
			Message:  "Exposed secret",
		},
		{
			Rule:     "empty-rule",
			Severity: "low",
			File:     "",
			Line:     0,
		},
	}

	attached := AttachSnippets(findings, diff, "", false)
	if len(attached) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(attached))
	}

	if attached[0].Snippet == "" {
		t.Errorf("expected finding 0 to have snippet populated")
	}
	if !strings.Contains(attached[0].Snippet, "var Secret = \"super-secret\"") {
		t.Errorf("unexpected snippet: %s", attached[0].Snippet)
	}

	if attached[1].Snippet != "" {
		t.Errorf("expected finding 1 with empty file to have empty snippet, got %s", attached[1].Snippet)
	}

	// Test AttachSnippetsToReport
	report := &Report{
		Findings: findings,
	}
	AttachSnippetsToReport(report, diff, "", false)
	if report.Findings[0].Snippet == "" {
		t.Errorf("expected report finding 0 to have snippet populated")
	}
}

func TestSnippetGeneratorEdgeCases(t *testing.T) {
	gen := NewSnippetGenerator("")

	// Empty file
	if snip := gen.GenerateSnippet(Finding{File: ""}); snip != nil {
		t.Errorf("expected nil snippet for empty file")
	}

	// Non-existent file and no diff
	if snip := gen.GenerateSnippet(Finding{File: "nonexistent.go", Line: 5}); snip != nil {
		t.Errorf("expected nil snippet for non-existent file without source")
	}

	// Format nil snippet
	if txt := FormatSnippetText(nil); txt != "" {
		t.Errorf("expected empty string for nil snippet")
	}
	if md := FormatSnippetMarkdown(nil); md != "" {
		t.Errorf("expected empty string for nil snippet")
	}
	if h := FormatSnippetHTML(nil); h != "" {
		t.Errorf("expected empty string for nil snippet")
	}
}

func TestSnippetGeneratorDeletedFileOnly(t *testing.T) {
	diff := `diff --git a/deprecated.go b/deprecated.go
deleted file mode 100644
--- a/deprecated.go
+++ /dev/null
@@ -1,3 +0,0 @@
-package old
-var SecretKey = "exposed-old-key"
-func Cleanup() {}
`
	finding := Finding{
		Rule:     "exposed-secret",
		Severity: "high",
		File:     "deprecated.go",
		Line:     2,
		Message:  "Key in deleted file",
	}

	gen := NewSnippetGenerator(diff, WithContextRadius(2))
	snip := gen.GenerateSnippet(finding)
	if snip == nil {
		t.Fatalf("expected snippet for deleted file finding, got nil")
	}

	if snip.StartLine != 1 || snip.EndLine != 3 {
		t.Errorf("expected startLine=1 endLine=3, got start=%d end=%d", snip.StartLine, snip.EndLine)
	}

	foundTarget := false
	for _, l := range snip.Lines {
		if l.Kind != SnippetLineDeleted {
			t.Errorf("expected all lines to be SnippetLineDeleted, got %s", l.Kind)
		}
		if l.LineNumber != 0 {
			t.Errorf("expected LineNumber 0 for deleted line, got %d", l.LineNumber)
		}
		if l.OldLineNumber == 2 {
			foundTarget = true
			if !l.IsFinding {
				t.Errorf("line 2 should be marked IsFinding")
			}
			if !strings.Contains(l.Content, "SecretKey") {
				t.Errorf("unexpected content: %s", l.Content)
			}
		}
	}
	if !foundTarget {
		t.Errorf("target deleted line 2 was not found in snippet")
	}

	text := snip.FormattedText
	if !strings.Contains(text, ">") || !strings.Contains(text, "-") {
		t.Errorf("expected text snippet to have marker '>' and '-':\n%s", text)
	}
}

func TestSnippetGeneratorTargetLineOutOfBounds(t *testing.T) {
	content := "line 1\nline 2\nline 3\n"
	gen := NewSnippetGenerator("", WithContextRadius(2), WithFileSource("small.txt", content))

	// Finding line 50 does not exist in 3-line file
	finding := Finding{File: "small.txt", Line: 50}
	snip := gen.GenerateSnippet(finding)
	if snip != nil {
		t.Errorf("expected nil snippet for out-of-bounds line 50 in 3-line file, got %+v", snip)
	}
}

func TestSnippetGeneratorDeletedLineVsAddedLineMarkers(t *testing.T) {
	diff := `diff --git a/api.py b/api.py
--- a/api.py
+++ b/api.py
@@ -10,3 +10,3 @@ def handle():
     auth = True
-    secret = "old_secret_123"
+    secret = "new_secret_456"
     return auth
`
	// Finding targets line 11 (the added replacement line)
	finding := Finding{
		Rule:     "exposed-secret",
		Severity: "high",
		File:     "api.py",
		Line:     11,
	}

	gen := NewSnippetGenerator(diff, WithContextRadius(2))
	snip := gen.GenerateSnippet(finding)
	if snip == nil {
		t.Fatalf("expected snippet, got nil")
	}

	addedMarked := false
	deletedMarked := false
	for _, l := range snip.Lines {
		if l.Kind == SnippetLineAdded && l.IsFinding {
			addedMarked = true
		}
		if l.Kind == SnippetLineDeleted && l.IsFinding {
			deletedMarked = true
		}
	}

	if !addedMarked {
		t.Errorf("expected added line to be marked finding")
	}
	if deletedMarked {
		t.Errorf("deleted line should NOT be marked finding when added line is the target")
	}
}
