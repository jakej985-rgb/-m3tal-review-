package prreview

import (
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestGeneratePRReview(t *testing.T) {
	diffText := `diff --git a/pkg/auth/token.go b/pkg/auth/token.go
--- a/pkg/auth/token.go
+++ b/pkg/auth/token.go
@@ -10,3 +10,5 @@ package auth
+func InsecureHandler() {
+	exec.Command("sh", "-c", "echo test")
+}
`
	fileDiffs, err := ParseUnifiedDiff(diffText)
	if err != nil {
		t.Fatalf("parse diff: %v", err)
	}

	findings := []review.Finding{
		{
			Rule:        "pipe-to-shell",
			Severity:    "critical",
			Confidence:  "high",
			File:        "pkg/auth/token.go",
			Line:        11,
			Message:     "Direct execution of shell command detected",
			Remediation: "Use sanitized argument lists without spawning a shell",
		},
		{
			Rule:       "trailing-whitespace",
			Severity:   "low",
			Confidence: "medium",
			File:       "pkg/auth/token.go",
			Line:       10,
			Message:    "Trailing whitespace detected",
		},
	}

	opts := FormatOptions{
		CommentOnly: false,
	}

	report, err := GeneratePRReview(findings, fileDiffs, opts)
	if err != nil {
		t.Fatalf("GeneratePRReview error: %v", err)
	}

	if report.Verdict != VerdictRequestChanges {
		t.Errorf("expected VerdictRequestChanges, got %s", report.Verdict)
	}
	if report.CriticalCount != 1 {
		t.Errorf("expected 1 critical finding, got %d", report.CriticalCount)
	}
	if report.LowCount != 1 {
		t.Errorf("expected 1 low finding, got %d", report.LowCount)
	}

	// Critical finding should be in InlineComments
	if len(report.InlineComments) != 1 {
		t.Fatalf("expected 1 inline comment, got %d", len(report.InlineComments))
	}
	ic := report.InlineComments[0]
	if ic.Rule != "pipe-to-shell" {
		t.Errorf("expected pipe-to-shell inline comment, got %s", ic.Rule)
	}
	if ic.Line != 11 {
		t.Errorf("expected line 11, got %d", ic.Line)
	}
	if !strings.Contains(ic.Body, "Remediation Guidance") {
		t.Errorf("expected remediation guidance in inline comment body")
	}

	// Top-level summary should contain marker tag
	if !strings.Contains(report.SummaryMarkdown, SummaryMarkerTag) {
		t.Errorf("expected summary markdown to contain %s", SummaryMarkerTag)
	}

	// Top-level summary should contain collapsible low-severity finding
	if !strings.Contains(report.SummaryMarkdown, "<details>") {
		t.Errorf("expected summary markdown to contain collapsible details")
	}
	if !strings.Contains(report.SummaryMarkdown, "trailing-whitespace") {
		t.Errorf("expected summary markdown to contain trailing-whitespace")
	}

	// Walkthrough should contain the Component Walkthrough table
	if !strings.Contains(report.SummaryMarkdown, "Component Walkthrough") {
		t.Errorf("expected summary markdown to contain Component Walkthrough table")
	}
}

func TestGeneratePRReview_CommentOnly(t *testing.T) {
	findings := []review.Finding{
		{
			Rule:     "insecure-cookie",
			Severity: "high",
			File:     "server.go",
			Line:     5,
			Message:  "Cookie without Secure flag",
		},
	}
	opts := FormatOptions{
		CommentOnly: true,
	}
	report, err := GeneratePRReview(findings, nil, opts)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if report.Verdict != VerdictComment {
		t.Errorf("expected VerdictComment under CommentOnly mode, got %s", report.Verdict)
	}
}

func TestGeneratePRReview_FindingOutsideDiffHunk(t *testing.T) {
	diffText := `diff --git a/pkg/auth/token.go b/pkg/auth/token.go
--- a/pkg/auth/token.go
+++ b/pkg/auth/token.go
@@ -10,3 +10,3 @@ package auth
 func InsecureHandler() {
+	println("ok")
 }
`
	fileDiffs, err := ParseUnifiedDiff(diffText)
	if err != nil {
		t.Fatalf("parse diff: %v", err)
	}

	// Line 999 is outside the hunk [10..12]
	findings := []review.Finding{
		{
			Rule:     "exposed-secret",
			Severity: "critical",
			File:     "pkg/auth/token.go",
			Line:     999,
			Message:  "Hardcoded token detected outside changed hunk",
		},
	}

	report, err := GeneratePRReview(findings, fileDiffs, FormatOptions{})
	if err != nil {
		t.Fatalf("GeneratePRReview: %v", err)
	}

	// Should NOT generate inline comment since line 999 is outside diff (would 422 on GitHub API)
	if len(report.InlineComments) != 0 {
		t.Fatalf("expected 0 inline comments for line outside diff, got %d", len(report.InlineComments))
	}

	// Finding should be in summary markdown
	if !strings.Contains(report.SummaryMarkdown, "exposed-secret") {
		t.Errorf("expected summary markdown to contain non-diff finding")
	}
	if !strings.Contains(report.SummaryMarkdown, "Additional Findings & Non-Diff Issues") {
		t.Errorf("expected summary markdown to contain 'Additional Findings & Non-Diff Issues'")
	}
}

func TestGeneratePRReview_LifecycleFindingsHaveNoAsyncGapSuggestion(t *testing.T) {
	diffText := `diff --git a/lib/screen.dart b/lib/screen.dart
--- a/lib/screen.dart
+++ b/lib/screen.dart
@@ -10,3 +10,4 @@ class Screen {
+    Theme.of(context);
+    context.watch<MyState>();
`
	fileDiffs, err := ParseUnifiedDiff(diffText)
	if err != nil {
		t.Fatalf("parse diff: %v", err)
	}

	findings := []review.Finding{
		{
			Rule:     "deactivated-context-lifecycle",
			Severity: "high",
			File:     "lib/screen.dart",
			Line:     10,
			Message:  "Calling Theme.of() inside dispose() attempts to query deactivated widget element ancestors",
			Snippet:  "    Theme.of(context);",
		},
		{
			Rule:     "watch-outside-build",
			Severity: "high",
			File:     "lib/screen.dart",
			Line:     11,
			Message:  "Calling context.watch() outside build",
			Snippet:  "    context.watch<MyState>();",
		},
	}

	report, err := GeneratePRReview(findings, fileDiffs, FormatOptions{})
	if err != nil {
		t.Fatalf("GeneratePRReview: %v", err)
	}

	for _, ic := range report.InlineComments {
		if strings.Contains(ic.Body, "```suggestion") {
			t.Errorf("expected no inline suggestion for lifecycle finding %s, got: %s", ic.Rule, ic.Body)
		}
		if strings.Contains(ic.Body, "if (!mounted) return;") || strings.Contains(ic.Body, "if (!context.mounted) return;") {
			t.Errorf("lifecycle finding %s must not offer async-gap mounted check suggestion", ic.Rule)
		}
	}
}
