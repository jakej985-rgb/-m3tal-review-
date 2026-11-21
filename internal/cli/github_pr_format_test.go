package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestFormatReportGitHubPR_EmptyFindings(t *testing.T) {
	grade := review.ComputeGrade(nil)
	rep := review.Report{
		Passed:   true,
		Findings: nil,
		Grade:    &grade,
	}

	out, err := formatReportGitHubPR(rep, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "✅ **Passed**") {
		t.Errorf("expected Passed verdict, got:\n%s", out)
	}
	if !strings.Contains(out, "No quality, security, or lifecycle issues detected") {
		t.Errorf("expected clean summary, got:\n%s", out)
	}
}

func TestFormatReportGitHubPR_WithSuggestion(t *testing.T) {
	tmpDir := t.TempDir()
	relPath := "lib/features/learn/lesson_screen.dart"
	fullPath := filepath.Join(tmpDir, relPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatal(err)
	}

	code := `class LessonScreen extends State<LessonScreenWidget> {
  void _fetch() async {
    await fetchLesson();
    setState(() {
      _loaded = true;
    });
  }
}
`
	if err := os.WriteFile(fullPath, []byte(code), 0644); err != nil {
		t.Fatal(err)
	}

	finding := review.Finding{
		Rule:        "unmounted-async-gap",
		Severity:    "high",
		Category:    "quality",
		Confidence:  "High",
		File:        relPath,
		Line:        4,
		Message:     "setState() called across async gap without mounted check",
		Remediation: "Guard with 'if (!mounted) return;' before setState()",
	}

	grade := review.ComputeGrade([]review.Finding{finding})
	rep := review.Report{
		Passed:   false,
		Findings: []review.Finding{finding},
		Grade:    &grade,
	}

	out, err := formatReportGitHubPR(rep, tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, "❌ **Changes Requested**") {
		t.Errorf("expected Changes Requested, got:\n%s", out)
	}
	if !strings.Contains(out, "unmounted-async-gap") {
		t.Errorf("expected finding rule name in report, got:\n%s", out)
	}
	if !strings.Contains(out, "💡 Available") {
		t.Errorf("expected Available suggestion status, got:\n%s", out)
	}
	if !strings.Contains(out, "```suggestion") {
		t.Errorf("expected ```suggestion block in report, got:\n%s", out)
	}
	if !strings.Contains(out, "if (!mounted) return;") {
		t.Errorf("expected mounted check in suggestion block, got:\n%s", out)
	}
}

func TestExtractSuggestionFromPatch(t *testing.T) {
	patch := `--- a/file.go
+++ b/file.go
@@ -10,3 +10,4 @@
 context before
-old code
+suggested code line 1
+suggested code line 2
 context after
`

	got := extractSuggestionFromPatch(patch, 11)
	expected := "suggested code line 1\nsuggested code line 2"
	if got != expected {
		t.Errorf("got %q, want %q", got, expected)
	}
}
