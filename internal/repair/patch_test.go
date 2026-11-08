package repair

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestApplyPatchToContentNewFile(t *testing.T) {
	patch := `--- /dev/null
+++ b/created.txt
@@ -0,0 +1,2 @@
+hello
+world
`
	res, err := ApplyPatchToContent("", patch)
	if err != nil {
		t.Fatalf("unexpected error applying new file patch: %v", err)
	}
	expected := "hello\nworld\n"
	if res != expected {
		t.Fatalf("got %q, want %q", res, expected)
	}
}

func TestApplyPatchToContentModification(t *testing.T) {
	orig := "line1\nline2\nline3\n"
	patch := `--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2_modified
 line3
`
	res, err := ApplyPatchToContent(orig, patch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "line1\nline2_modified\nline3\n"
	if res != expected {
		t.Fatalf("got %q, want %q", res, expected)
	}
}

func TestApplyPatchToContentContextMismatch(t *testing.T) {
	orig := "different_line1\nline2\nline3\n"
	patch := `--- a/file.txt
+++ b/file.txt
@@ -1,3 +1,3 @@
 line1
-line2
+line2_modified
 line3
`
	_, err := ApplyPatchToContent(orig, patch)
	if err == nil {
		t.Fatal("expected context mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "hunk context mismatch") {
		t.Fatalf("expected hunk context mismatch error, got: %v", err)
	}
}

func TestApplyProposalToFile(t *testing.T) {
	tmp := t.TempDir()
	targetFile := "sub/target.txt"
	origContent := "foo\nbar\n"
	propContent := "foo\nbaz\n"

	p := NewProposal("p1", review.Finding{}, "test-fixer", targetFile, origContent, propContent, "test explanation")

	// Pre-create file
	targetAbs := filepath.Join(tmp, targetFile)
	_ = os.MkdirAll(filepath.Dir(targetAbs), 0755)
	if err := os.WriteFile(targetAbs, []byte(origContent), 0644); err != nil {
		t.Fatal(err)
	}

	if err := ApplyProposalToFile(tmp, p); err != nil {
		t.Fatalf("ApplyProposalToFile failed: %v", err)
	}

	data, err := os.ReadFile(targetAbs)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != propContent {
		t.Fatalf("got %q, want %q", string(data), propContent)
	}
}
