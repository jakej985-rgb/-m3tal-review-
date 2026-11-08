package repair

import (
	"strings"
	"testing"
)

func TestFileToAddedDiff(t *testing.T) {
	diff := FileToAddedDiff("pkg/foo.go", "package pkg\nvar x = 1\n")
	if !strings.Contains(diff, "--- /dev/null") {
		t.Errorf("expected /dev/null header, got:\n%s", diff)
	}
	if !strings.Contains(diff, "+++ b/pkg/foo.go") {
		t.Errorf("expected b/pkg/foo.go header, got:\n%s", diff)
	}
	if !strings.Contains(diff, "@@ -0,0 +1,2 @@") {
		t.Errorf("expected @@ -0,0 +1,2 @@, got:\n%s", diff)
	}

	// Empty content
	emptyDiff := FileToAddedDiff("empty.txt", "")
	if !strings.Contains(emptyDiff, "@@ -0,0 +0,0 @@") {
		t.Errorf("expected @@ -0,0 +0,0 @@ for empty content, got:\n%s", emptyDiff)
	}
}

func TestGenerateUnifiedDiff(t *testing.T) {
	orig := "a\nb\nc\nd\ne\n"
	prop := "a\nb\nC_MODIFIED\nd\ne\n"

	diff := GenerateUnifiedDiff("letters.txt", orig, prop)
	if !strings.Contains(diff, "--- a/letters.txt") || !strings.Contains(diff, "+++ b/letters.txt") {
		t.Fatalf("unexpected headers: %s", diff)
	}
	if !strings.Contains(diff, "-c") || !strings.Contains(diff, "+C_MODIFIED") {
		t.Fatalf("unexpected diff body: %s", diff)
	}

	// Identical content returns empty diff
	identicalDiff := GenerateUnifiedDiff("letters.txt", orig, orig)
	if identicalDiff != "" {
		t.Fatalf("expected empty diff for identical content, got: %q", identicalDiff)
	}
}

func TestGenerateUnifiedDiffLargeFile(t *testing.T) {
	// 5000 lines, only 1 changed
	var origBuilder, propBuilder strings.Builder
	for i := 1; i <= 5000; i++ {
		if i == 2500 {
			origBuilder.WriteString("original_line_2500\n")
			propBuilder.WriteString("modified_line_2500\n")
		} else {
			origBuilder.WriteString("common_line\n")
			propBuilder.WriteString("common_line\n")
		}
	}

	diff := GenerateUnifiedDiff("large.txt", origBuilder.String(), propBuilder.String())
	if !strings.Contains(diff, "-original_line_2500") || !strings.Contains(diff, "+modified_line_2500") {
		t.Fatalf("diff missing modified line: %s", diff)
	}
}
