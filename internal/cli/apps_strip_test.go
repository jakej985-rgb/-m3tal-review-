package cli

import (
	"strings"
	"testing"
)

func TestStripRoutedFilesFromDiff(t *testing.T) {
	diff := strings.Join([]string{
		"diff --git a/main.go b/main.go",
		"index 111..222 100644",
		"--- a/main.go",
		"+++ b/main.go",
		"@@ -1 +1 @@",
		"+func f() {}",
		"diff --git a/README.md b/README.md",
		"index 333..444 100644",
		"--- a/README.md",
		"+++ b/README.md",
		"@@ -1 +1 @@",
		"+hello",
		"",
	}, "\n")

	stripped := stripRoutedFilesFromDiff(diff, map[string]bool{"main.go": true})
	if strings.Contains(stripped, "main.go") {
		t.Fatalf("expected main.go to be stripped from diff:\n%s", stripped)
	}
	if !strings.Contains(stripped, "README.md") {
		t.Fatalf("expected README.md to remain in diff:\n%s", stripped)
	}
}
