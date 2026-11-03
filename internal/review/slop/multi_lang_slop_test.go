package slop_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func stageNonGoSlopSource(t *testing.T, name, source string) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git", "init")
	cmd.Dir = repo
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, output)
	}
	cmd = exec.Command("git", "add", name)
	cmd.Dir = repo
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, output)
	}
	return repo
}

func fullSourceDiff(file, source string) string {
	lines := []string{}
	if source != "" {
		lines = strings.Split(strings.TrimSuffix(source, "\n"), "\n")
	}
	var diff strings.Builder
	fmt.Fprintf(&diff, "diff --git a/%s b/%s\nnew file mode 100644\n--- /dev/null\n+++ b/%s\n@@ -0,0 +1,%d @@\n", file, file, file, len(lines))
	for _, line := range lines {
		diff.WriteByte('+')
		diff.WriteString(line)
		diff.WriteByte('\n')
	}
	return diff.String()
}
