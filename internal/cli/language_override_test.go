package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReviewLanguageOverridesFromRepoConfig(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	// Create .m3tal-review-config.json with language_overrides
	cfgJSON := `{"language_overrides": {"*.custom": "python"}}`
	if err := os.WriteFile(filepath.Join(repoDir, ".m3tal-review-config.json"), []byte(cfgJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Create a file with custom extension containing python deserialization issue
	pyVuln := "import pickle\npickle.loads(user_input)\n"
	if err := os.WriteFile(filepath.Join(repoDir, "exploit.custom"), []byte(pyVuln), 0644); err != nil {
		t.Fatal(err)
	}

	runGit("add", ".m3tal-review-config.json", "exploit.custom")

	origWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWd) })

	output, err := captureOutput(func() error {
		return execute("review", "--format=json")
	})
	if err != nil && !strings.Contains(err.Error(), "findings") && !strings.Contains(err.Error(), "issue") {
		t.Fatalf("execute review failed unexpectedly: %v\noutput: %s", err, output)
	}

	if !strings.Contains(output, "unsafe-deserialization") {
		t.Errorf("expected unsafe-deserialization finding for .custom overridden to python:\n%s", output)
	}
}
