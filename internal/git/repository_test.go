package git

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRepositoryRoot(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	root, err := RepositoryRoot(repoDir)
	if err != nil {
		t.Fatalf("RepositoryRoot() error: %v", err)
	}

	if root != filepath.Clean(repoDir) {
		t.Errorf("RepositoryRoot() = %q, want %q", root, filepath.Clean(repoDir))
	}
}
