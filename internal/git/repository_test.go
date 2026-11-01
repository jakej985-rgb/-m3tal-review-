package git

import (
	"os"
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

func TestRepositoryRootOutsideRepository(t *testing.T) {
	dir := t.TempDir()

	_, err := RepositoryRoot(dir)
	if err == nil {
		t.Fatal("RepositoryRoot() expected an error for a non-repository directory")
	}
}

func TestIsClean(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	clean, err := IsClean(repoDir)
	if err != nil {
		t.Fatalf("IsClean() error: %v", err)
	}
	if !clean {
		t.Fatal("IsClean() = false, want true for a clean repository")
	}

	filePath := filepath.Join(repoDir, "untracked.txt")
	if err := os.WriteFile(filePath, []byte("change"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	clean, err = IsClean(repoDir)
	if err != nil {
		t.Fatalf("IsClean() error after file creation: %v", err)
	}
	if clean {
		t.Fatal("IsClean() = true, want false when an untracked file exists")
	}
}
