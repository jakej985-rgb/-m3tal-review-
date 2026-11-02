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

	trackedPath := filepath.Join(repoDir, "tracked.txt")
	if err := os.WriteFile(trackedPath, []byte("initial"), 0644); err != nil {
		t.Fatalf("write tracked file: %v", err)
	}

	add := exec.Command("git", "-C", repoDir, "add", "tracked.txt")
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage tracked file: %v\n%s", err, output)
	}

	commit := exec.Command(
		"git", "-C", repoDir,
		"-c", "user.name=Test User",
		"-c", "user.email=test@example.com",
		"commit", "-m", "add tracked file",
	)
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("commit tracked file: %v\n%s", err, output)
	}

	if err := os.WriteFile(trackedPath, []byte("modified"), 0644); err != nil {
		t.Fatalf("modify tracked file: %v", err)
	}

	clean, err = IsClean(repoDir)
	if err != nil {
		t.Fatalf("IsClean() error after tracked file modification: %v", err)
	}
	if clean {
		t.Fatal("IsClean() = true, want false when a tracked file is modified")
	}
}

func TestCurrentBranch(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	createBranch := exec.Command("git", "-C", repoDir, "checkout", "-b", "review-test")
	if output, err := createBranch.CombinedOutput(); err != nil {
		t.Fatalf("create test branch: %v\n%s", err, output)
	}

	branch, err := CurrentBranch(repoDir)
	if err != nil {
		t.Fatalf("CurrentBranch() error: %v", err)
	}

	if branch != "review-test" {
		t.Errorf("CurrentBranch() = %q, want %q", branch, "review-test")
	}
}

func TestCurrentBranchDetachedHEAD(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	configureName := exec.Command("git", "-C", repoDir, "config", "user.name", "Test User")
	if output, err := configureName.CombinedOutput(); err != nil {
		t.Fatalf("configure git user name: %v\n%s", err, output)
	}

	configureEmail := exec.Command("git", "-C", repoDir, "config", "user.email", "test@example.com")
	if output, err := configureEmail.CombinedOutput(); err != nil {
		t.Fatalf("configure git user email: %v\n%s", err, output)
	}

	filePath := filepath.Join(repoDir, "README.md")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	add := exec.Command("git", "-C", repoDir, "add", "README.md")
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage test file: %v\n%s", err, output)
	}

	commit := exec.Command("git", "-C", repoDir, "commit", "-m", "initial commit")
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("create initial commit: %v\n%s", err, output)
	}

	detach := exec.Command("git", "-C", repoDir, "checkout", "--detach", "HEAD")
	if output, err := detach.CombinedOutput(); err != nil {
		t.Fatalf("detach HEAD: %v\n%s", err, output)
	}

	branch, err := CurrentBranch(repoDir)
	if err == nil {
		t.Fatalf("CurrentBranch() = %q, want error for detached HEAD", branch)
	}
}
