package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func TestChangedFiles(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	filePath := filepath.Join(repoDir, "tracked.txt")
	if err := os.WriteFile(filePath, []byte("initial"), 0644); err != nil {
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
		"commit", "-m", "initial commit",
	)
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("create initial commit: %v\n%s", err, output)
	}

	if err := os.WriteFile(filePath, []byte("modified"), 0644); err != nil {
		t.Fatalf("modify tracked file: %v", err)
	}

	files, err := ChangedFiles(repoDir)
	if err != nil {
		t.Fatalf("ChangedFiles() error: %v", err)
	}

	if len(files) != 1 || files[0] != "tracked.txt" {
		t.Fatalf("ChangedFiles() = %v, want [tracked.txt]", files)
	}
}

func TestChangedFilesHandlesNewlineInFilename(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	filename := "file\nwith-newline.txt"
	filePath := filepath.Join(repoDir, filename)
	if err := os.WriteFile(filePath, []byte("initial"), 0644); err != nil {
		t.Fatalf("write file with newline: %v", err)
	}

	add := exec.Command("git", "-C", repoDir, "add", filename)
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage file with newline: %v\n%s", err, output)
	}

	commit := exec.Command(
		"git", "-C", repoDir,
		"-c", "user.name=Test User",
		"-c", "user.email=test@example.com",
		"commit", "-m", "initial commit",
	)
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("create initial commit: %v\n%s", err, output)
	}

	if err := os.WriteFile(filePath, []byte("modified"), 0644); err != nil {
		t.Fatalf("modify file with newline: %v", err)
	}

	files, err := ChangedFiles(repoDir)
	if err != nil {
		t.Fatalf("ChangedFiles() error: %v", err)
	}

	if len(files) != 1 || files[0] != filename {
		t.Fatalf("ChangedFiles() = %q, want [%q]", files, filename)
	}
}

func TestUntrackedFiles(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	filePath := filepath.Join(repoDir, "new-file.txt")
	if err := os.WriteFile(filePath, []byte("new"), 0644); err != nil {
		t.Fatalf("write untracked file: %v", err)
	}

	files, err := UntrackedFiles(repoDir)
	if err != nil {
		t.Fatalf("UntrackedFiles() error: %v", err)
	}

	if len(files) != 1 || files[0] != "new-file.txt" {
		t.Fatalf("UntrackedFiles() = %v, want [new-file.txt]", files)
	}
}

func TestUntrackedFilesIgnoresGitIgnoredFiles(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	ignorePath := filepath.Join(repoDir, ".gitignore")
	if err := os.WriteFile(ignorePath, []byte("ignored.txt\n"), 0644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}

	visiblePath := filepath.Join(repoDir, "visible.txt")
	if err := os.WriteFile(visiblePath, []byte("visible"), 0644); err != nil {
		t.Fatalf("write visible file: %v", err)
	}

	ignoredPath := filepath.Join(repoDir, "ignored.txt")
	if err := os.WriteFile(ignoredPath, []byte("ignored"), 0644); err != nil {
		t.Fatalf("write ignored file: %v", err)
	}

	files, err := UntrackedFiles(repoDir)
	if err != nil {
		t.Fatalf("UntrackedFiles() error: %v", err)
	}

	if len(files) != 2 {
		t.Fatalf("UntrackedFiles() = %v, want [.gitignore visible.txt]", files)
	}

	if files[0] != ".gitignore" || files[1] != "visible.txt" {
		t.Fatalf("UntrackedFiles() = %v, want [.gitignore visible.txt]", files)
	}
}

func TestUntrackedFilesHandlesNewlineInFilename(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	filename := "file\nwith-newline.txt"
	filePath := filepath.Join(repoDir, filename)

	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("write file with newline: %v", err)
	}

	files, err := UntrackedFiles(repoDir)
	if err != nil {
		t.Fatalf("UntrackedFiles() error: %v", err)
	}

	if len(files) != 1 || files[0] != filename {
		t.Fatalf("UntrackedFiles() = %q, want [%q]", files, filename)
	}
}

func TestStagedFiles(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	filePath := filepath.Join(repoDir, "staged.txt")
	if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
		t.Fatalf("write staged file: %v", err)
	}

	add := exec.Command("git", "-C", repoDir, "add", "staged.txt")
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage file: %v\n%s", err, output)
	}

	files, err := StagedFiles(repoDir)
	if err != nil {
		t.Fatalf("StagedFiles() error: %v", err)
	}

	if len(files) != 1 || files[0] != "staged.txt" {
		t.Fatalf("StagedFiles() = %v, want [staged.txt]", files)
	}
}

func TestStagedFilesEmpty(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	files, err := StagedFiles(repoDir)
	if err != nil {
		t.Fatalf("StagedFiles() error: %v", err)
	}

	if len(files) != 0 {
		t.Fatalf("StagedFiles() = %v, want empty slice", files)
	}
}

func TestStagedFilesHandlesNewlineInFilename(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	filename := "file\nwith-newline.txt"
	filePath := filepath.Join(repoDir, filename)
	if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
		t.Fatalf("write file with newline: %v", err)
	}

	add := exec.Command("git", "-C", repoDir, "add", filename)
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage file with newline: %v\n%s", err, output)
	}

	files, err := StagedFiles(repoDir)
	if err != nil {
		t.Fatalf("StagedFiles() error: %v", err)
	}

	if len(files) != 1 || files[0] != filename {
		t.Fatalf("StagedFiles() = %q, want [%q]", files, filename)
	}
}

func TestStagedDiff(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	filePath := filepath.Join(repoDir, "file.txt")
	if err := os.WriteFile(filePath, []byte("original\n"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	add := exec.Command("git", "-C", repoDir, "add", "file.txt")
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("stage file: %v\n%s", err, output)
	}

	commit := exec.Command(
		"git", "-C", repoDir,
		"-c", "user.name=Test User",
		"-c", "user.email=test@example.com",
		"commit", "-m", "initial commit",
	)
	if output, err := commit.CombinedOutput(); err != nil {
		t.Fatalf("commit file: %v\n%s", err, output)
	}

	if err := os.WriteFile(filePath, []byte("staged change\n"), 0644); err != nil {
		t.Fatalf("modify file: %v", err)
	}

	addStaged := exec.Command("git", "-C", repoDir, "add", "file.txt")
	if output, err := addStaged.CombinedOutput(); err != nil {
		t.Fatalf("stage file modification: %v\n%s", err, output)
	}

	if err := os.WriteFile(filePath, []byte("unstaged change\n"), 0644); err != nil {
		t.Fatalf("modify file again: %v", err)
	}

	diff, err := StagedDiff(repoDir)
	if err != nil {
		t.Fatalf("StagedDiff() error: %v", err)
	}

	if !strings.Contains(diff, "staged change") {
		t.Fatalf("expected staged change in diff:\n%s", diff)
	}

	if strings.Contains(diff, "unstaged change") {
		t.Fatalf("diff included unstaged change:\n%s", diff)
	}
}

func TestStagedFileStatuses(t *testing.T) {
	repoDir := t.TempDir()

	initRepo := exec.Command("git", "init", repoDir)
	if output, err := initRepo.CombinedOutput(); err != nil {
		t.Fatalf("initialize test repository: %v\n%s", err, output)
	}

	runGit := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v error: %v\n%s", args, err, out)
		}
	}

	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")

	// Commit initial files
	fileA := filepath.Join(repoDir, "to_modify.txt")
	fileB := filepath.Join(repoDir, "to_delete.txt")
	fileC := filepath.Join(repoDir, "to_rename with space.txt")
	os.WriteFile(fileA, []byte("orig content a"), 0644)
	os.WriteFile(fileB, []byte("orig content b"), 0644)
	os.WriteFile(fileC, []byte("orig content c"), 0644)

	runGit("add", ".")
	runGit("commit", "-m", "initial")

	// Now stage:
	// 1. Addition (with space)
	fileAdd := filepath.Join(repoDir, "new file.txt")
	os.WriteFile(fileAdd, []byte("new"), 0644)
	runGit("add", "new file.txt")

	// 2. Modification
	os.WriteFile(fileA, []byte("modified"), 0644)
	runGit("add", "to_modify.txt")

	// 3. Deletion
	runGit("rm", "to_delete.txt")

	// 4. Rename (with space)
	runGit("mv", "to_rename with space.txt", "renamed file.txt")

	statuses, err := StagedFileStatuses(repoDir)
	if err != nil {
		t.Fatalf("StagedFileStatuses() error: %v", err)
	}

	if statuses["new file.txt"] != "A" {
		t.Errorf("status of new file.txt = %q, want 'A'", statuses["new file.txt"])
	}
	if statuses["to_modify.txt"] != "M" {
		t.Errorf("status of to_modify.txt = %q, want 'M'", statuses["to_modify.txt"])
	}
	if statuses["to_delete.txt"] != "D" {
		t.Errorf("status of to_delete.txt = %q, want 'D'", statuses["to_delete.txt"])
	}
	if !strings.HasPrefix(statuses["renamed file.txt"], "R") {
		t.Errorf("status of renamed file.txt = %q, want starting with 'R'", statuses["renamed file.txt"])
	}
}
