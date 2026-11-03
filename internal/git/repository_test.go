package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

func TestParseBinaryFilesFromNumstat(t *testing.T) {
	output := []byte("-\t-\timage.bin\x0012\t3\ttext file.go\x00-\t-\t\x00old.bin\x00new name.bin\x00")
	got, err := ParseBinaryFilesFromNumstat(output)
	if err != nil {
		t.Fatalf("ParseBinaryFilesFromNumstat() error: %v", err)
	}
	want := []string{"image.bin", "new name.bin"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseBinaryFilesFromNumstat() = %q, want %q", got, want)
	}
}

func TestParseBinaryFilesFromNumstatRejectsMalformedInput(t *testing.T) {
	if _, err := ParseBinaryFilesFromNumstat([]byte("not-numstat\x00")); err == nil {
		t.Fatal("expected malformed numstat error")
	}
}

func TestStagedSubmoduleFiles(t *testing.T) {
	repoDir := t.TempDir()
	runGit := func(args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, output)
		}
		return output
	}
	runGit("init")
	runGit("config", "user.name", "Test User")
	runGit("config", "user.email", "test@example.com")
	if err := os.WriteFile(filepath.Join(repoDir, "README.md"), []byte("baseline\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit("add", "README.md")
	runGit("commit", "-m", "initial")
	sha := strings.TrimSpace(string(runGit("rev-parse", "HEAD")))
	runGit("update-index", "--add", "--cacheinfo", "160000,"+sha+",vendor/lib")
	got, err := StagedSubmoduleFiles(repoDir)
	if err != nil {
		t.Fatalf("StagedSubmoduleFiles() error: %v", err)
	}
	if !reflect.DeepEqual(got, []string{"vendor/lib"}) {
		t.Fatalf("StagedSubmoduleFiles() = %q, want [vendor/lib]", got)
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
	if err != nil {
		t.Fatalf("CurrentBranch() error for detached HEAD: %v", err)
	}
	if !strings.Contains(branch, "(detached HEAD at ") {
		t.Fatalf("CurrentBranch() = %q, want detached HEAD label", branch)
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

func TestParseStagedFileStatusesValid(t *testing.T) {
	// Sample git diff -z stream containing A, M, D, R, C, and special characters (tab, space, symbols)
	specialName := "dir with space/file with\ttab and #special.txt"
	input := []byte(
		"A\x00new.txt\x00" +
			"M\x00" + specialName + "\x00" +
			"D\x00deleted.txt\x00" +
			"R100\x00old path.txt\x00renamed path.txt\x00" +
			"C095\x00source.txt\x00copied path.txt\x00",
	)

	statuses, err := ParseStagedFileStatuses(input)
	if err != nil {
		t.Fatalf("ParseStagedFileStatuses() unexpected error: %v", err)
	}

	if statuses["new.txt"] != "A" {
		t.Errorf("status for new.txt = %q, want 'A'", statuses["new.txt"])
	}
	if statuses[specialName] != "M" {
		t.Errorf("status for %q = %q, want 'M'", specialName, statuses[specialName])
	}
	if statuses["deleted.txt"] != "D" {
		t.Errorf("status for deleted.txt = %q, want 'D'", statuses["deleted.txt"])
	}
	if statuses["renamed path.txt"] != "R100" {
		t.Errorf("status for renamed path.txt = %q, want 'R100'", statuses["renamed path.txt"])
	}
	if statuses["copied path.txt"] != "C095" {
		t.Errorf("status for copied path.txt = %q, want 'C095'", statuses["copied path.txt"])
	}

	// Empty input
	emptyStatuses, err := ParseStagedFileStatuses(nil)
	if err != nil {
		t.Fatalf("ParseStagedFileStatuses(nil) error: %v", err)
	}
	if len(emptyStatuses) != 0 {
		t.Errorf("expected empty map for nil input, got %d entries", len(emptyStatuses))
	}
}

func TestParseStagedFileStatusesMalformed(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{
			name:  "truncated single status",
			input: []byte("M\x00"),
		},
		{
			name:  "truncated rename without new path",
			input: []byte("R100\x00old.txt\x00"),
		},
		{
			name:  "truncated rename with only status",
			input: []byte("R100\x00"),
		},
		{
			name:  "truncated copy without new path",
			input: []byte("C100\x00source.txt\x00"),
		},
		{
			name:  "empty status token",
			input: []byte("\x00file.txt\x00"),
		},
		{
			name:  "empty file path",
			input: []byte("M\x00\x00"),
		},
		{
			name:  "empty new path in rename",
			input: []byte("R100\x00old.txt\x00\x00"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseStagedFileStatuses(tc.input)
			if err == nil {
				t.Fatalf("expected error for malformed input %q, got nil", tc.input)
			}
		})
	}
}
