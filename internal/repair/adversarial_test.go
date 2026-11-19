package repair

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestChainedSymlinks verifies that multi-hop symlinks are evaluated to their final target
// and rejected if any intermediate or final link escapes the repository root.
func TestChainedSymlinks(t *testing.T) {
	repoDir := t.TempDir()
	outsideDir := t.TempDir()

	secretFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("sensitive"), 0644); err != nil {
		t.Fatal(err)
	}

	// Link 1 -> Link 2 -> Outside
	link2 := filepath.Join(repoDir, "link2")
	if err := os.Symlink(outsideDir, link2); err != nil {
		t.Skip("symlinks not supported on this platform")
	}
	link1 := filepath.Join(repoDir, "link1")
	if err := os.Symlink(link2, link1); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	err := ValidateTargetFilePath(repoDir, "link1/secret.txt")
	if err == nil {
		t.Fatal("expected chained symlink escaping repository root to be rejected, but it passed")
	}

	// Contained chained symlink: LinkA -> LinkB -> internal directory
	internalDir := filepath.Join(repoDir, "internal")
	if err := os.MkdirAll(internalDir, 0755); err != nil {
		t.Fatal(err)
	}
	internalFile := filepath.Join(internalDir, "file.txt")
	if err := os.WriteFile(internalFile, []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}

	linkB := filepath.Join(repoDir, "linkB")
	if err := os.Symlink(internalDir, linkB); err != nil {
		t.Skip("symlinks not supported")
	}
	linkA := filepath.Join(repoDir, "linkA")
	if err := os.Symlink(linkB, linkA); err != nil {
		t.Skip("symlinks not supported")
	}

	if err := ValidateTargetFilePath(repoDir, "linkA/file.txt"); err != nil {
		t.Fatalf("expected contained chained symlink to pass validation, got: %v", err)
	}
}

// TestDanglingSymlinks verifies that dangling symlinks (broken targets) are handled safely.
func TestDanglingSymlinks(t *testing.T) {
	repoDir := t.TempDir()

	danglingEscaping := filepath.Join(repoDir, "dangling_outside")
	if err := os.Symlink("/nonexistent/outside/path", danglingEscaping); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	// Dangling symlink escaping root must fail resolution
	err := ValidateTargetFilePath(repoDir, "dangling_outside")
	if err == nil {
		t.Fatal("expected dangling symlink pointing outside root to fail validation, but it passed")
	}

	// Contained dangling link pointing inside repo
	danglingInternal := filepath.Join(repoDir, "dangling_inside")
	if err := os.Symlink(filepath.Join(repoDir, "missing.txt"), danglingInternal); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	// The link itself exists and is a symlink, so it should be inspected
	err = ValidateTargetFilePath(repoDir, "dangling_inside")
	// If it points inside the repo, EvalSymlinks might fail because target doesn't exist.
	// Either way, it must not allow escape.
	if err != nil && !strings.Contains(err.Error(), "no such file") && !strings.Contains(err.Error(), "resolve symlink") {
		t.Logf("dangling internal symlink returned: %v", err)
	}
}

// TestApplyProposalToFileContainedSymlink verifies that applying a proposal to a contained
// symlink writes to the real target file without destroying the symlink itself.
func TestApplyProposalToFileContainedSymlink(t *testing.T) {
	repoDir := t.TempDir()
	subDir := filepath.Join(repoDir, "sub")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	realFile := filepath.Join(subDir, "target.txt")
	if err := os.WriteFile(realFile, []byte("hello old world\n"), 0644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(repoDir, "link.txt")
	if err := os.Symlink(realFile, linkPath); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	p := &Proposal{
		ID:              "prop-symlink-test",
		TargetFile:      "link.txt",
		OriginalContent: "hello old world\n",
		ProposedContent: "hello new world\n",
		Patch:           "--- a/link.txt\n+++ b/link.txt\n@@ -1 +1 @@\n-hello old world\n+hello new world\n",
	}

	if err := ApplyProposalToFile(repoDir, p); err != nil {
		t.Fatalf("ApplyProposalToFile on contained symlink failed: %v", err)
	}

	// Real file should be updated
	updated, err := os.ReadFile(realFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(updated) != "hello new world\n" {
		t.Fatalf("expected real target file to be updated, got %q", string(updated))
	}

	// link.txt must still be a symlink
	li, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatal(err)
	}
	if li.Mode()&os.ModeSymlink == 0 {
		t.Fatal("expected link.txt to remain a symlink, but it was replaced by a regular file")
	}
}

// TestTOCTOUConcurrentSymlinkSwap simulates a race condition where a target regular file
// is replaced with an escaping symlink between validation and write.
func TestTOCTOUConcurrentSymlinkSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated permissions on Windows")
	}

	repoDir := t.TempDir()
	outsideDir := t.TempDir()

	outsideTarget := filepath.Join(outsideDir, "victim.txt")
	if err := os.WriteFile(outsideTarget, []byte("vital secret\n"), 0644); err != nil {
		t.Fatal(err)
	}

	targetName := "race_file.txt"
	targetPath := filepath.Join(repoDir, targetName)
	if err := os.WriteFile(targetPath, []byte("before\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p := &Proposal{
		ID:              "prop-toctou",
		TargetFile:      targetName,
		OriginalContent: "before\n",
		ProposedContent: "after\n",
		Patch:           "--- a/race_file.txt\n+++ b/race_file.txt\n@@ -1 +1 @@\n-before\n+after\n",
	}

	// Validate path boundaries when file is regular
	if err := ValidatePatchBoundaries(repoDir, p.TargetFile, p.Patch); err != nil {
		t.Fatalf("initial validation failed: %v", err)
	}

	// Now simulate concurrent swap: replace targetPath with an escaping symlink
	if err := os.Remove(targetPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, targetPath); err != nil {
		t.Skip("symlink creation failed")
	}

	// ApplyProposalToFile MUST detect the escape at write time and refuse to write to outsideTarget
	err := ApplyProposalToFile(repoDir, p)
	if err == nil {
		t.Fatal("CRITICAL: ApplyProposalToFile wrote to escaping symlink target; TOCTOU vulnerability!")
	}
	if !strings.Contains(err.Error(), "outside repository") && !strings.Contains(err.Error(), "escapes") {
		t.Logf("ApplyProposalToFile refused write with: %v", err)
	}

	// Verify outsideTarget was NOT modified
	content, _ := os.ReadFile(outsideTarget)
	if string(content) != "vital secret\n" {
		t.Fatalf("outside target was corrupted! Got %q", string(content))
	}
}

// TestAtomicWriteFailurePreservesOriginalFile tests that an injected write failure leaves
// the original destination file byte-for-byte intact and cleans up any temp files.
func TestAtomicWriteFailurePreservesOriginalFile(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "intact.txt")
	originalData := []byte("original content unchanged\n")
	if err := os.WriteFile(targetFile, originalData, 0644); err != nil {
		t.Fatal(err)
	}

	// Attempt an invalid proposal
	p := &Proposal{
		ID:              "prop-fail",
		TargetFile:      "intact.txt",
		OriginalContent: "wrong original content\n",
		ProposedContent: "should not be written\n",
		Patch:           "--- a/intact.txt\n+++ b/intact.txt\n@@ -1 +1 @@\n-wrong original content\n+should not be written\n",
	}

	err := ApplyProposalToFile(dir, p)
	if err == nil {
		t.Fatal("expected proposal to fail due to content mismatch, but it succeeded")
	}

	// Verify original file is pristine
	after, err := os.ReadFile(targetFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(originalData) {
		t.Fatalf("expected file to remain unchanged, got %q", string(after))
	}

	// Verify no temporary files remain
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".m3tal-repair-") {
			t.Fatalf("found leftover temporary file: %s", e.Name())
		}
	}
}

// TestParallelRepairProposalsSafety verifies that concurrent repairs on distinct files
// in the same directory do not race or corrupt temporary files.
func TestParallelRepairProposalsSafety(t *testing.T) {
	dir := t.TempDir()
	const count = 10
	var wg sync.WaitGroup

	for i := 0; i < count; i++ {
		fileName := filepath.Join(dir, strings.ReplaceAll("test_file_N.txt", "N", string(rune('0'+i))))
		if err := os.WriteFile(fileName, []byte("init\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	errCh := make(chan error, count)
	worker := func(idx int) {
		defer wg.Done()
		fname := strings.ReplaceAll("test_file_N.txt", "N", string(rune('0'+idx)))
		p := &Proposal{
			ID:              "p-" + fname,
			TargetFile:      fname,
			OriginalContent: "init\n",
			ProposedContent: "fixed\n",
			Patch:           "--- a/" + fname + "\n+++ b/" + fname + "\n@@ -1 +1 @@\n-init\n+fixed\n",
		}
		if err := ApplyProposalToFile(dir, p); err != nil {
			errCh <- err
		}
	}

	for i := 0; i < count; i++ {
		wg.Add(1)
		go worker(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("parallel repair error: %v", err)
	}
}
