package repair

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// A committed absolute symlink replaced locally by a real directory with an
// untracked child must not let the worktree overlay write through the link.
func TestSandboxOverlayDoesNotWriteThroughCommittedSymlink(t *testing.T) {
	repo := t.TempDir()
	gitCmd(t, repo, "init")
	gitCmd(t, repo, "config", "user.name", "t")
	gitCmd(t, repo, "config", "user.email", "t@t")

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(repo, "out")); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "out")
	gitCmd(t, repo, "commit", "-m", "link", "--no-gpg-sign")

	if err := os.Remove(filepath.Join(repo, "out")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, "out"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "out", "child.txt"), []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sb, err := NewSandbox(repo, true)
	if err != nil {
		t.Fatalf("sandbox: %v", err)
	}
	defer sb.Close()

	if _, err := os.Lstat(filepath.Join(outside, "child.txt")); !os.IsNotExist(err) {
		t.Fatalf("overlay wrote outside the sandbox (err=%v)", err)
	}
	if sb.IsWorktree {
		data, err := os.ReadFile(filepath.Join(sb.TempDir, "out", "child.txt"))
		if err != nil || string(data) != "x\n" {
			t.Fatalf("expected child copied into real sandbox dir, got %q err=%v", data, err)
		}
	}
}

// A repair whose context is already cancelled must never apply.
func TestRepairCancelledContextDoesNotApply(t *testing.T) {
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	file := "clean.go"
	content := "func main() {   \n}\n"
	if err := os.WriteFile(filepath.Join(repoDir, file), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewRepairEngine(repoDir, nil)
	engine.ApprovalHandler = func(*Proposal, review.RemediationVerificationResult) (bool, error) {
		return true, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	res, _ := engine.RepairFinding(ctx, review.Finding{
		ID: "cancel", Rule: "code-slop", Severity: "low", File: file,
		Message: "Trailing whitespace detected",
	})
	if res != nil && (res.Applied || res.Outcome == OutcomeApprovedAndApplied) {
		t.Fatalf("cancelled repair was applied: outcome=%s", res.Outcome)
	}
	disk, _ := os.ReadFile(filepath.Join(repoDir, file))
	if string(disk) != content {
		t.Fatalf("working tree modified after cancellation: %q", disk)
	}
}

// Repairing through a contained symlink must keep the link and fix its target.
func TestApplyProposalPreservesContainedSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0755); err != nil {
		t.Fatal(err)
	}
	orig := "a   \n"
	fixed := "a\n"
	if err := os.WriteFile(filepath.Join(root, "src", "main.js"), []byte(orig), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("src", "main.js"), filepath.Join(root, "alias.js")); err != nil {
		t.Fatal(err)
	}

	f := review.Finding{ID: "sym", Rule: "code-slop", File: "alias.js"}
	p := NewProposal("", f, "test", "alias.js", orig, fixed, "strip")
	if err := ApplyProposalToFile(root, p); err != nil {
		t.Fatalf("apply: %v", err)
	}

	info, err := os.Lstat(filepath.Join(root, "alias.js"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("alias.js is no longer a symlink (err=%v)", err)
	}
	data, _ := os.ReadFile(filepath.Join(root, "src", "main.js"))
	if string(data) != fixed {
		t.Fatalf("symlink target not repaired: %q", data)
	}
}

func TestRedundantBoolFixStringArgsAndLiterals(t *testing.T) {
	cases := []struct{ in, want string }{
		{`if strings.HasPrefix(name, "x") == false {`, `if !strings.HasPrefix(name, "x") {`},
		{`if ok == true {`, `if ok {`},
		{`s := "ok == true"`, `s := "ok == true"`},
		{`x := 1 // ok == false`, `x := 1 // ok == false`},
	}
	for _, tc := range cases {
		if got := applyRedundantBoolFix(tc.in); got != tc.want {
			t.Errorf("applyRedundantBoolFix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWorldWritableFixerMultilineCall(t *testing.T) {
	src := "package main\n\nfunc f() {\n\tos.WriteFile(\n\t\tpath,\n\t\tdata,\n\t\t0777,\n\t)\n\t// 0777 in comment\n}\n"
	f := review.Finding{Rule: "world-writable-file-mode", File: "f.go", Line: 7}
	prop, err := WorldWritableFileModeFixer{}.GenerateProposal(context.Background(), "", f, []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if prop == nil {
		t.Fatal("expected proposal for multiline permission call")
	}
	if !strings.Contains(prop.ProposedContent, "\t\t0644,\n") {
		t.Fatalf("mode not rewritten:\n%s", prop.ProposedContent)
	}
	if !strings.Contains(prop.ProposedContent, "// 0777 in comment") {
		t.Fatalf("comment literal was rewritten:\n%s", prop.ProposedContent)
	}
}
