package repair

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func gitCmd(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// Regression (was audit repro): worktree and copy sandbox modes must expose
// the same tree — tracked overlays, untracked files, and symlinks.
func TestAuditSandboxWorktreeVsCopy(t *testing.T) {
	repo := t.TempDir()
	gitCmd(t, repo, "init")
	gitCmd(t, repo, "config", "user.name", "t")
	gitCmd(t, repo, "config", "user.email", "t@t")

	// tracked file, committed
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("v1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// tracked executable
	if err := os.WriteFile(filepath.Join(repo, "script.sh"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "-A")
	gitCmd(t, repo, "commit", "-m", "init", "--no-gpg-sign")

	// uncommitted tracked modification
	if err := os.WriteFile(filepath.Join(repo, "tracked.txt"), []byte("v2-uncommitted\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// untracked file
	if err := os.WriteFile(filepath.Join(repo, "untracked.txt"), []byte("untracked\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// ignored untracked file (copy mode includes these too)
	if err := os.WriteFile(filepath.Join(repo, ".gitignore"), []byte("ignored.txt\n"), 0644); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", ".gitignore")
	gitCmd(t, repo, "commit", "-m", "ignore", "--no-gpg-sign")
	if err := os.WriteFile(filepath.Join(repo, "ignored.txt"), []byte("ignored\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// symlink (untracked) pointing outside repo — must NOT be preserved:
	// sandbox reads would escape to host files (R10).
	outside := filepath.Join(t.TempDir(), "outside-secret.txt")
	if err := os.WriteFile(outside, []byte("secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(repo, "link-escape.txt")); err != nil {
		t.Fatal(err)
	}
	// symlink staying inside the repo — must be preserved as a symlink.
	if err := os.Symlink("tracked.txt", filepath.Join(repo, "link-inner.txt")); err != nil {
		t.Fatal(err)
	}
	// COMMITTED escaping symlink: `git worktree add` materializes it and
	// the overlay never touches it — the sandbox sweep must remove it.
	if err := os.Symlink(outside, filepath.Join(repo, "link-committed-escape.txt")); err != nil {
		t.Fatal(err)
	}
	gitCmd(t, repo, "add", "link-committed-escape.txt")
	gitCmd(t, repo, "commit", "-m", "escaping link", "--no-gpg-sign")

	// --- copy mode ---
	copySB, err := NewSandbox(repo, false)
	if err != nil {
		t.Fatalf("copy sandbox: %v", err)
	}
	defer copySB.Close()

	// --- worktree mode ---
	wtSB, err := NewSandbox(repo, true)
	if err != nil {
		t.Fatalf("worktree sandbox: %v", err)
	}
	defer wtSB.Close()
	if !wtSB.IsWorktree {
		t.Skip("worktree mode unavailable (fell back to copy); parity trivially holds")
	}

	assertFile := func(sb *Sandbox, name, want string) {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(sb.TempDir, name))
		if err != nil {
			t.Fatalf("%s: read %s in sandbox: %v", sb.TempDir, name, err)
		}
		if string(data) != want {
			t.Fatalf("%s: %s = %q, want %q", sb.TempDir, name, string(data), want)
		}
	}

	// Tracked overlay must reflect uncommitted working-tree content.
	for _, sb := range []*Sandbox{copySB, wtSB} {
		assertFile(sb, "tracked.txt", "v2-uncommitted\n")
		// Untracked and ignored files must be present in both modes.
		assertFile(sb, "untracked.txt", "untracked\n")
		assertFile(sb, "ignored.txt", "ignored\n")
	}

	// R10: symlinks escaping the repo root must be absent from BOTH sandbox
	// modes; contained symlinks must be preserved as symlinks.
	for _, sb := range []*Sandbox{copySB, wtSB} {
		if _, err := os.Lstat(filepath.Join(sb.TempDir, "link-escape.txt")); !os.IsNotExist(err) {
			t.Fatalf("%s: escaping symlink link-escape.txt present in sandbox (err=%v)", sb.TempDir, err)
		}
		if _, err := os.Lstat(filepath.Join(sb.TempDir, "link-committed-escape.txt")); !os.IsNotExist(err) {
			t.Fatalf("%s: committed escaping symlink present in sandbox (err=%v)", sb.TempDir, err)
		}
		info, err := os.Lstat(filepath.Join(sb.TempDir, "link-inner.txt"))
		if err != nil {
			t.Fatalf("%s: lstat link-inner.txt: %v", sb.TempDir, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s: link-inner.txt is not a symlink (mode %v)", sb.TempDir, info.Mode())
		}
		target, err := os.Readlink(filepath.Join(sb.TempDir, "link-inner.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if target != "tracked.txt" {
			t.Fatalf("%s: link-inner.txt target %q, want tracked.txt", sb.TempDir, target)
		}
	}

	// Executable bit must survive in both modes. Windows has no POSIX
	// exec bit — the filesystem cannot store it, so the check is
	// POSIX-only.
	if runtime.GOOS == "windows" {
		return
	}
	for _, sb := range []*Sandbox{copySB, wtSB} {
		info, err := os.Stat(filepath.Join(sb.TempDir, "script.sh"))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o111 == 0 {
			t.Fatalf("%s: script.sh lost executable bit (mode %v)", sb.TempDir, info.Mode())
		}
	}
}
