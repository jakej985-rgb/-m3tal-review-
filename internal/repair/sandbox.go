package repair

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Sandbox provides an isolated filesystem environment (temporary copy or git worktree)
// ensuring the user's working tree remains strictly untouched until explicit approval.
type Sandbox struct {
	RepoRoot   string
	TempDir    string
	IsWorktree bool
}

// NewSandbox initializes an isolated sandbox directory.
func NewSandbox(repoRoot string, preferWorktree bool) (*Sandbox, error) {
	absRoot, err := filepath.Abs(repoRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve repository root %q: %w", repoRoot, err)
	}

	tempDir, err := os.MkdirTemp("", "m3tal-repair-sb-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary sandbox directory: %w", err)
	}

	sb := &Sandbox{
		RepoRoot:   absRoot,
		TempDir:    tempDir,
		IsWorktree: false,
	}

	cleanupNeeded := true
	defer func() {
		if cleanupNeeded {
			_ = sb.Close()
		}
	}()

	if preferWorktree {
		// Attempt git worktree
		cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-C", absRoot, "worktree", "add", "--detach", tempDir, "HEAD")
		if _, err := cmd.CombinedOutput(); err == nil {
			sb.IsWorktree = true
			// Overlay uncommitted tracked changes into the worktree
			if err := overlayWorkingTreeChanges(absRoot, tempDir); err != nil {
				return nil, fmt.Errorf("overlay working tree changes: %w", err)
			}
			cleanupNeeded = false
			return sb, nil
		} else {
			// Worktree failed (e.g. repo not clean or bare or git limitation), fallback to copy mode
			_ = os.RemoveAll(tempDir)
			tempDir, err = os.MkdirTemp("", "m3tal-repair-sb-*")
			if err != nil {
				return nil, fmt.Errorf("create temporary sandbox directory after worktree fallback: %w", err)
			}
			sb.TempDir = tempDir
		}
	}

	// Copy sandbox mode
	if err := copyDirectory(absRoot, tempDir); err != nil {
		return nil, fmt.Errorf("populate sandbox copy: %w", err)
	}

	// Initialize isolated git repository in the sandbox copy for git diff operations
	_ = initIsolatedGitRepo(tempDir)

	cleanupNeeded = false
	return sb, nil
}

// ApplyProposal applies the proposal to the isolated sandbox.
func (s *Sandbox) ApplyProposal(p *Proposal) error {
	return ApplyProposalToFile(s.TempDir, p)
}

// RepairedDiff returns the diff in the sandbox for targetFile against baseline.
func (s *Sandbox) RepairedDiff(targetFile string) (string, error) {
	// Try git diff inside sandbox
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-C", s.TempDir, "diff", "HEAD", "--", targetFile)
	out, err := cmd.CombinedOutput()
	if err == nil && len(out) > 0 {
		return string(out), nil
	}

	// Fallback: compare against file in RepoRoot
	origPath := filepath.Join(s.RepoRoot, targetFile)
	repairedPath := filepath.Join(s.TempDir, targetFile)

	origBytes, _ := os.ReadFile(origPath)
	repairedBytes, err := os.ReadFile(repairedPath)
	if err != nil {
		return "", fmt.Errorf("read repaired file in sandbox: %w", err)
	}

	return GenerateUnifiedDiff(targetFile, string(origBytes), string(repairedBytes)), nil
}

// Close destroys the temporary sandbox and removes worktree references.
func (s *Sandbox) Close() error {
	var errs []string

	if s.IsWorktree && s.RepoRoot != "" && s.TempDir != "" {
		cmdRemove := exec.Command("git", "-c", "core.fsmonitor=false", "-C", s.RepoRoot, "worktree", "remove", "--force", s.TempDir)
		if out, err := cmdRemove.CombinedOutput(); err != nil {
			errs = append(errs, fmt.Sprintf("git worktree remove: %s: %v", strings.TrimSpace(string(out)), err))
		}
		cmdPrune := exec.Command("git", "-c", "core.fsmonitor=false", "-C", s.RepoRoot, "worktree", "prune")
		_ = cmdPrune.Run()
	}

	if s.TempDir != "" {
		if err := os.RemoveAll(s.TempDir); err != nil {
			errs = append(errs, fmt.Sprintf("remove sandbox dir: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("sandbox cleanup failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func copyDirectory(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		// Skip .git to keep sandbox isolated, and skip .m3tal-review internal reports
		if rel == ".git" || strings.HasPrefix(rel, ".git"+string(filepath.Separator)) {
			return filepath.SkipDir
		}
		if rel == ".m3tal-review" || strings.HasPrefix(rel, ".m3tal-review"+string(filepath.Separator)) {
			return filepath.SkipDir
		}

		destPath := filepath.Join(dst, rel)

		if info.IsDir() {
			return os.MkdirAll(destPath, info.Mode().Perm())
		}

		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(linkTarget, destPath)
		}

		if !info.Mode().IsRegular() {
			return nil
		}

		return copyFile(path, destPath, info.Mode().Perm())
	})
}

func copyFile(src, dst string, perm os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return nil
}

func overlayWorkingTreeChanges(srcRepo, worktreeDir string) error {
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-C", srcRepo, "diff", "-z", "HEAD", "--name-only")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	files := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	for _, f := range files {
		if f == "" {
			continue
		}
		srcPath := filepath.Join(srcRepo, f)
		dstPath := filepath.Join(worktreeDir, f)
		info, err := os.Lstat(srcPath)
		if os.IsNotExist(err) {
			_ = os.Remove(dstPath)
			continue
		}
		if err == nil && info.Mode().IsRegular() {
			_ = copyFile(srcPath, dstPath, info.Mode().Perm())
		}
	}
	return nil
}

func initIsolatedGitRepo(dir string) error {
	cmdInit := exec.Command("git", "-c", "core.fsmonitor=false", "-C", dir, "init")
	if err := cmdInit.Run(); err != nil {
		return err
	}
	_ = exec.Command("git", "-c", "core.fsmonitor=false", "-C", dir, "config", "user.name", "m3tal-repair").Run()
	_ = exec.Command("git", "-c", "core.fsmonitor=false", "-C", dir, "config", "user.email", "repair@m3tal.local").Run()
	_ = exec.Command("git", "-c", "core.fsmonitor=false", "-C", dir, "add", "-A").Run()
	_ = exec.Command("git", "-c", "core.fsmonitor=false", "-C", dir, "commit", "-m", "baseline", "--no-gpg-sign").Run()
	return nil
}
