package repair

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
			// Sweep committed escaping symlinks BEFORE the overlay: otherwise
			// overlay writes could follow a materialized link out of the
			// sandbox and land on host files.
			if err := removeEscapingSymlinks(tempDir); err != nil {
				return nil, fmt.Errorf("sandbox symlink sweep: %w", err)
			}
			// Overlay uncommitted tracked changes into the worktree
			if err := overlayWorkingTreeChanges(absRoot, tempDir); err != nil {
				return nil, fmt.Errorf("overlay working tree changes: %w", err)
			}
			// Committed symlinks escaping the repo are materialized by
			// `git worktree add` and never pass through the overlay —
			// remove any link that resolves outside the sandbox.
			if err := removeEscapingSymlinks(tempDir); err != nil {
				return nil, fmt.Errorf("sandbox symlink sweep: %w", err)
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
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-C", s.TempDir, "diff", "--no-ext-diff", "--no-textconv", "HEAD", "--", targetFile)
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

// symlinkEscapesRoot reports whether the symlink at linkPath resolves
// outside root. Both lexical resolution and symlink evaluation are
// checked so chained links cannot smuggle an escape past the sandbox.
func symlinkEscapesRoot(linkPath, root string) bool {
	target, err := os.Readlink(linkPath)
	if err != nil {
		return true // unreadable link: treat as unsafe
	}
	resolved := target
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(filepath.Dir(linkPath), resolved)
	}
	resolved = filepath.Clean(resolved)

	// Canonicalize both sides through the same resolver: platforms like
	// macOS alias /var -> /private/var, so comparing an evaluated target
	// against a merely-absolute root produces false escapes.
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return true
	}
	rootAbs = resolveExistingPath(rootAbs)

	resolved = resolveExistingPath(resolved)
	return resolved != rootAbs && !strings.HasPrefix(resolved, rootAbs+string(filepath.Separator))
}

// resolveExistingPath returns p with symlinks resolved in its longest
// existing prefix and the nonexistent tail rejoined lexically. Unlike
// filepath.EvalSymlinks it still produces a canonical path for dangling
// symlink targets, keeping the escape check consistent on platforms where
// ancestor directories themselves are symlinks (e.g. macOS /var).
func resolveExistingPath(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return filepath.Clean(p)
	}
	var suffix []string
	cur := abs
	for {
		if eval, err := filepath.EvalSymlinks(cur); err == nil {
			parts := append([]string{eval}, suffix...)
			return filepath.Join(parts...)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return filepath.Clean(abs)
		}
		suffix = append([]string{filepath.Base(cur)}, suffix...)
		cur = parent
	}
}

// removeEscapingSymlinks deletes symlinks under root whose targets resolve
// outside root. Used on worktree sandboxes where committed links bypass the
// copy/overlay containment checks.
func removeEscapingSymlinks(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 && symlinkEscapesRoot(path, root) {
			return os.Remove(path)
		}
		return nil
	})
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
			// Skip links that escape the repository root: preserving them
			// verbatim would let sandbox reads reach host files outside
			// the reviewed tree.
			if symlinkEscapesRoot(path, src) {
				return nil
			}
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

// overlayWorkingTreeChanges makes the detached HEAD worktree reflect the
// source repository's working tree: tracked modifications, deletions, type
// changes (including symlinks), and non-ignored untracked files. This
// mirrors copyDirectory's coverage so verification sees the same tree in
// both sandbox modes.
func overlayWorkingTreeChanges(srcRepo, worktreeDir string) error {
	// Tracked changes vs HEAD. `git diff HEAD` trusts the index stat cache,
	// which can hide modifications (racy-clean entries, platform timestamp
	// quirks — observed on Windows runners), so instead hash each tracked
	// file's working bytes and compare against the HEAD tree directly.
	head, err := headTreeEntries(srcRepo)
	if err != nil {
		return err
	}
	tracked, err := listIndexPaths(srcRepo)
	if err != nil {
		return err
	}
	// Union with HEAD paths: staged deletions/renames drop the old path from
	// the index, but the HEAD-based worktree still contains it.
	seen := make(map[string]bool, len(tracked))
	for _, f := range tracked {
		seen[f] = true
	}
	for p := range head {
		if !seen[p] {
			tracked = append(tracked, p)
			seen[p] = true
		}
	}
	for _, f := range tracked {
		if f == "" {
			continue
		}
		changed, err := trackedFileDiffers(srcRepo, f, head[f])
		if err != nil {
			return err
		}
		if changed {
			if err := overlayPath(srcRepo, worktreeDir, f); err != nil {
				return err
			}
		}
	}

	// All untracked files, including ignored ones: copy mode copies
	// everything except .git/.m3tal-review, so the overlay must too.
	cmdUntracked := exec.Command("git", "-c", "core.fsmonitor=false", "-C", srcRepo, "ls-files", "-z", "--others")
	outUntracked, err := cmdUntracked.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git ls-files --others: %s", strings.TrimSpace(string(outUntracked)))
	}
	for _, f := range strings.Split(strings.TrimRight(string(outUntracked), "\x00"), "\x00") {
		if f == "" || f == ".git" || strings.HasPrefix(f, ".git/") ||
			f == ".m3tal-review" || strings.HasPrefix(f, ".m3tal-review/") {
			continue
		}
		if err := overlayPath(srcRepo, worktreeDir, f); err != nil {
			return err
		}
	}
	return nil
}

// headEntry identifies a path in the HEAD tree: git mode and blob hash.
type headEntry struct {
	mode string
	sha  string
	size int64
}

// headTreeEntries returns the HEAD tree's blob entries keyed by path.
func headTreeEntries(repo string) (map[string]headEntry, error) {
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-C", repo, "ls-tree", "-r", "-l", "-z", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-tree HEAD: %w", err)
	}
	entries := make(map[string]headEntry)
	for _, rec := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rec == "" {
			continue
		}
		meta, path, ok := strings.Cut(rec, "\t")
		if !ok {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) < 4 {
			continue
		}
		size, _ := strconv.ParseInt(fields[3], 10, 64)
		entries[path] = headEntry{mode: fields[0], sha: fields[2], size: size}
	}
	return entries, nil
}

// listIndexPaths returns every path recorded in the index (stage-agnostic).
func listIndexPaths(repo string) ([]string, error) {
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-C", repo, "ls-files", "-z")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %w", err)
	}
	return strings.Split(strings.TrimRight(string(out), "\x00"), "\x00"), nil
}

// trackedFileDiffers reports whether the working-tree file at rel differs
// from its HEAD entry (or is absent from HEAD). It hashes raw working bytes
// as a git blob, so it is immune to index stat-cache staleness. A missing
// file counts as differing so overlayPath can propagate the deletion.
func trackedFileDiffers(srcRepo, rel string, head headEntry) (bool, error) {
	srcPath := filepath.Join(srcRepo, rel)
	info, err := os.Lstat(srcPath)
	if err != nil {
		return true, nil // missing or unreadable: let overlayPath decide
	}
	if info.IsDir() {
		// Only a real gitlink (160000) is a submodule with no content to
		// overlay; a file/symlink replaced by a directory must be overlaid.
		return head.mode != "160000", nil
	}

	var workMode, workSHA string
	var workSize int64
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, err := os.Readlink(srcPath)
		if err != nil {
			return true, nil
		}
		workMode = "120000"
		workSize = int64(len(target))
		workSHA, err = gitBlobHash(strings.NewReader(target), workSize)
		if err != nil {
			return true, err
		}
	case info.Mode().IsRegular():
		workMode = "100644"
		if info.Mode().Perm()&0o111 != 0 {
			workMode = "100755"
		}
		workSize = info.Size()
		if head.sha != "" && head.mode == workMode && head.size >= 0 && head.size != workSize {
			return true, nil // size differs: content cannot match
		}
		f, err := os.Open(srcPath)
		if err != nil {
			return true, nil
		}
		workSHA, err = gitBlobHash(f, workSize)
		f.Close()
		if err != nil {
			return true, err
		}
	default:
		// FIFO/socket/device: copy mode skips these; overlay removes dst.
		return true, nil
	}

	if head.sha == "" {
		return true, nil // not in HEAD (staged addition): must appear
	}
	return head.mode != workMode || head.sha != workSHA, nil
}

// gitBlobHash computes the git object id ("blob <size>\x00" + content)
// without spawning git hash-object per file.
func gitBlobHash(r io.Reader, size int64) (string, error) {
	h := sha1.New()
	if _, err := fmt.Fprintf(h, "blob %d\x00", size); err != nil {
		return "", err
	}
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// overlayPath copies one working-tree path into the worktree sandbox,
// preserving symlinks and permission bits; a missing source removes the
// destination (deletion), and a type change replaces it.
func overlayPath(srcRepo, worktreeDir, rel string) error {
	srcPath := filepath.Join(srcRepo, rel)
	dstPath := filepath.Join(worktreeDir, rel)
	info, err := os.Lstat(srcPath)
	if os.IsNotExist(err) {
		return os.RemoveAll(dstPath)
	}
	if err != nil {
		return fmt.Errorf("lstat %q: %w", srcPath, err)
	}

	// Every ancestor of the destination must be a real directory inside
	// the sandbox; a symlinked ancestor would redirect writes elsewhere.
	if err := ensureContainedParent(worktreeDir, dstPath); err != nil {
		return err
	}

	if info.IsDir() {
		// Directories carry no content, but a destination of another type
		// (e.g. a committed symlink replaced locally by a directory) must be
		// replaced so children are not written through it.
		if dstInfo, statErr := os.Lstat(dstPath); statErr == nil && !dstInfo.IsDir() {
			if err := os.RemoveAll(dstPath); err != nil {
				return fmt.Errorf("replace %q: %w", dstPath, err)
			}
		}
		return os.MkdirAll(dstPath, info.Mode().Perm()|0700)
	}

	// Remove any existing destination of a different type before writing.
	if dstInfo, statErr := os.Lstat(dstPath); statErr == nil {
		needReplace := info.Mode()&os.ModeSymlink != 0 ||
			(dstInfo.Mode()&os.ModeSymlink != 0) ||
			info.IsDir() != dstInfo.IsDir()
		if needReplace {
			if err := os.RemoveAll(dstPath); err != nil {
				return fmt.Errorf("replace %q: %w", dstPath, err)
			}
		}
	}

	if info.Mode()&os.ModeSymlink != 0 {
		// Skip links escaping the source repo: the worktree sandbox must
		// not resolve reads to host files outside the reviewed tree.
		if symlinkEscapesRoot(srcPath, srcRepo) {
			return nil
		}
		target, err := os.Readlink(srcPath)
		if err != nil {
			return fmt.Errorf("readlink %q: %w", srcPath, err)
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return err
		}
		return os.Symlink(target, dstPath)
	}

	if !info.Mode().IsRegular() {
		// FIFOs, sockets, devices: copy mode skips them; do the same.
		return os.RemoveAll(dstPath)
	}
	return copyFile(srcPath, dstPath, info.Mode().Perm())
}

// ensureContainedParent walks each ancestor of dstPath below root. Any
// ancestor that is a symlink or non-directory is removed so subsequent
// MkdirAll/copy operations cannot follow it outside the sandbox.
func ensureContainedParent(root, dstPath string) error {
	rel, err := filepath.Rel(root, filepath.Dir(dstPath))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("overlay path %q escapes sandbox", dstPath)
	}
	if rel == "." {
		return nil
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if os.IsNotExist(err) {
			return nil // MkdirAll will create real directories from here
		}
		if err != nil {
			return fmt.Errorf("lstat %q: %w", cur, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			if err := os.RemoveAll(cur); err != nil {
				return fmt.Errorf("replace %q: %w", cur, err)
			}
			return nil
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
