package review

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

// ruleSourceCache memoizes file contents for the duration of a process. A
// single review run reads each changed file once per rule; caching avoids
// repeated git/show or disk reads. The CLI is one-shot, so entries never go
// stale within a run.
var ruleSourceCache sync.Map // key: root + "\x00" + file + "\x00" + wt

func readRuleSource(repositoryRoot, file string, workingTree bool) ([]byte, error) {
	if repositoryRoot == "" {
		return nil, os.ErrNotExist
	}
	// Reviewed repositories are untrusted: never let a diff path escape the
	// repository root (absolute paths, ".." segments, or empty paths).
	if !filepath.IsLocal(file) || file == "." {
		return nil, os.ErrInvalid
	}
	wt := "0"
	if workingTree {
		wt = "1"
	}
	key := repositoryRoot + "\x00" + file + "\x00" + wt
	if workingTree {
		// Working-tree files change between runs (watch mode) and within
		// repair verification (sandbox apply). Include mtime+size so cached
		// entries self-invalidate instead of serving stale content.
		if info, err := os.Stat(filepath.Join(repositoryRoot, file)); err == nil {
			key += "\x00" + info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z") + "\x00" + strconv.FormatInt(info.Size(), 10)
		}
	} else if stamp := indexStamp(repositoryRoot); stamp != "" {
		// Staged content changes whenever the index changes (watch mode,
		// repeated runs). Keying by the index file's mtime+size keeps
		// cached blobs correct across staging operations.
		key += "\x00" + stamp
	}
	if cached, ok := ruleSourceCache.Load(key); ok {
		return cached.([]byte), nil
	}
	var data []byte
	var err error
	if workingTree {
		data, err = os.ReadFile(filepath.Join(repositoryRoot, file))
	} else {
		data, err = git.StagedFileContent(repositoryRoot, file)
	}
	if err == nil {
		ruleSourceCache.Store(key, data)
	}
	return data, err
}

// indexStamp returns a cheap fingerprint of the repository index
// (mtime+size of .git/index, following gitdir links for worktrees and
// submodules). Empty string means the stamp could not be determined.
func indexStamp(repositoryRoot string) string {
	gitPath := filepath.Join(repositoryRoot, ".git")
	info, err := os.Stat(gitPath)
	if err != nil {
		return ""
	}
	gitDir := gitPath
	if !info.IsDir() {
		// .git file: "gitdir: <path>" (worktrees, submodules).
		data, err := os.ReadFile(gitPath)
		if err != nil {
			return ""
		}
		line := strings.TrimSpace(string(data))
		if !strings.HasPrefix(line, "gitdir:") {
			return ""
		}
		gitDir = strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
		if !filepath.IsAbs(gitDir) {
			gitDir = filepath.Join(repositoryRoot, gitDir)
		}
	}
	idx, err := os.Stat(filepath.Join(gitDir, "index"))
	if err != nil {
		return ""
	}
	return idx.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z") + "\x00" + strconv.FormatInt(idx.Size(), 10)
}

func fullSourceBlock(file string, source []byte, addedLines []int) diffSourceBlock {
	added := make(map[int]bool, len(addedLines))
	for _, line := range addedLines {
		added[line] = true
	}
	return diffSourceBlock{file: file, firstLine: 1, text: string(source), addedLines: added, fullSource: true}
}
