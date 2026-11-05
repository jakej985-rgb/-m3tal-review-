package review

import (
	"os"
	"path/filepath"
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
	wt := "0"
	if workingTree {
		wt = "1"
	}
	key := repositoryRoot + "\x00" + file + "\x00" + wt
	if cached, ok := ruleSourceCache.Load(key); ok {
		return cached.([]byte), nil
	}
	// Reviewed repositories are untrusted: never let a diff path escape the
	// repository root (absolute paths, ".." segments, or empty paths).
	if !filepath.IsLocal(file) || file == "." {
		return nil, os.ErrInvalid
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

func fullSourceBlock(file string, source []byte, addedLines []int) diffSourceBlock {
	added := make(map[int]bool, len(addedLines))
	for _, line := range addedLines {
		added[line] = true
	}
	return diffSourceBlock{file: file, firstLine: 1, text: string(source), addedLines: added}
}
