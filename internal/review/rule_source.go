package review

import (
	"os"
	"path/filepath"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

func readRuleSource(repositoryRoot, file string, workingTree bool) ([]byte, error) {
	if repositoryRoot == "" {
		return nil, os.ErrNotExist
	}
	// Defend against path traversal: ensure file path is a valid local relative path
	// within the repository root before accessing the filesystem or git index.
	if !filepath.IsLocal(file) || file == "." {
		return nil, os.ErrInvalid
	}
	if workingTree {
		return os.ReadFile(filepath.Join(repositoryRoot, file))
	}
	return git.StagedFileContent(repositoryRoot, file)
}

func fullSourceBlock(file string, source []byte, addedLines []int) diffSourceBlock {
	added := make(map[int]bool, len(addedLines))
	for _, line := range addedLines {
		added[line] = true
	}
	return diffSourceBlock{file: file, firstLine: 1, text: string(source), addedLines: added}
}
