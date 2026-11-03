package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func RepositoryRoot(path string) (string, error) {
	command := exec.Command("git", "-C", path, "rev-parse", "--show-toplevel")

	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"find repository root: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	root := strings.TrimSpace(string(output))

	return root, nil
}

func Available() error {
	_, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("git executable not found: %w", err)
	}

	return nil
}

func IsClean(path string) (bool, error) {
	command := exec.Command("git", "-C", path, "status", "--porcelain")

	output, err := command.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf(
			"check working tree status: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	return strings.TrimSpace(string(output)) == "", nil
}

func CurrentBranch(path string) (string, error) {
	command := exec.Command("git", "-C", path, "branch", "--show-current")

	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"get current branch: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	branch := strings.TrimSpace(string(output))
	if branch == "" {
		return "", fmt.Errorf("get current branch: repository is in detached HEAD state")
	}

	return branch, nil
}

func ChangedFiles(path string) ([]string, error) {
	command := exec.Command("git", "-C", path, "diff", "--name-only", "-z", "HEAD")

	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"get changed files: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	files := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if len(files) == 1 && files[0] == "" {
		return []string{}, nil
	}

	return files, nil
}

func StagedFiles(path string) ([]string, error) {
	command := exec.Command("git", "-C", path, "diff", "--cached", "--name-only", "-z")

	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"get staged files: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	files := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if len(files) == 1 && files[0] == "" {
		return []string{}, nil
	}

	return files, nil
}

// ParseStagedFileStatuses parses NUL-delimited output from 'git diff --cached --name-status -z'.
// It returns a map of staged file paths to their git status (e.g. A, M, D, R100, C100).
// If the output is truncated or malformed, it returns an explicit error.
func ParseStagedFileStatuses(output []byte) (map[string]string, error) {
	statuses := make(map[string]string)
	if len(output) == 0 {
		return statuses, nil
	}

	trimmed := bytes.TrimSuffix(output, []byte{0})
	if len(trimmed) == 0 {
		return statuses, nil
	}

	tokens := bytes.Split(trimmed, []byte{0})
	for i := 0; i < len(tokens); {
		if len(tokens[i]) == 0 {
			return nil, fmt.Errorf("malformed git status output: empty status token at index %d", i)
		}
		status := string(tokens[i])

		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			// Rename or Copy has status, oldPath, newPath
			if i+2 >= len(tokens) {
				return nil, fmt.Errorf("malformed git status output: incomplete record for rename/copy status %q", status)
			}
			newPath := string(tokens[i+2])
			if newPath == "" {
				return nil, fmt.Errorf("malformed git status output: empty new path for status %q", status)
			}
			statuses[newPath] = status
			i += 3
			continue
		}

		if i+1 >= len(tokens) {
			return nil, fmt.Errorf("malformed git status output: incomplete record for status %q", status)
		}
		filePath := string(tokens[i+1])
		if filePath == "" {
			return nil, fmt.Errorf("malformed git status output: empty file path for status %q", status)
		}
		statuses[filePath] = status
		i += 2
	}

	return statuses, nil
}

// StagedFileStatuses returns a map of staged file paths to their git status (e.g. A, M, D, R).
func StagedFileStatuses(path string) (map[string]string, error) {
	command := exec.Command("git", "-C", path, "diff", "--cached", "--name-status", "-z")

	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"get staged file statuses: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	return ParseStagedFileStatuses(output)
}

func UntrackedFiles(path string) ([]string, error) {
	command := exec.Command(
		"git", "-C", path,
		"ls-files", "--others", "--exclude-standard", "-z",
	)

	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"get untracked files: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	files := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if len(files) == 1 && files[0] == "" {
		return []string{}, nil
	}

	return files, nil
}

// StagedDiff returns the patch for changes staged for commit.
func StagedDiff(path string) (string, error) {
	command := exec.Command(
		"git",
		"-C",
		path,
		"diff",
		"--cached",
		"--no-ext-diff",
		"--unified=0",
	)

	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"get staged diff: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	return string(output), nil
}
