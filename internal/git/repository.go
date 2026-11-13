package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func RepositoryRoot(path string) (string, error) {
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "rev-parse", "--show-toplevel")

	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"find repository root: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	root := filepath.Clean(filepath.FromSlash(strings.TrimSpace(string(output))))
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}

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
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "status", "--porcelain")

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
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "branch", "--show-current")

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
		command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "rev-parse", "--short", "HEAD")
		output, err := command.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("get detached HEAD commit: %s: %w", strings.TrimSpace(string(output)), err)
		}
		return "(detached HEAD at " + strings.TrimSpace(string(output)) + ")", nil
	}

	return branch, nil
}

func ChangedFiles(path string) ([]string, error) {
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "diff", "--name-only", "-z", "HEAD")

	output, err := command.CombinedOutput()
	if err != nil {
		// A repository without commits has no HEAD to diff against. In that case,
		// report the staged paths, which are the tracked changes in the unborn tree.
		headCommand := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "rev-parse", "--verify", "HEAD")
		if _, headErr := headCommand.CombinedOutput(); headErr != nil {
			stagedCommand := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "diff", "--cached", "--name-only", "-z")
			stagedOutput, stagedErr := stagedCommand.CombinedOutput()
			if stagedErr == nil {
				output = stagedOutput
				err = nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("get changed files: %s: %w", strings.TrimSpace(string(output)), err)
		}
	}

	files := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if len(files) == 1 && files[0] == "" {
		return []string{}, nil
	}

	return files, nil
}

func StagedFiles(path string) ([]string, error) {
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "diff", "--cached", "--name-only", "-z")

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
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "diff", "--cached", "--name-status", "-z")

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

// ParseBinaryFilesFromNumstat returns paths whose staged diff has no textual line counts.
// Git emits '-' for both counts on binary files. With -z, rename records contain an
// empty path token followed by the old and new paths.
func ParseBinaryFilesFromNumstat(output []byte) ([]string, error) {
	trimmed := bytes.TrimSuffix(output, []byte{0})
	if len(trimmed) == 0 {
		return []string{}, nil
	}
	tokens := bytes.Split(trimmed, []byte{0})
	var binaryFiles []string
	for i := 0; i < len(tokens); {
		fields := bytes.SplitN(tokens[i], []byte{'\t'}, 3)
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed git numstat record at token %d", i)
		}
		isBinary := bytes.Equal(fields[0], []byte("-")) && bytes.Equal(fields[1], []byte("-"))
		path := string(fields[2])
		i++
		if path == "" { // rename/copy: next two tokens are old and new paths
			if i+1 >= len(tokens) || len(tokens[i]) == 0 || len(tokens[i+1]) == 0 {
				return nil, fmt.Errorf("malformed git numstat rename record")
			}
			path = string(tokens[i+1])
			i += 2
		}
		if isBinary {
			binaryFiles = append(binaryFiles, path)
		}
	}
	return binaryFiles, nil
}

// StagedBinaryFiles lists staged paths represented as binary in Git's numstat output.
func StagedBinaryFiles(path string) ([]string, error) {
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "diff", "--cached", "--diff-filter=ACMRTUXB", "--numstat", "-z")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("get staged binary files: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return ParseBinaryFilesFromNumstat(output)
}

// StagedSubmoduleFiles lists staged paths whose index mode is a Git submodule.
func StagedSubmoduleFiles(path string) ([]string, error) {
	staged, err := StagedFiles(path)
	if err != nil {
		return nil, err
	}
	stagedSet := make(map[string]bool, len(staged))
	for _, file := range staged {
		stagedSet[file] = true
	}
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "ls-files", "--stage", "-z")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("get staged index modes: %s: %w", strings.TrimSpace(string(output)), err)
	}
	trimmed := bytes.TrimSuffix(output, []byte{0})
	var submodules []string
	for _, record := range bytes.Split(trimmed, []byte{0}) {
		parts := bytes.SplitN(record, []byte{'\t'}, 2)
		if len(parts) != 2 {
			if len(record) == 0 {
				continue
			}
			return nil, fmt.Errorf("malformed git index entry")
		}
		metadata := bytes.Fields(parts[0])
		file := string(parts[1])
		if len(metadata) >= 3 && string(metadata[0]) == "160000" && stagedSet[file] {
			submodules = append(submodules, file)
		}
	}
	return submodules, nil
}

// StagedModeChangedFiles lists staged paths whose Git mode changed without
// treating ordinary additions and deletions as mode-only review gaps.
func StagedModeChangedFiles(path string) ([]string, error) {
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "diff", "--cached", "--raw", "-z", "--no-abbrev")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("get staged mode changes: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return ParseModeChangedFiles(output)
}

// ParseModeChangedFiles parses NUL-delimited raw diff records and returns paths
// whose old and new Git modes differ, excluding added and deleted files.
func ParseModeChangedFiles(output []byte) ([]string, error) {
	trimmed := bytes.TrimSuffix(output, []byte{0})
	if len(trimmed) == 0 {
		return []string{}, nil
	}
	tokens := bytes.Split(trimmed, []byte{0})
	var modeChanged []string
	for i := 0; i < len(tokens); {
		fields := bytes.Fields(tokens[i])
		if len(fields) != 5 || len(fields[0]) < 2 || fields[0][0] != ':' {
			return nil, fmt.Errorf("malformed git raw diff record at token %d", i)
		}
		oldMode := string(fields[0][1:])
		newMode := string(fields[1])
		status := string(fields[4])
		i++
		if i >= len(tokens) || len(tokens[i]) == 0 {
			return nil, fmt.Errorf("malformed git raw diff path at token %d", i)
		}
		path := string(tokens[i])
		i++
		if strings.HasPrefix(status, "R") || strings.HasPrefix(status, "C") {
			if i >= len(tokens) || len(tokens[i]) == 0 {
				return nil, fmt.Errorf("malformed git raw diff rename path at token %d", i)
			}
			path = string(tokens[i])
			i++
		}
		if oldMode != newMode && status[0] != 'A' && status[0] != 'D' {
			modeChanged = append(modeChanged, path)
		}
	}
	return modeChanged, nil
}

func UntrackedFiles(path string) ([]string, error) {
	command := exec.Command(
		"git", "-c", "core.fsmonitor=false", "-C", path,
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

// WorkingTreeFiles lists index-tracked paths and all untracked paths, including
// ignored files, using NUL delimiters so unusual filenames are preserved safely.
func WorkingTreeFiles(path string) ([]string, error) {
	return WorkingTreeFilesWithIgnored(path, true)
}

// WorkingTreeFilesWithIgnored lists tracked paths and untracked paths. When
// includeIgnored is false, Git ignore rules filter untracked paths.
func WorkingTreeFilesWithIgnored(path string, includeIgnored bool) ([]string, error) {
	args := []string{"-c", "core.fsmonitor=false", "-C", path, "ls-files", "--cached", "--others"}
	if !includeIgnored {
		args = append(args, "--exclude-standard")
	}
	args = append(args, "-z")
	command := exec.Command("git", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("list working-tree files: %s: %w", strings.TrimSpace(string(output)), err)
	}
	trimmed := bytes.TrimSuffix(output, []byte{0})
	if len(trimmed) == 0 {
		return []string{}, nil
	}
	files := strings.Split(string(trimmed), "\x00")
	sort.Strings(files)
	return files, nil
}

// StagedDiff returns the patch for changes staged for commit.
func StagedDiff(path string) (string, error) {
	command := exec.Command(
		"git",
		"-c", "core.fsmonitor=false",
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

// UnstagedDiff returns the patch for tracked changes not yet staged.
func UnstagedDiff(path string) (string, error) {
	command := exec.Command(
		"git",
		"-c", "core.fsmonitor=false",
		"-C", path,
		"diff",
		"--no-ext-diff",
		"--unified=0",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("get unstaged diff: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return string(output), nil
}

// UnstagedFiles returns tracked files with unstaged modifications.
func UnstagedFiles(path string) ([]string, error) {
	command := exec.Command("git", "-c", "core.fsmonitor=false", "-C", path, "diff", "--name-only", "-z")
	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("get unstaged files: %s: %w", strings.TrimSpace(string(output)), err)
	}
	files := strings.Split(strings.TrimSuffix(string(output), "\x00"), "\x00")
	if len(files) == 1 && files[0] == "" {
		return []string{}, nil
	}
	return files, nil
}

// WorkingTreeDiffAgainst returns the patch of working-tree changes relative to
// a base ref (used by "review --base").
func WorkingTreeDiffAgainst(path, ref string) (string, error) {
	command := exec.Command(
		"git",
		"-c", "core.fsmonitor=false",
		"-C",
		path,
		"diff",
		ref,
		"--no-ext-diff",
		"--unified=0",
	)

	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"get diff against %s: %s: %w",
			ref,
			strings.TrimSpace(string(output)),
			err,
		)
	}

	return string(output), nil
}

// ChangedFilesAgainst lists files differing between the working tree and ref.
func ChangedFilesAgainst(path, ref string) ([]string, error) {
	command := exec.Command(
		"git",
		"-c", "core.fsmonitor=false",
		"-C",
		path,
		"diff",
		"--name-only",
		"-z",
		ref,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"list files changed against %s: %s: %w",
			ref,
			strings.TrimSpace(string(output)),
			err,
		)
	}

	trimmed := strings.TrimRight(string(output), "\x00")
	if trimmed == "" {
		return nil, nil
	}
	files := strings.Split(trimmed, "\x00")
	sort.Strings(files)
	return files, nil
}

// BinaryFilesAgainst lists files that differ from ref and are binary.
func BinaryFilesAgainst(path, ref string) ([]string, error) {
	command := exec.Command(
		"git",
		"-c", "core.fsmonitor=false",
		"-C",
		path,
		"diff",
		"--numstat",
		"-z",
		ref,
	)

	output, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf(
			"list binary files against %s: %s: %w",
			ref,
			strings.TrimSpace(string(output)),
			err,
		)
	}

	var files []string
	for _, record := range strings.Split(string(output), "\x00") {
		fields := strings.SplitN(record, "\t", 3)
		if len(fields) != 3 {
			continue
		}
		if fields[0] == "-" && fields[1] == "-" {
			files = append(files, fields[2])
		}
	}
	sort.Strings(files)
	return files, nil
}
