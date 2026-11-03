package review

import (
	"strconv"
	"strings"
)

type FileChangeType string

const (
	FileAdded    FileChangeType = "added"
	FileModified FileChangeType = "modified"
	FileDeleted  FileChangeType = "deleted"
	FileRenamed  FileChangeType = "renamed"
)

type FileDiff struct {
	OldPath    string
	NewPath    string
	Path       string
	ChangeType FileChangeType
	AddedLines []int
}

func unquoteDiffPath(s string) string {
	trimmed := strings.TrimRight(s, "\t\r\n ")
	trimmed = strings.TrimSpace(trimmed)
	if unquoted, err := strconv.Unquote(trimmed); err == nil {
		return unquoted
	}
	return strings.Trim(trimmed, "\"")
}

func parseGitDiffHeaderPaths(line string) (string, string) {
	rest := strings.TrimPrefix(line, "diff --git ")
	var oldPart, newPart string

	if strings.HasPrefix(rest, "\"") {
		if idx := strings.Index(rest, "\" \"b/"); idx != -1 {
			oldPart = rest[:idx+1]
			newPart = rest[idx+2:]
		}
	}
	if oldPart == "" && newPart == "" {
		if idx := strings.Index(rest, " b/"); idx != -1 {
			oldPart = rest[:idx]
			newPart = rest[idx+len(" b/"):]
		}
	}

	cleanOld := unquoteDiffPath(oldPart)
	if strings.HasPrefix(cleanOld, "a/") {
		cleanOld = strings.TrimPrefix(cleanOld, "a/")
	}
	cleanNew := unquoteDiffPath(newPart)
	if strings.HasPrefix(cleanNew, "b/") {
		cleanNew = strings.TrimPrefix(cleanNew, "b/")
	}
	return cleanOld, cleanNew
}

// ParseDiff parses a unified git diff into individual file diffs with classifications
// (added, modified, deleted, renamed) and their corresponding added line numbers.
func ParseDiff(diff string) []FileDiff {
	var fileDiffs []FileDiff
	var current *FileDiff

	finish := func() {
		if current == nil {
			return
		}
		if current.ChangeType == "" {
			if current.OldPath != "" && current.NewPath != "" && current.OldPath != current.NewPath {
				current.ChangeType = FileRenamed
			} else {
				current.ChangeType = FileModified
			}
		}
		if current.ChangeType == FileDeleted {
			if current.OldPath != "" {
				current.Path = current.OldPath
			}
			current.NewPath = ""
		} else {
			if current.NewPath != "" {
				current.Path = current.NewPath
			} else if current.OldPath != "" {
				current.Path = current.OldPath
			}
		}
		fileDiffs = append(fileDiffs, *current)
		current = nil
	}

	inHunk := false
	currentLine := 0

	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			finish()
			inHunk = false
			oldPath, newPath := parseGitDiffHeaderPaths(line)
			current = &FileDiff{
				OldPath: oldPath,
				NewPath: newPath,
			}
			continue
		}

		if current == nil && (strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ")) {
			current = &FileDiff{}
			inHunk = false
		}

		if current != nil && !inHunk {
			if strings.HasPrefix(line, "deleted file mode") {
				current.ChangeType = FileDeleted
			} else if strings.HasPrefix(line, "new file mode") {
				current.ChangeType = FileAdded
			} else if strings.HasPrefix(line, "rename from ") {
				current.ChangeType = FileRenamed
				current.OldPath = unquoteDiffPath(strings.TrimPrefix(line, "rename from "))
			} else if strings.HasPrefix(line, "rename to ") {
				current.ChangeType = FileRenamed
				current.NewPath = unquoteDiffPath(strings.TrimPrefix(line, "rename to "))
			} else if strings.HasPrefix(line, "--- ") {
				p := unquoteDiffPath(strings.TrimPrefix(line, "--- "))
				if p == "/dev/null" {
					current.ChangeType = FileAdded
				} else if strings.HasPrefix(p, "a/") {
					current.OldPath = strings.TrimPrefix(p, "a/")
				}
			} else if strings.HasPrefix(line, "+++ ") {
				p := unquoteDiffPath(strings.TrimPrefix(line, "+++ "))
				if p == "/dev/null" {
					current.ChangeType = FileDeleted
				} else if strings.HasPrefix(p, "b/") {
					current.NewPath = strings.TrimPrefix(p, "b/")
				}
			}
		}

		if matches := hunkHeader.FindStringSubmatch(line); matches != nil {
			inHunk = true
			currentLine, _ = strconv.Atoi(matches[1])
			continue
		}

		if inHunk && current != nil {
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				current.AddedLines = append(current.AddedLines, currentLine)
				currentLine++
			} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				// deleted line from old file; do not increment currentLine for new file
			} else if strings.HasPrefix(line, "\\") {
				// e.g. \ No newline at end of file; do not increment
			} else if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				currentLine++
			}
		}
	}

	finish()
	return fileDiffs
}
