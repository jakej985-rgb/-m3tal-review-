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
			parts := strings.Split(strings.TrimPrefix(line, "diff --git "), " ")
			var oldPath, newPath string
			if len(parts) > 0 && strings.HasPrefix(parts[0], "a/") {
				oldPath = strings.TrimPrefix(parts[0], "a/")
			}
			if len(parts) > 1 && strings.HasPrefix(parts[1], "b/") {
				newPath = strings.TrimPrefix(parts[1], "b/")
			}
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
				current.OldPath = strings.TrimPrefix(line, "rename from ")
			} else if strings.HasPrefix(line, "rename to ") {
				current.ChangeType = FileRenamed
				current.NewPath = strings.TrimPrefix(line, "rename to ")
			} else if strings.HasPrefix(line, "--- ") {
				p := strings.TrimPrefix(line, "--- ")
				if p == "/dev/null" {
					current.ChangeType = FileAdded
				} else if strings.HasPrefix(p, "a/") {
					current.OldPath = strings.TrimPrefix(p, "a/")
				}
			} else if strings.HasPrefix(line, "+++ ") {
				p := strings.TrimPrefix(line, "+++ ")
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

