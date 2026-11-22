package prreview

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// FileDiff represents changes for a single file in a git diff.
type FileDiff struct {
	OldPath   string
	NewPath   string
	IsNew     bool
	IsDeleted bool
	IsRenamed bool
	Additions int
	Deletions int
	Hunks     []DiffHunk
}

// DiffHunk represents a single contiguous diff hunk.
type DiffHunk struct {
	OldStart int
	OldCount int
	NewStart int
	NewCount int
	Header   string
	Lines    []DiffLine
}

// DiffLine represents a single line inside a diff hunk.
type DiffLine struct {
	Type     LineType // Add, Delete, Context
	Content  string
	OldLine  int // 0 if added
	NewLine  int // 0 if deleted
	Position int // 1-based offset from first @@ header in the file diff
}

// LineType classifies the diff line modification.
type LineType string

const (
	LineAdded   LineType = "added"
	LineDeleted LineType = "deleted"
	LineContext LineType = "context"
)

var hunkHeaderRe = regexp.MustCompile(`^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$`)

// ParseUnifiedDiff parses unified diff output into structured FileDiff records.
func ParseUnifiedDiff(diffText string) ([]*FileDiff, error) {
	scanner := bufio.NewScanner(strings.NewReader(diffText))
	var files []*FileDiff
	var currentFile *FileDiff
	var currentHunk *DiffHunk
	filePos := 0

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "diff --git ") {
			// Start new file
			currentFile = &FileDiff{}
			files = append(files, currentFile)
			currentHunk = nil
			filePos = 0

			parts := strings.Fields(line)
			if len(parts) >= 4 {
				currentFile.OldPath = strings.TrimPrefix(parts[2], "a/")
				currentFile.NewPath = strings.TrimPrefix(parts[3], "b/")
			}
			continue
		}

		if currentFile == nil {
			continue
		}

		if strings.HasPrefix(line, "new file mode") {
			currentFile.IsNew = true
			continue
		}
		if strings.HasPrefix(line, "deleted file mode") {
			currentFile.IsDeleted = true
			continue
		}
		if strings.HasPrefix(line, "rename from ") {
			currentFile.IsRenamed = true
			currentFile.OldPath = strings.TrimPrefix(line, "rename from ")
			continue
		}
		if strings.HasPrefix(line, "rename to ") {
			currentFile.IsRenamed = true
			currentFile.NewPath = strings.TrimPrefix(line, "rename to ")
			continue
		}
		if strings.HasPrefix(line, "--- ") {
			path := strings.TrimPrefix(line, "--- ")
			if path != "/dev/null" {
				currentFile.OldPath = strings.TrimPrefix(path, "a/")
			}
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			path := strings.TrimPrefix(line, "+++ ")
			if path != "/dev/null" {
				currentFile.NewPath = strings.TrimPrefix(path, "b/")
			}
			continue
		}

		if strings.HasPrefix(line, "@@ ") {
			matches := hunkHeaderRe.FindStringSubmatch(line)
			if matches == nil {
				continue
			}

			oldStart, _ := strconv.Atoi(matches[1])
			oldCount := 1
			if matches[2] != "" {
				oldCount, _ = strconv.Atoi(matches[2])
			}
			newStart, _ := strconv.Atoi(matches[3])
			newCount := 1
			if matches[4] != "" {
				newCount, _ = strconv.Atoi(matches[4])
			}

			currentHunk = &DiffHunk{
				OldStart: oldStart,
				OldCount: oldCount,
				NewStart: newStart,
				NewCount: newCount,
				Header:   line,
			}
			currentFile.Hunks = append(currentFile.Hunks, *currentHunk)
			currentHunk = &currentFile.Hunks[len(currentFile.Hunks)-1]
			filePos++
			continue
		}

		if currentHunk == nil {
			continue
		}

		filePos++
		if strings.HasPrefix(line, "+") {
			currentFile.Additions++
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:     LineAdded,
				Content:  strings.TrimPrefix(line, "+"),
				NewLine:  currentHunk.NewStart + countLines(currentHunk.Lines, LineAdded, LineContext),
				Position: filePos,
			})
		} else if strings.HasPrefix(line, "-") {
			currentFile.Deletions++
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:     LineDeleted,
				Content:  strings.TrimPrefix(line, "-"),
				OldLine:  currentHunk.OldStart + countLines(currentHunk.Lines, LineDeleted, LineContext),
				Position: filePos,
			})
		} else if strings.HasPrefix(line, " ") {
			oldLine := currentHunk.OldStart + countLines(currentHunk.Lines, LineDeleted, LineContext)
			newLine := currentHunk.NewStart + countLines(currentHunk.Lines, LineAdded, LineContext)
			currentHunk.Lines = append(currentHunk.Lines, DiffLine{
				Type:     LineContext,
				Content:  strings.TrimPrefix(line, " "),
				OldLine:  oldLine,
				NewLine:  newLine,
				Position: filePos,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan diff: %w", err)
	}

	return files, nil
}

func countLines(lines []DiffLine, types ...LineType) int {
	c := 0
	typeMap := make(map[LineType]bool)
	for _, t := range types {
		typeMap[t] = true
	}
	for _, l := range lines {
		if typeMap[l.Type] {
			c++
		}
	}
	return c
}

// ChangedLines returns a set of 1-based new line numbers modified in this file diff.
func (f *FileDiff) ChangedLines() map[int]bool {
	lines := make(map[int]bool)
	for _, hunk := range f.Hunks {
		for _, l := range hunk.Lines {
			if l.Type == LineAdded && l.NewLine > 0 {
				lines[l.NewLine] = true
			}
		}
	}
	return lines
}

// FindPositionForLine finds the diff position for a given new line number.
func (f *FileDiff) FindPositionForLine(lineNum int) int {
	for _, hunk := range f.Hunks {
		for _, l := range hunk.Lines {
			if l.NewLine == lineNum {
				return l.Position
			}
		}
	}
	return 0
}
