package review

import (
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/slop"
)

// SlopRule adapts the dedicated slop analyzer to the review engine's Rule API.
type SlopRule struct {
	RepositoryRoot string
	WorkingTree    bool
	Degraded       bool
}

func (SlopRule) Name() string {
	return "code-slop"
}

func (r SlopRule) Check(diff string) []Finding {
	parsed := ParseDiff(diff)
	files := make([]slop.FileDiff, 0, len(parsed))
	for _, fd := range parsed {
		var source string
		if fd.ChangeType == FileAdded {
			source = completeAddedFile(fd)
		}
		files = append(files, slop.FileDiff{
			Path:        fd.Path,
			ChangeType:  string(fd.ChangeType),
			AddedLines:  fd.AddedLines,
			AddedText:   fd.AddedText,
			ContextText: fd.ContextText,
			Source:      source,
		})
	}
	return slop.SlopRule{
		RepositoryRoot: r.RepositoryRoot,
		WorkingTree:    r.WorkingTree,
		Degraded:       r.Degraded,
	}.Analyze(files)
}

func completeAddedFile(fd FileDiff) string {
	lines := append([]int(nil), fd.AddedLines...)
	sort.Ints(lines)
	if len(lines) == 0 || lines[0] != 1 || lines[len(lines)-1] != len(lines) {
		return ""
	}
	var source strings.Builder
	for index, line := range lines {
		if line != index+1 {
			return ""
		}
		source.WriteString(fd.AddedText[line])
		if index+1 < len(lines) {
			source.WriteByte('\n')
		}
	}
	return source.String()
}
