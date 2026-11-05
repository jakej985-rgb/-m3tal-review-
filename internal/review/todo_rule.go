package review

import (
	"path"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

type TodoRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

var todoMarkdown = regexp.MustCompile(`(?i)^\s*(?:#{1,6}\s+|[-*]\s+\[ \]\s+)(TODO|FIXME|XXX)\b`)
var todoMarker = regexp.MustCompile(`(?i)\b(TODO|FIXME|XXX)\b`)

func (TodoRule) Name() string {
	return "todo-marker"
}

func (r TodoRule) Check(diff string) []Finding {
	var findings []Finding
	for _, fileDiff := range ParseDiff(diff) {
		if !isTodoFile(fileDiff.Path) {
			continue
		}
		source, sourceErr := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree)
		sourceText := string(source)
		var sourceLines []string
		if sourceErr == nil {
			sourceLines = strings.Split(sourceText, "\n")
		}
		for _, line := range fileDiff.AddedLines {
			if finding := findTodo(fileDiff, line, sourceText, sourceLines, sourceErr); finding != nil {
				findings = append(findings, *finding)
			}
		}
	}

	return findings
}

func findTodo(fileDiff FileDiff, line int, sourceText string, sourceLines []string, sourceErr error) *Finding {
	text := fileDiff.AddedText[line]
	useSource := sourceErr == nil && line >= 1 && line <= len(sourceLines)
	if useSource {
		text = sourceLines[line-1]
	}
	markers := todoMarker.FindAllStringIndex(text, -1)
	if len(markers) == 0 {
		return nil
	}
	if isMarkdownFile(fileDiff.Path) {
		if !todoMarkdown.MatchString(text) {
			return nil
		}
	} else if useSource {
		matched := false
		for _, marker := range markers {
			offset := lineStartOffset(sourceLines, line) + marker[0]
			if offsetInComment(fileDiff.Path, sourceText, offset) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	} else {
		// The file could not be read, so only the added line is available.
		// offsetInComment on the single line still distinguishes comments
		// from comment-like text inside string literals.
		matched := false
		for _, marker := range markers {
			if offsetInComment(fileDiff.Path, text, marker[0]) {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	}
	return &Finding{
		Rule:        "todo-marker",
		Severity:    "low",
		File:        fileDiff.Path,
		Line:        line,
		Message:     "Added comment contains a TODO/FIXME marker",
		Remediation: "Resolve the TODO or create a tracked issue with an owner and follow-up plan.",
	}
}

func lineStartOffset(lines []string, line int) int {
	offset := 0
	for priorLine := 0; priorLine < line-1 && priorLine < len(lines); priorLine++ {
		offset += len(lines[priorLine]) + 1
	}
	return offset
}

func isTodoFile(file string) bool {
	if (language.CodeChecker{}).Language(file) != language.LanguageUnknown || language.IsLikelySourceFile(file) {
		return true
	}
	return isMarkdownFile(file)
}

func isMarkdownFile(file string) bool {
	return extIs(strings.ToLower(path.Ext(file)), ".md", ".markdown", ".mdown", ".rst")
}
