package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// ScrollFocusRule detects interactive and keyboard-navigable widgets inside
// scrollable containers (e.g. sidebars, lists, menus) whose focus change handler
// updates focus state without ensuring visibility via Scrollable.ensureVisible.
// Without explicit visibility reveals, forward and reverse keyboard tab navigation
// can cycle focus into clipped or off-screen items whose focus ring is hidden.
type ScrollFocusRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (ScrollFocusRule) Name() string {
	return "flutter-scroll-focus-visibility"
}

func (r ScrollFocusRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	onFocusChangeRe = regexp.MustCompile(
		`\bonFocusChange\s*:\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*\{`,
	)
	scrollableIndicatorRe = regexp.MustCompile(
		`(?i)(?:ListView|SingleChildScrollView|CustomScrollView|Scrollable|ScrollController|sidebar|drawer)`,
	)
	ensureVisibleRe = regexp.MustCompile(
		`\bScrollable\s*\.\s*ensureVisible\b`,
	)
)

func (r ScrollFocusRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(filePath, ".dart") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r ScrollFocusRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	source := block.text

	// Must be in a file or block involving scrollable or sidebar structures
	isScrollableContext := scrollableIndicatorRe.MatchString(block.file) ||
		scrollableIndicatorRe.MatchString(source)

	if !isScrollableContext {
		return findings
	}

	lines := strings.Split(source, "\n")
	for i, line := range lines {
		m := onFocusChangeRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}

		findingLine := block.firstLine + i

		// Check if inside added lines
		if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
			continue
		}

		// Inspect the onFocusChange handler body
		handlerChunk := strings.Join(lines[i:], "\n")
		braceIdx := strings.Index(handlerChunk, "{")
		idxClose := findMatchingBrace(handlerChunk, braceIdx)

		var handlerBody string
		if idxClose > 0 && idxClose <= len(handlerChunk) {
			handlerBody = handlerChunk[:idxClose]
		} else {
			end := i + 20
			if end > len(lines) {
				end = len(lines)
			}
			handlerBody = strings.Join(lines[i:end], "\n")
		}

		// If it updates focus state (e.g. setState or assigning focus flag)
		updatesFocus := strings.Contains(handlerBody, "focused") &&
			(strings.Contains(handlerBody, "setState") || strings.Contains(handlerBody, "_isFocused"))

		if !updatesFocus {
			continue
		}

		// If it calls Scrollable.ensureVisible, it is compliant
		if ensureVisibleRe.MatchString(handlerBody) {
			continue
		}

		key := fmt.Sprintf("%s:%d:flutter-scroll-focus-visibility", block.file, findingLine)
		if seen[key] {
			continue
		}
		seen[key] = true

		findings = append(findings, Finding{
			File:        block.file,
			Line:        findingLine,
			Rule:        "flutter-scroll-focus-visibility",
			Severity:    "medium",
			Category:    "quality",
			Confidence:  "high",
			Message:     "Invisible focus in scrollable container: onFocusChange updates focus state without ensuring the focused widget is visible in viewport.",
			Remediation: "When an interactive row gains focus, call Scrollable.ensureVisible(context, ...) so the focus outline remains visible during forward and reverse keyboard navigation.",
		})
	}

	return findings
}

func findMatchingBrace(s string, openIdx int) int {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != '{' {
		return -1
	}
	depth := 0
	inString := false
	var quoteChar rune

	for i, r := range s[openIdx:] {
		actualIdx := openIdx + i
		if inString {
			if r == quoteChar && (i == 0 || s[actualIdx-1] != '\\') {
				inString = false
			}
			continue
		}
		if r == '"' || r == '\'' {
			inString = true
			quoteChar = r
			continue
		}
		if r == '{' {
			depth++
		} else if r == '}' {
			depth--
			if depth == 0 {
				return actualIdx
			}
		}
	}
	return -1
}
