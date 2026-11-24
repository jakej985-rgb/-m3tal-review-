package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// ShortcutScopeRule detects CallbackShortcuts mounted inside shell scaffolds
// rather than at the application root (e.g. MaterialApp.router builder).
// When CallbackShortcuts is hosted inside a shell scaffold, detail screens
// rendered via parentNavigatorKey (root navigator) bypass the shortcut focus
// chain, dropping keyboard shortcuts (such as zoom, reset, F1) on detail views.
type ShortcutScopeRule struct {
	ruleRuntime
}

func (ShortcutScopeRule) Name() string {
	return "flutter-shell-shortcuts-ancestor"
}

var (
	callbackShortcutsRe = regexp.MustCompile(`\bCallbackShortcuts\s*\(`)
	shellScaffoldPathRe = regexp.MustCompile(`(?i)(?:scaffold/|shell|main_scaffold)`)
	rootMaterialAppRe   = regexp.MustCompile(`\bMaterialApp(?:\.router)?\s*\(`)
)

func stripDartComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	inLineComment := false
	inBlockComment := false
	inString := byte(0)
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if inLineComment {
			if ch == '\n' {
				inLineComment = false
				b.WriteByte(ch)
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlockComment = false
				b.WriteString("  ")
				i++
			} else if ch == '\n' {
				b.WriteByte(ch)
			} else {
				b.WriteByte(' ')
			}
			continue
		}
		if inString != 0 {
			b.WriteByte(ch)
			if ch == '\\' && i+1 < len(src) {
				i++
				b.WriteByte(src[i])
			} else if ch == inString {
				inString = 0
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inString = ch
			b.WriteByte(ch)
			continue
		}
		if ch == '/' && i+1 < len(src) {
			if src[i+1] == '/' {
				inLineComment = true
				b.WriteString("  ")
				i++
				continue
			} else if src[i+1] == '*' {
				inBlockComment = true
				b.WriteString("  ")
				i++
				continue
			}
		}
		b.WriteByte(ch)
	}
	return b.String()
}

func (r ShortcutScopeRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r ShortcutScopeRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !dartSourceFileRe.MatchString(block.file) || isTestFile(block.file) {
			continue
		}

		// Check if file is a shell scaffold component
		if !shellScaffoldPathRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		cleanText := stripDartComments(scanText)

		// If this file configures the root MaterialApp / MaterialApp.router,
		// shortcuts mounted here cover detail routes outside the shell navigator.
		if rootMaterialAppRe.MatchString(cleanText) {
			continue
		}

		if !callbackShortcutsRe.MatchString(cleanText) {
			continue
		}

		lines := strings.Split(cleanText, "\n")
		for i, line := range lines {
			if callbackShortcutsRe.MatchString(line) {
				lineNum := startLine + i
				if len(block.addedLines) > 0 && !block.addedLines[lineNum] {
					continue
				}
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:     "flutter-shell-shortcuts-ancestor",
						Severity: "medium",
						File:     block.file,
						Line:     lineNum,
						Message:  "CallbackShortcuts mounted inside shell scaffold excludes full-screen detail routes",
						Remediation: "Hoist CallbackShortcuts to wrap MaterialApp.router's builder at " +
							"the application root so shortcuts cover detail routes outside the shell navigator.",
					})
				}
			}
		}
	}

	return findings
}
