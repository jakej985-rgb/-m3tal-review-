package review

import (
	"context"
	"regexp"
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
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if ch == '/' && i+1 < len(src) && src[i+1] == '/' {
			i = maskLineComment(src, i, &b)
			continue
		}
		if ch == '/' && i+1 < len(src) && src[i+1] == '*' {
			i = maskBlockComment(src, i, &b)
			continue
		}
		b.WriteByte(ch)
	}
	res := b.String()
	return res
}

func (r ShortcutScopeRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func checkShortcutBlock(b diffSourceBlock, text string, start int, seen map[string]bool) []Finding {
	var shortcutFindings []Finding
	cleanText := stripDartComments(text)
	if rootMaterialAppRe.MatchString(cleanText) || !callbackShortcutsRe.MatchString(cleanText) {
		return nil
	}

	lines := strings.Split(cleanText, "\n")
	for i, line := range lines {
		if callbackShortcutsRe.MatchString(line) && shouldReportFinding(b, start+i, false, seen) {
			shortcutFindings = append(shortcutFindings, Finding{
				Rule:     "flutter-shell-shortcuts-ancestor",
				Severity: "medium",
				File:     b.file,
				Line:     start + i,
				Message:  "CallbackShortcuts mounted inside shell scaffold excludes full-screen detail routes",
				Remediation: "Hoist CallbackShortcuts to wrap MaterialApp.router's builder at " +
					"the application root so shortcuts cover detail routes outside the shell navigator.",
			})
		}
	}
	return shortcutFindings
}

func (r ShortcutScopeRule) CheckContext(ctx context.Context, diff string) []Finding {
	return executeBlockRule(ctx, diff, r.repositoryRoot, r.workingTree, func(f string) bool {
		return dartSourceFileRe.MatchString(f) && !isTestFile(f) && shellScaffoldPathRe.MatchString(f)
	}, checkShortcutBlock)
}
