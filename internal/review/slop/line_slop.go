package slop

import (
	"regexp"
	"sort"
	"strings"
)

var slopDebugLeftoverPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^debugger\s*;?\s*$`),
	regexp.MustCompile(`^breakpoint\s*\(\s*\)`),
	regexp.MustCompile(`^import\s+.*\bipdb\b|^import\s+pdb\b|set_trace\s*\(`),
	regexp.MustCompile(`\bdbg!\s*\(`),
	regexp.MustCompile(`\bruntime\.Breakpoint\s*\(`),
	regexp.MustCompile(`\b(?:binding\.pry|debugger\b)`),
	regexp.MustCompile(`\bvar_dump\s*\(|\bdd\s*\(\s*\$`),
	regexp.MustCompile(`System\.out\.println|printStackTrace\s*\(`),
}

var slopSuppressionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^//+\s*(?:nolint\b|eslint-disable|noinspection|ts-ignore|ts-nocheck|ts-expect-error|revive:disable|staticcheck:ignore)`),
	regexp.MustCompile(`^#+\s*(?:noinspection|pragma:\s*no\s*cover|fmt:\s*(?:off|on|skip)|isort:\s*(?:skip|off)|mypy:\s*ignore)`),
	regexp.MustCompile(`#\s*(?:noqa\b|type:\s*ignore\b|pylint:\s*disable|shellcheck\s+disable)`),
	regexp.MustCompile(`^(?:/\*+|\*+)\s*(?:eslint-disable|nolint|noinspection)`),
	regexp.MustCompile(`^<!--\s*(?:eslint|markdownlint|prettier-ignore)`),
	regexp.MustCompile(`^--\s*(?:luacheck:|selene:)`),
}

// checkSlopLineExtras applies language-agnostic heuristics to added lines:
// lint suppressions, runs of commented-out code, and duplicated blocks.
func checkSlopLineExtras(fd FileDiff) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	lines := make([]int, 0, len(fd.AddedLines))
	for _, line := range fd.AddedLines {
		lines = append(lines, line)
	}
	sort.Ints(lines)

	// Lint/tool suppressions added without visible justification.
	for _, line := range lines {
		trimmed := strings.TrimSpace(fd.AddedText[line])
		for _, pattern := range slopSuppressionPatterns {
			if pattern.MatchString(trimmed) {
				appendSlopFinding(&findings, seen, fd.Path, line, "Lint suppression without justification", "Suppressions hide findings; add a short justification or fix the underlying issue.")
				break
			}
		}
	}

	// Line hygiene: trailing whitespace, long lines, mixed indentation,
	// debug leftovers, and runs of blank lines.
	blankRun := 0
	for _, line := range lines {
		raw := fd.AddedText[line]
		trimmedRaw := strings.TrimRight(raw, " \t\r")
		if trimmedRaw != raw {
			appendSlopFinding(&findings, seen, fd.Path, line, "Trailing whitespace", "Remove trailing spaces or tabs.")
		}
		if len(raw) > 120 {
			appendSlopFinding(&findings, seen, fd.Path, line, "Line exceeds 120 characters", "Consider wrapping the line for readability.")
		}
		indent := raw[:len(raw)-len(strings.TrimLeft(raw, " \t"))]
		if strings.Contains(indent, " ") && strings.Contains(indent, "\t") {
			appendSlopFinding(&findings, seen, fd.Path, line, "Mixed tabs and spaces in indentation", "Pick one indentation style consistently.")
		}
		if strings.TrimSpace(raw) == "" {
			blankRun++
			if blankRun == 3 {
				appendSlopFinding(&findings, seen, fd.Path, line-2, "Excessive consecutive blank lines", "Collapse runs of blank lines to at most two.")
			}
		} else {
			blankRun = 0
		}
		for _, pattern := range slopDebugLeftoverPatterns {
			if pattern.MatchString(strings.TrimSpace(raw)) {
				appendSlopFinding(&findings, seen, fd.Path, line, "Debug leftover statement", "Remove debugger/breakpoint statements before committing.")
				break
			}
		}
	}

	// Runs of at least two consecutive added comment lines that look like code.
	runStart, runPrev := 0, 0
	for _, line := range lines {
		if commentedOutCode(fd.AddedText[line]) == "" {
			if runStart != 0 && runPrev-runStart+1 >= 2 {
				appendSlopFinding(&findings, seen, fd.Path, runStart, "Commented-out code", "Remove dead commented code or restore it if it is still needed.")
			}
			runStart, runPrev = 0, 0
			continue
		}
		if runStart == 0 {
			runStart, runPrev = line, line
			continue
		}
		if line == runPrev+1 {
			runPrev = line
		} else {
			if runPrev-runStart+1 >= 2 {
				appendSlopFinding(&findings, seen, fd.Path, runStart, "Commented-out code", "Remove dead commented code or restore it if it is still needed.")
			}
			runStart, runPrev = line, line
		}
	}
	if runStart != 0 && runPrev-runStart+1 >= 2 {
		appendSlopFinding(&findings, seen, fd.Path, runStart, "Commented-out code", "Remove dead commented code or restore it if it is still needed.")
	}

	findings = append(findings, duplicateBlockFindings(fd, lines)...)
	return findings
}

var commentPrefixes = []string{"//", "#", "/*", "*", "<!--", "-- "}

// commentedOutCode strips a leading comment marker and reports whether the
// remainder looks like code rather than prose.
func commentedOutCode(text string) string {
	trimmed := strings.TrimSpace(text)
	for _, prefix := range commentPrefixes {
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(trimmed, prefix))
		if looksLikeCommentedCode(rest) {
			return rest
		}
		return ""
	}
	return ""
}

func looksLikeCommentedCode(s string) bool {
	if len(s) < 8 || strings.Contains(s, "http") || strings.Contains(s, "@") {
		return false
	}
	if strings.HasSuffix(s, ".") || strings.HasSuffix(s, ",") {
		return false
	}
	hasLetter := false
	for i := 0; i < len(s); i++ {
		if (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z') {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return false
	}
	if !strings.ContainsAny(s, "{};=") && !strings.Contains(s, "->") && !strings.Contains(s, "=>") {
		return false
	}
	// Code-like text almost always contains an assignment, terminator, or brace.
	return strings.ContainsAny(s, "=;{}")
}

// duplicateBlockFindings finds identical sequences of 4+ normalized added
// lines within the same file.
func duplicateBlockFindings(fd FileDiff, lines []int) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	type ref struct {
		run, idx int
	}
	firstSeen := make(map[string]ref)

	// Split added lines into contiguous runs.
	var runs [][]int
	var norms [][]string
	for _, line := range lines {
		if len(runs) == 0 || line != runs[len(runs)-1][len(runs[len(runs)-1])-1]+1 {
			runs = append(runs, nil)
			norms = append(norms, nil)
		}
		r := len(runs) - 1
		runs[r] = append(runs[r], line)
		norms[r] = append(norms[r], normalizeSlopLine(fd.AddedText[line]))
	}

	for r, run := range runs {
		norm := norms[r]
		for i := 0; i+4 <= len(norm); i++ {
			gram := strings.Join(norm[i:i+4], "\n")
			if !dupBlockSubstantive(norm[i:i+4]) || dupBlockAllComments(norm[i:i+4]) {
				continue
			}
			if prev, ok := firstSeen[gram]; ok && (prev.run != r || prev.idx != i) {
				dupLen := 4
				prevNorm := norms[prev.run]
				for i+dupLen < len(norm) && prev.idx+dupLen < len(prevNorm) && norm[i+dupLen] == prevNorm[prev.idx+dupLen] {
					dupLen++
				}
				appendSlopFinding(&findings, seen, fd.Path, run[i], "Duplicated code block", "Extract the repeated logic into a shared helper or function.")
				i += dupLen - 1
				continue
			}
			firstSeen[gram] = ref{run: r, idx: i}
		}
	}
	return findings
}

func normalizeSlopLine(line string) string {
	return strings.Join(strings.Fields(line), " ")
}

func dupBlockAllComments(lines []string) bool {
	for _, line := range lines {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "//") && !strings.HasPrefix(line, "#") &&
			!strings.HasPrefix(line, "*") && !strings.HasPrefix(line, "<!--") &&
			!strings.HasPrefix(line, "--") {
			return false
		}
	}
	return true
}

func dupBlockSubstantive(lines []string) bool {
	letters, operators := 0, 0
	for _, line := range lines {
		if line == "" {
			continue
		}
		for i := 0; i < len(line); i++ {
			c := line[i]
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
				letters++
			}
			if strings.ContainsRune("(){}=;:", rune(c)) {
				operators++
			}
		}
	}
	return letters >= 4 && operators >= 2
}

// crossFileDuplicateFindings extends duplicate-block detection across all
// changed files in the diff: identical normalized 4-line sequences appearing
// in different files are flagged once per extra file.
func crossFileDuplicateFindings(fileDiffs []FileDiff) []Finding {
	type ref struct {
		file string
		line int
	}
	firstSeen := make(map[string]ref)
	seen := make(map[string]bool)
	var findings []Finding
	for _, fd := range fileDiffs {
		if fd.ChangeType == FileDeleted || len(fd.AddedLines) == 0 {
			continue
		}
		lines := make([]int, 0, len(fd.AddedLines))
		for _, line := range fd.AddedLines {
			lines = append(lines, line)
		}
		sort.Ints(lines)
		// Contiguous runs of added lines.
		var runs [][]int
		var norms [][]string
		for _, line := range lines {
			if len(runs) == 0 || line != runs[len(runs)-1][len(runs[len(runs)-1])-1]+1 {
				runs = append(runs, nil)
				norms = append(norms, nil)
			}
			r := len(runs) - 1
			runs[r] = append(runs[r], line)
			norms[r] = append(norms[r], normalizeSlopLine(fd.AddedText[line]))
		}
		for r, run := range runs {
			norm := norms[r]
			for i := 0; i+4 <= len(norm); i++ {
				gram := strings.Join(norm[i:i+4], "\n")
				if !dupBlockSubstantive(norm[i:i+4]) || dupBlockAllComments(norm[i:i+4]) {
					continue
				}
				if prev, ok := firstSeen[gram]; ok && prev.file != fd.Path {
					appendSlopFinding(&findings, seen, fd.Path, run[i], "Code block duplicated across files", "The same block appears in "+prev.file+"; extract it into a shared helper.")
					i += 3
					continue
				}
				if _, ok := firstSeen[gram]; !ok {
					firstSeen[gram] = ref{file: fd.Path, line: run[i]}
				}
			}
			_ = r
		}
	}
	return findings
}
