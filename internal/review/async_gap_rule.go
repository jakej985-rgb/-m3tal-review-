package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// AsyncGapRule is a deterministic lifecycle static analyzer that detects
// BuildContext, setState(), or controller calls across async gaps (await) without
// verifying widget mountedness, preventing 'setState() called after dispose()'
// and deactivated ancestor lookup exceptions.
type AsyncGapRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (AsyncGapRule) Name() string {
	return "unmounted-async-gap"
}

func (r *AsyncGapRule) EnableWorkingTree() {
	r.WorkingTree = true
}

func (r AsyncGapRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// await statement
	awaitExprRe = regexp.MustCompile(`\bawait\s+`)

	// Single-line early exit guard (e.g. 'if (!mounted) return;', 'if (x || !context.mounted) return;', 'throw')
	mountedEarlyExitRe = regexp.MustCompile(
		`\bif\s*\([^)]*!(?:context\.)?mounted[^)]*\)\s*(?:return\b|throw\b|rethrow\b)`,
	)

	// Opening of multi-line !mounted guard (e.g. 'if (!mounted) {')
	mountedIfNegativeBlockRe = regexp.MustCompile(
		`\bif\s*\([^)]*!(?:context\.)?mounted[^)]*\)\s*\{`,
	)

	// Unconditional exit statement: return; return x; throw x; rethrow;
	unconditionalExitRe = regexp.MustCompile(`^\s*(?:return\b|throw\b|rethrow\b)`)

	// Guard reference and false comparison patterns
	mountedRefRe   = regexp.MustCompile(`\b(?:context\.)?mounted\b`)
	mountedFalseRe = regexp.MustCompile(`\b(?:context\.)?mounted\s*==\s*false\b|\b(?:context\.)?mounted\s*!=\s*true\b`)

	// Ternary guard on mounted: mounted ? ... : ...
	mountedTernaryRe = regexp.MustCompile(`\b(?:context\.)?mounted\s*\?`)

	// Calls requiring mounted context
	setStateRe   = regexp.MustCompile(`\bsetState\s*\(`)
	contextUseRe = regexp.MustCompile(
		`\b(?:Navigator\.(?:of|pop|push|maybePop|pushNamed|pushReplacement|popUntil)|ScaffoldMessenger\.of|Scaffold\.of|Theme\.of|MediaQuery\.(?:of|sizeOf|orientationOf|paddingOf|viewInsetsOf|platformBrightnessOf|textScalerOf)|FocusScope\.of|DefaultTabController\.of|BlocProvider\.of(?:\s*<[^;\n()]+>)?|context\.(?:go|push|pop|read|watch|select)|ref\.(?:read|watch)|showDialog|showModalBottomSheet|showBottomSheet|showMenu|showDatePicker|showTimePicker|showSearch)\b`,
	)
	controllerRe = regexp.MustCompile(
		`(?i:\b\w*(?:controller|node|animation)\w*)\s*\.\s*(?:forward|reverse|reset|animateTo|jumpTo|jumpToPage|requestFocus)\s*\(`,
	)

	// Method declaration in Dart (handles nested generics like Future<List<T>>)
	methodDeclRe = regexp.MustCompile(
		`(?:^|\s)(?:@override\s+)?(?:void|Widget|Future(?:<[^;\n()]+>)?|[A-Z]\w*(?:<[^;\n()]+>)?|bool|int|String|double)\s+([a-zA-Z0-9_]+)\s*\(`,
	)

	// Event callback opening in Flutter UI (onPressed: () { ..., onTap: () => ...)
	eventCallbackRe = regexp.MustCompile(
		`\bon[A-Z]\w*\s*:\s*(?:\([^)]*\)|[a-zA-Z0-9_]+)?\s*(?:=>|\{)`,
	)

	deactivatedContextRe = regexp.MustCompile(
		`\b(?:Theme\.of|MediaQuery\.(?:of|sizeOf|orientationOf|paddingOf)|Navigator\.of|ScaffoldMessenger\.of|Provider\.of(?:\s*<[^;\n()]+>)?|context\.(?:read|watch|select)(?:\s*<[^;\n()]+>)?|context\.(?:go|push|pop))\s*\(`,
	)
	watchOutsideBuildRe = regexp.MustCompile(
		`\b(?:context|ref)\.watch\s*(?:<[^;\n()]+>)?\s*\(`,
	)
)

func isSafePositiveMountedGuard(line string) bool {
	openIdx := strings.Index(line, "if")
	if openIdx < 0 {
		return false
	}
	parenStart := strings.Index(line[openIdx:], "(")
	if parenStart < 0 {
		return false
	}
	parenStart += openIdx

	parenDepth := 0
	parenEnd := -1
	for idx := parenStart; idx < len(line); idx++ {
		if line[idx] == '(' {
			parenDepth++
		} else if line[idx] == ')' {
			parenDepth--
			if parenDepth == 0 {
				parenEnd = idx
				break
			}
		}
	}
	if parenEnd == -1 {
		return false
	}
	cond := line[parenStart+1 : parenEnd]

	// Disjunctions (||) cannot guarantee mounted is true
	if strings.Contains(cond, "||") {
		return false
	}
	// Must not be negated
	if strings.Contains(cond, "!") {
		return false
	}
	// Must not compare to false
	if mountedFalseRe.MatchString(cond) {
		return false
	}
	// Must reference mounted or context.mounted
	return mountedRefRe.MatchString(cond)
}

func isUnconditionalEarlyExit(lines []string, j int) bool {
	line := lines[j]
	if mountedEarlyExitRe.MatchString(line) {
		return true
	}
	if mountedIfNegativeBlockRe.MatchString(line) {
		maxK := j + 4
		if maxK > len(lines) {
			maxK = len(lines)
		}
		for k := j + 1; k < maxK; k++ {
			trimmed := strings.TrimSpace(lines[k])
			if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			// If unconditional return/throw/rethrow at block level
			if unconditionalExitRe.MatchString(trimmed) {
				return true
			}
			// If nested if or closing brace before an unconditional return, it is NOT guaranteed
			if strings.HasPrefix(trimmed, "if") || strings.Contains(trimmed, "}") {
				return false
			}
		}
	}
	return false
}

func (r AsyncGapRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		// Only check Dart source files (.dart) and ignore tests
		if !strings.HasSuffix(strings.ToLower(filePath), ".dart") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		// If repository snapshot is available, load full file source so partial diff hunks have full enclosing method context
		if r.RepositoryRoot != "" {
			if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
				blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
			}
		}

		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r AsyncGapRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	currentMethod := ""
	methodBaseDepth := 0
	currentBraceDepth := 0

	for i, line := range lines {
		lineNum := block.firstLine + i

		// Track method declarations and depth
		if m := methodDeclRe.FindStringSubmatch(line); len(m) > 1 {
			currentMethod = m[1]
			methodBaseDepth = currentBraceDepth
		}

		// Track braces to know when we exit currentMethod
		for _, ch := range line {
			if ch == '{' {
				currentBraceDepth++
			} else if ch == '}' {
				currentBraceDepth--
				if currentMethod != "" && currentBraceDepth <= methodBaseDepth {
					currentMethod = ""
				}
			}
		}

		// Look for an await expression (async gap)
		if !awaitExprRe.MatchString(line) {
			continue
		}

		// Find the end line of the await statement (balanced parentheses and semicolon)
		stmtEnd := i
		parenDepth := 0
		for k := i; k < len(lines); k++ {
			stmtEnd = k
			for _, ch := range lines[k] {
				if ch == '(' {
					parenDepth++
				} else if ch == ')' {
					parenDepth--
				}
			}
			if parenDepth <= 0 && strings.Contains(lines[k], ";") {
				break
			}
		}

		// Inspect subsequent lines (up to 50 lines) after the await statement completes
		end := stmtEnd + 50
		if end > len(lines) {
			end = len(lines)
		}

		inPositiveGuardBlock := false
		positiveGuardBraceDepth := 0

		for j := stmtEnd + 1; j < end; j++ {
			currLine := lines[j]
			currLineNum := block.firstLine + j

			// If a new method declaration begins, break
			if methodDeclRe.MatchString(currLine) {
				break
			}

			// Check for unconditional early exit of unmounted path
			if isUnconditionalEarlyExit(lines, j) {
				break
			}

			// Check for entering positive guard branch: if (mounted && ...) {
			if !inPositiveGuardBlock && isSafePositiveMountedGuard(currLine) && strings.Contains(currLine, "{") {
				inPositiveGuardBlock = true
				positiveGuardBraceDepth = 1
				// Count any closing braces on the same line after {
				for _, ch := range currLine[strings.Index(currLine, "{")+1:] {
					if ch == '{' {
						positiveGuardBraceDepth++
					} else if ch == '}' {
						positiveGuardBraceDepth--
					}
				}
				if positiveGuardBraceDepth <= 0 {
					inPositiveGuardBlock = false
				}
				continue
			}

			if inPositiveGuardBlock {
				for _, ch := range currLine {
					if ch == '{' {
						positiveGuardBraceDepth++
					} else if ch == '}' {
						positiveGuardBraceDepth--
					}
				}
				if positiveGuardBraceDepth <= 0 {
					inPositiveGuardBlock = false
				}
				// Lines inside positive guard are protected
				continue
			}

			// Single-line ternary guard: mounted ? ... : ...
			if mountedTernaryRe.MatchString(currLine) {
				continue
			}

			// Unprotected call check
			if block.addedLines[currLineNum] || block.addedLines[lineNum] {
				matchedOp := ""
				if setStateRe.MatchString(currLine) {
					matchedOp = "setState()"
				} else if m := contextUseRe.FindString(currLine); m != "" {
					matchedOp = m
				} else if m := controllerRe.FindString(currLine); m != "" {
					matchedOp = strings.TrimSuffix(m, "(")
				}

				if matchedOp != "" {
					key := fmt.Sprintf("%s:%d:%s", block.file, currLineNum, matchedOp)
					if seen[key] {
						continue
					}
					seen[key] = true

					msg := fmt.Sprintf(
						"%s called across async gap (after await on line %d) without checking if (!mounted) or if (!context.mounted); throws if widget unmounts during async operation",
						matchedOp, lineNum,
					)
					remediation := "Add 'if (!mounted) return;' (or 'if (!context.mounted) return;') immediately after the await statement."

					finding := Finding{
						Rule:        "unmounted-async-gap",
						Severity:    "high",
						Category:    "quality",
						File:        block.file,
						Line:        currLineNum,
						Message:     msg,
						Remediation: remediation,
						Confidence:  "High",
						Explanation: &model.FindingExplanation{
							RuleRationale:   "Calling setState, BuildContext, or controllers after an asynchronous operation when the widget has been unmounted causes runtime exceptions.",
							EvidenceSummary: fmt.Sprintf("%s invoked across async boundary without mounted guard.", matchedOp),
							EvidenceKind:    "async-boundary",
							EvidenceSteps: []model.ExplainedStep{
								{
									StepNumber: 1,
									Kind:       "source",
									Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
									Statement:  "Asynchronous await operation suspends execution",
								},
								{
									StepNumber: 2,
									Kind:       "sink",
									Location:   fmt.Sprintf("%s:%d", block.file, currLineNum),
									Statement:  fmt.Sprintf("%s called without verifying widget is still mounted", matchedOp),
								},
							},
						},
					}
					findings = append(findings, finding)
					break
				}
			}
		}
	}

	return findings
}
