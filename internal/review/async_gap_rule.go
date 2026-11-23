package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// AsyncGapRule is a deterministic lifecycle static analyzer that detects
// BuildContext or setState() calls across async gaps (await) without
// verifying widget mountedness, preventing 'setState() called after dispose()'
// and deactivated ancestor lookup exceptions.
type AsyncGapRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (AsyncGapRule) Name() string {
	return "unmounted-async-gap"
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

	// Positive block guard: if (mounted) { or if (context.mounted) { or mounted ?
	mountedPositiveGuardRe = regexp.MustCompile(
		`\bif\s*\(\s*(?:context\.)?mounted\s*\)\s*\{|\bmounted\s*\?`,
	)

	// Early exit statement within multi-line block
	earlyExitRe = regexp.MustCompile(`^\s*(?:return\b|throw\b|rethrow\b)|;\s*(?:return\b|throw\b|rethrow\b)`)

	// Calls requiring mounted context
	setStateRe = regexp.MustCompile(`\bsetState\s*\(`)
	contextUseRe = regexp.MustCompile(
		`\b(?:Navigator\.(?:of|pop|push|maybePop|pushNamed|pushReplacement|popUntil)|ScaffoldMessenger\.of|Scaffold\.of|Theme\.of|MediaQuery\.(?:of|sizeOf|orientationOf|paddingOf|viewInsetsOf|platformBrightnessOf|textScalerOf)|FocusScope\.of|DefaultTabController\.of|BlocProvider\.of|context\.(?:go|push|pop|read|watch|select)|ref\.(?:read|watch)|showDialog|showModalBottomSheet|showBottomSheet|showMenu|showDatePicker|showTimePicker|showSearch)\b`,
	)
	controllerRe = regexp.MustCompile(
		`\b[a-zA-Z0-9_]*(?:Controller|Node|Animation)\s*\.\s*(?:forward|reverse|reset|animateTo|jumpTo|jumpToPage|requestFocus)\s*\(`,
	)

	lifecycleIllegalSetStateRe = regexp.MustCompile(`\bvoid\s+(initState|dispose)\s*\(\s*\)`)
	asyncDisposeMethodRe       = regexp.MustCompile(`\bvoid\s+dispose\s*\(\s*\)`)
	deactivatedContextRe       = regexp.MustCompile(
		`\b(?:Theme\.of|MediaQuery\.(?:of|sizeOf|orientationOf|paddingOf)|Navigator\.of|ScaffoldMessenger\.of|Provider\.of|context\.(?:read|watch|select)(?:\s*<[^>]+>)?|context\.(?:go|push|pop))\s*\(`,
	)
	watchOutsideBuildRe = regexp.MustCompile(`\b(?:context|ref)\.watch\s*(?:<[^>]+>)?\s*\(`)
	methodBoundaryRe    = regexp.MustCompile(`^\s*(?:@override\s+)?(?:void|Widget|Future<[^>]*>|[A-Z]\w*|bool|int|String|double)\s+[a-zA-Z0-9_]+\s*\(`)
)

func isMountedGuard(lines []string, j int) bool {
	line := lines[j]
	if mountedEarlyExitRe.MatchString(line) {
		return true
	}
	if mountedPositiveGuardRe.MatchString(line) {
		return true
	}
	if mountedIfNegativeBlockRe.MatchString(line) {
		maxK := j + 4
		if maxK > len(lines) {
			maxK = len(lines)
		}
		for k := j + 1; k < maxK; k++ {
			trimmed := strings.TrimSpace(lines[k])
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if earlyExitRe.MatchString(trimmed) {
				return true
			}
			if strings.Contains(lines[k], "}") {
				break
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
		if !isUIFile(filePath) || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r AsyncGapRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	inBuildMethod := false

	for i, line := range lines {
		lineNum := block.firstLine + i

		// Track current method context to detect watch() calls outside build()
		if strings.Contains(line, "Widget build(") || strings.Contains(line, "Widget build (") {
			inBuildMethod = true
		} else if methodBoundaryRe.MatchString(line) {
			inBuildMethod = false
		}

		// Check for watch() called outside build()
		if !inBuildMethod && watchOutsideBuildRe.MatchString(line) && block.addedLines[lineNum] {
			key := fmt.Sprintf("%s:%d:watch-outside-build", block.file, lineNum)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        "unmounted-async-gap",
					Severity:    "high",
					Category:    "quality",
					File:        block.file,
					Line:        lineNum,
					Message:     "Calling context.watch() or ref.watch() outside of Widget build() causes runtime exceptions and leaks subscriptions; use context.read() or ref.read() instead",
					Remediation: "Use context.read() or ref.read() in callbacks and async methods.",
					Confidence:  "High",
				})
			}
		}

		// Check for setState called inside initState() or dispose()
		if m := lifecycleIllegalSetStateRe.FindStringSubmatch(line); len(m) > 1 {
			lifecycleMethod := m[1]
			end := i + 30
			if end > len(lines) {
				end = len(lines)
			}
			for j := i + 1; j < end; j++ {
				currLine := lines[j]
				currLineNum := block.firstLine + j
				if methodBoundaryRe.MatchString(currLine) {
					break
				}
				if setStateRe.MatchString(currLine) && (block.addedLines[currLineNum] || block.addedLines[lineNum]) {
					key := fmt.Sprintf("%s:%d:lifecycle-%s-setstate", block.file, currLineNum, lifecycleMethod)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "unmounted-async-gap",
							Severity:    "high",
							Category:    "quality",
							File:        block.file,
							Line:        currLineNum,
							Message:     fmt.Sprintf("Calling setState() inside %s() throws or is redundant; the framework cannot re-render unmounted/building widgets", lifecycleMethod),
							Remediation: fmt.Sprintf("In %s(), assign state variables directly without calling setState().", lifecycleMethod),
							Confidence:  "High",
						})
					}
				}
			}
		}

		// Check for deactivated context / inherited model lookup inside dispose()
		if asyncDisposeMethodRe.MatchString(line) {
			end := i + 30
			if end > len(lines) {
				end = len(lines)
			}
			for j := i + 1; j < end; j++ {
				currLine := lines[j]
				currLineNum := block.firstLine + j
				if methodBoundaryRe.MatchString(currLine) {
					break
				}
				if m := deactivatedContextRe.FindString(currLine); m != "" && (block.addedLines[currLineNum] || block.addedLines[lineNum]) {
					op := strings.TrimSuffix(m, "(")
					key := fmt.Sprintf("%s:%d:dispose-deactivated-%s", block.file, currLineNum, op)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "unmounted-async-gap",
							Severity:    "high",
							Category:    "quality",
							File:        block.file,
							Line:        currLineNum,
							Message:     fmt.Sprintf("Calling %s() inside dispose() attempts to query deactivated widget element ancestors and throws runtime assertions", op),
							Remediation: "Remove context-dependent lookups from dispose(); perform cleanup on listeners, subscriptions, and controllers directly.",
							Confidence:  "High",
						})
					}
				}
			}
		}

		// Look for an await expression
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

		hasGuard := false
		for j := stmtEnd + 1; j < end; j++ {
			currLine := lines[j]
			currLineNum := block.firstLine + j

			// If a new function begins, break
			if methodBoundaryRe.MatchString(currLine) {
				break
			}

			// If a mounted guard is found, subsequent calls in this scope are safe
			if isMountedGuard(lines, j) {
				hasGuard = true
				break
			}

			// If we touch an added line that uses setState, context, or controllers after await without a guard
			if !hasGuard && (block.addedLines[currLineNum] || block.addedLines[lineNum]) {
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
