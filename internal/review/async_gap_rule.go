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

	// Mounted checks (including compound conditions like 'if (x || !context.mounted) return;')
	mountedGuardRe = regexp.MustCompile(
		`\b(?:if\s*\([^)]*!(?:context\.)?mounted[^)]*\)\s*return|if\s*\([^)]*(?:context\.)?mounted[^)]*\)|mounted\s*\?)`,
	)

	// Calls requiring mounted context
	setStateRe = regexp.MustCompile(`\bsetState\s*\(`)
	contextUseRe = regexp.MustCompile(
		`\b(?:Navigator\.(?:of|pop|push)|ScaffoldMessenger\.of|Theme\.of|context\.(?:go|push|pop))\b`,
	)
	lifecycleIllegalSetStateRe = regexp.MustCompile(`\bvoid\s+(initState|dispose)\s*\(\s*\)`)
)

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

	for i, line := range lines {
		lineNum := block.firstLine + i

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
				if strings.Contains(currLine, "void ") || strings.Contains(currLine, "Widget ") || strings.Contains(currLine, "Future<") {
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

		// Inspect subsequent lines (up to 20 lines) after the await statement completes
		end := stmtEnd + 20
		if end > len(lines) {
			end = len(lines)
		}

		hasGuard := false
		for j := stmtEnd + 1; j < end; j++ {
			currLine := lines[j]
			currLineNum := block.firstLine + j

			// If a new function begins, break
			if strings.Contains(currLine, "void ") || strings.Contains(currLine, "Widget ") || strings.Contains(currLine, "Future<") {
				break
			}

			// If a mounted guard is found, subsequent calls in this scope are safe
			if mountedGuardRe.MatchString(currLine) {
				hasGuard = true
				break
			}

			// If we touch an added line that uses setState or context after await without a guard
			if !hasGuard && (block.addedLines[currLineNum] || block.addedLines[lineNum]) {
				matchedOp := ""
				if setStateRe.MatchString(currLine) {
					matchedOp = "setState()"
				} else if m := contextUseRe.FindString(currLine); m != "" {
					matchedOp = m
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
							RuleRationale:   "Calling setState or BuildContext after an asynchronous operation when the widget has been unmounted causes runtime exceptions.",
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
