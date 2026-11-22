package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// A11yTestGapRule flags widget tests that assert interactive accessibility
// elements (such as Tooltip or Semantics) using only shallow type queries
// (e.g. find.byType(Tooltip)) without exercising accessibility actions
// (SemanticsAction.tap), testing hover states, or asserting semantic node properties.
type A11yTestGapRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (A11yTestGapRule) Name() string {
	return "test-a11y-action-gap"
}

func (r A11yTestGapRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	testWidgetsRe = regexp.MustCompile(
		`\btestWidgets\s*\(\s*(['"][^'"]*['"])`,
	)
	shallowTooltipExpectRe = regexp.MustCompile(
		`\bexpect\s*\(\s*find\.byType\s*\(\s*Tooltip\s*\)`,
	)
	semanticsExerciseRe = regexp.MustCompile(
		`\b(?:getSemantics|SemanticsAction|semanticsOwner|find\.bySemanticsLabel|matchesSemantics)\b`,
	)
	tooltipHoverExerciseRe = regexp.MustCompile(
		`\b(?:createGesture|PointerDeviceKind\.mouse|find\.text\s*\(\s*['"][^'"]+['"]\s*\)|sendEventToBinding)\b`,
	)
)

func (r A11yTestGapRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(filePath, ".dart") || !isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r A11yTestGapRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		findingLine := block.firstLine + i

		// Only inspect added lines
		if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
			continue
		}

		if shallowTooltipExpectRe.MatchString(line) {
			// Inspect the surrounding test body
			start := i - 30
			if start < 0 {
				start = 0
			}
			end := i + 50
			if end > len(lines) {
				end = len(lines)
			}
			surroundingCode := strings.Join(lines[start:end], "\n")

			hasSemanticsAssertion := semanticsExerciseRe.MatchString(surroundingCode)
			hasTooltipHover := tooltipHoverExerciseRe.MatchString(surroundingCode)

			if !hasSemanticsAssertion || !hasTooltipHover {
				key := fmt.Sprintf("%s:%d:test-a11y-action-gap", block.file, findingLine)
				if seen[key] {
					continue
				}
				seen[key] = true

				findings = append(findings, Finding{
					File:        block.file,
					Line:        findingLine,
					Rule:        "test-a11y-action-gap",
					Severity:    "low",
					Category:    "quality",
					Confidence:  "high",
					Message:     "Untested tooltips and accessibility states: test counts Tooltip widgets without hovering or verifying semantic button roles and selected states.",
					Remediation: "Assert semantic roles using tester.getSemantics(...) or dispatch SemanticsAction.tap to verify accessibility contracts instead of only counting widget instances.",
				})
			}
		}
	}

	return findings
}
