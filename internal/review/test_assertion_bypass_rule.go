package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// TestAssertionBypassRule detects conditional statements in unit/widget test files
// that wrap assertions or actions on the system-under-test. Conditional guards like
// `if (!isPlaceholderGated) { await progressRepo.completeLesson(...); }` create
// false-clean test results because when the condition evaluates to false, the test
// silently skips the critical code path instead of validating it or failing.
type TestAssertionBypassRule struct {
	ruleRuntime
}

func (TestAssertionBypassRule) Name() string {
	return "test-assertion-bypass"
}

var (
	testFileRe = regexp.MustCompile(`(?i)(?:^|/)(?:test/|tests/|.*_test\.[a-z]+|test_.*\.py)$`)

	// conditionalGuardRe matches `if (!condition)` or `if (condition)` in tests
	conditionalGuardRe = regexp.MustCompile(`^\s*if\s*\(([^)]+)\)\s*\{?$`)

	// testActionOrAssertRe matches actions under test or assertion calls
	testActionOrAssertRe = regexp.MustCompile(
		`\b(?:expect\s*\(|assert\b|verify\s*\(|\.completeLesson\s*\(|\.addXp\s*\(|\.record\w*\s*\(|` +
			`tester\.tap\s*\(|tester\.pump\w*\s*\()`,
	)

	// allowedConditionalRe allows legitimate conditionals in tests (e.g. platform checks or teardown guards)
	allowedConditionalRe = regexp.MustCompile(`(?i)\b(?:kIsWeb|Platform\.is|isClosed|mounted|isNotEmpty|isEmpty)\b`)
)

func (r TestAssertionBypassRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r TestAssertionBypassRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !testFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
				continue
			}

			matches := conditionalGuardRe.FindStringSubmatch(trimmed)
			if len(matches) < 2 {
				continue
			}

			cond := matches[1]
			if allowedConditionalRe.MatchString(cond) {
				continue
			}

			// Look ahead in the next 5 lines for actions or assertions under test
			hasActionOrAssert := false
			for j := 1; j <= 5 && i+j < len(lines); j++ {
				aheadLine := strings.TrimSpace(lines[i+j])
				if testActionOrAssertRe.MatchString(aheadLine) {
					hasActionOrAssert = true
					break
				}
				if aheadLine == "}" || aheadLine == "" {
					continue
				}
			}

			if hasActionOrAssert {
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:     "test-assertion-bypass",
							Severity: "high",
							File:     block.file,
							Line:     lineNum,
							Message: "Test conditionally wraps actions or assertions under test, " +
								"allowing false-clean passes if the condition is false",
							Remediation: "Remove conditional guard and assert test behavior directly " +
								"or use explicit test preconditions / skip directives.",
						})
					}
				}
			}
		}
	}

	return findings
}
