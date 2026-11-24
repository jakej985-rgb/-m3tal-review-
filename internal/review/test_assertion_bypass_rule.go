package review

import (
	"context"
	"math"
	"regexp"
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

func hasTestAssertion(lines []string, start int) bool {
	hasAssert := false
	for j := 1; j <= 5 && start+j < len(lines); j++ {
		aheadLine := strings.TrimSpace(lines[start+j])
		if testActionOrAssertRe.MatchString(aheadLine) {
			hasAssert = true
			break
		}
	}
	return hasAssert
}

var testCaseStartRe = regexp.MustCompile(`^\s*(?:test|testWidgets|it|group|def\s+test_\w*|func\s+Test\w*)\s*\(`)

func isDeletedTestAssertion(line string) bool {
	trimmed := strings.TrimSpace(line)
	return !strings.HasPrefix(trimmed, "//") &&
		!strings.HasPrefix(trimmed, "#") &&
		testActionOrAssertRe.MatchString(trimmed)
}

// testCaseBounds returns the [first, last] new-side line numbers of the test case enclosing lines[idx].
// When no boundary is visible in the block (e.g. truncated patch context), that side is
// treated as unknown and left open rather than clamped to the block edge.
func testCaseBounds(lines []string, idx, start int) (int, int) {
	first, last := math.MinInt, math.MaxInt
	for k := idx; k >= 0; k-- {
		if testCaseStartRe.MatchString(lines[k]) {
			first = start + k
			break
		}
	}
	for k := idx + 1; k < len(lines); k++ {
		if testCaseStartRe.MatchString(lines[k]) {
			last = start + k - 1
			break
		}
	}
	return first, last
}

// hasRelevantDeletedAssertion reports whether an unconditional assertion was removed
// from the same test case as the guard at lines[idx].
func hasRelevantDeletedAssertion(b diffSourceBlock, lines []string, idx, start int) bool {
	if len(b.deletedAnchors) != len(b.deletedLines) {
		return false
	}
	first, last := testCaseBounds(lines, idx, start)
	for i, del := range b.deletedLines {
		anchor := b.deletedAnchors[i]
		if anchor >= first && anchor <= last && isDeletedTestAssertion(del) {
			return true
		}
	}
	return false
}

func checkTestBypassBlock(b diffSourceBlock, text string, start int, wt bool, seen map[string]bool) []Finding {
	var bypassFindings []Finding
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lineNum := start + i
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}
		matches := conditionalGuardRe.FindStringSubmatch(trimmed)
		if len(matches) < 2 || allowedConditionalRe.MatchString(matches[1]) {
			continue
		}
		if !hasTestAssertion(lines, i) {
			continue
		}
		deletedAssert := hasRelevantDeletedAssertion(b, lines, i, start)
		if !shouldReportAddedFinding(b, lineNum, wt || deletedAssert, seen) {
			continue
		}
		bypassFindings = append(bypassFindings, Finding{
			Rule:     "test-assertion-bypass",
			Severity: "high",
			File:     b.file,
			Line:     lineNum,
			Message: "Test conditionally wraps actions or assertions under test, " +
				"allowing false-clean passes if the condition is false",
			Remediation: "Remove conditional guard and assert test behavior directly " +
				"or use explicit test preconditions / skip directives.",
		})
	}
	return bypassFindings
}

func (r TestAssertionBypassRule) CheckContext(ctx context.Context, diff string) []Finding {
	return executeBlockRule(ctx, diff, r.repositoryRoot, r.workingTree, func(f string) bool {
		return testFileRe.MatchString(f)
	}, func(b diffSourceBlock, text string, start int, seen map[string]bool) []Finding {
		return checkTestBypassBlock(b, text, start, r.workingTree, seen)
	})
}
