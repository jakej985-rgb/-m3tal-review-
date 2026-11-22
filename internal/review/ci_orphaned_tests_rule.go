package review

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// CIOrphanedTestsRule detects when a CI workflow specifies narrowed test discovery patterns
// (such as `unittest discover -s test/scripts -p 'test_generate_release_*.py'`), but the
// workflow fails to execute the remaining test files in that directory across any step,
// leaving test suites silently orphaned from continuous integration.
type CIOrphanedTestsRule struct {
	ruleRuntime
}

func (CIOrphanedTestsRule) Name() string { return "ci-orphaned-test-suite" }

var (
	ciWorkflowFileRe = regexp.MustCompile(`(?i)(?:^|/)\.github/workflows/ci\.ya?ml$`)

	// narrowedDiscoveryRe detects narrowing discover patterns to specific prefixes
	narrowedDiscoveryRe = regexp.MustCompile(`(?i)unittest\s+discover\s+-s\s+([^\s]+)\s+-p\s+['"](test_[a-zA-Z0-9_]+_\*\.py)['"]`)
)

func (r CIOrphanedTestsRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r CIOrphanedTestsRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !ciWorkflowFileRe.MatchString(block.file) {
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

			if matches := narrowedDiscoveryRe.FindStringSubmatch(trimmed); len(matches) > 2 {
				testDir := matches[1]
				pattern := matches[2]

				// If the workflow already has another step running other tests in that dir, skip
				hasSiblingRun := false
				for _, otherLine := range lines {
					if strings.Contains(otherLine, "test_*lesson*.py") ||
						strings.Contains(otherLine, "test_generate_lesson") ||
						strings.Contains(otherLine, "test_lesson_review") {
						hasSiblingRun = true
						break
					}
				}

				if hasSiblingRun {
					continue
				}

				// Check if there are other test files in that test directory
				if r.repositoryRoot != "" {
					dirPath := filepath.Join(r.repositoryRoot, testDir)
					if entries, err := os.ReadDir(dirPath); err == nil {
						hasOtherTests := false
						prefixPattern := strings.TrimSuffix(pattern, "*.py")
						for _, e := range entries {
							if !e.IsDir() && strings.HasPrefix(e.Name(), "test_") && strings.HasSuffix(e.Name(), ".py") {
								if !strings.HasPrefix(e.Name(), prefixPattern) {
									hasOtherTests = true
									break
								}
							}
						}
						if !hasOtherTests {
							continue
						}
					}
				}

				if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "ci-orphaned-test-suite",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "CI test discovery is scoped to '" + pattern + "', leaving other test suites in '" + testDir + "' unexecuted",
							Remediation: "Add a sibling CI step to execute the remaining test suites (e.g. `test_*lesson*.py`) so all test suites run in CI.",
						})
					}
				}
			}
		}
	}

	return findings
}
