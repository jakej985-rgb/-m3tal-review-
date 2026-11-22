package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// ScopedTestDiscoveryRule detects release preflight gates and workflows that
// use overly broad test discovery patterns (e.g. `unittest discover ... -p 'test_*.py'`)
// across multi-suite test directories, which selects unrelated domain tests
// (such as PDF/renderer or simulator tests) and causes release preflight failures.
type ScopedTestDiscoveryRule struct {
	ruleRuntime
}

func (ScopedTestDiscoveryRule) Name() string { return "release-preflight-scope" }

var (
	releaseScriptOrWorkflowRe = regexp.MustCompile(`(?i)(?:quality_gate|\.github/workflows/|scripts/.*release|scripts/.*preflight).*\.(?:sh|yml|yaml|bash)$`)

	// broadTestDiscoveryRe matches unittest discover commands with wildcard test_*.py
	broadTestDiscoveryRe = regexp.MustCompile(`unittest\s+discover\s+.*-p\s+['"]test_\*\.py['"]`)
)

func (r ScopedTestDiscoveryRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r ScopedTestDiscoveryRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !releaseScriptOrWorkflowRe.MatchString(block.file) {
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
			if !block.addedLines[lineNum] && r.workingTree == false {
				continue
			}

			if broadTestDiscoveryRe.MatchString(line) {
				// Check if the context is release-tool or preflight testing
				isReleaseToolContext := false
				startCheck := i - 5
				if startCheck < 0 {
					startCheck = 0
				}
				for j := startCheck; j <= i; j++ {
					lower := strings.ToLower(lines[j])
					if strings.Contains(lower, "release-tool") || strings.Contains(lower, "release_tool") || strings.Contains(lower, "release tool") || strings.Contains(lower, "quality gate") || strings.Contains(lower, "preflight") {
						isReleaseToolContext = true
						break
					}
				}

				if isReleaseToolContext {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "release-preflight-scope",
							Severity:    "medium",
							File:        block.file,
							Line:        lineNum,
							Message:     "Release preflight uses broad test discovery pattern ('test_*.py'); unrelated test suites can block release pipelines",
							Remediation: "Scope release-tool test discovery to specific test targets (e.g. 'test_generate_release_*.py') or isolate into a dedicated directory.",
						})
					}
				}
			}
		}
	}

	return findings
}
