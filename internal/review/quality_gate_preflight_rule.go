package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// QualityGatePreflightRule detects quality gate and CI runner shell scripts that execute
// test runner suites (e.g. python unittest discover) without an early dependency preflight
// check, leading to failure late in the pipeline with ModuleNotFoundError.
type QualityGatePreflightRule struct {
	ruleRuntime
}

func (QualityGatePreflightRule) Name() string {
	return "quality-gate-preflight-dependency"
}

var (
	gateScriptFileRe = regexp.MustCompile(`(?i)(?:quality_gate|gate|check|preflight).*\.sh$`)

	// testDiscoveryRe matches python test discovery commands
	testDiscoveryRe = regexp.MustCompile(`(?i)python3?\s+-m\s+unittest\s+discover\b`)

	// preflightCheckRe matches early preflight python dependency checks
	preflightCheckRe = regexp.MustCompile(`(?i)python3?\s+-c\s+["']import\s+[^"']*["']`)
)

func (r QualityGatePreflightRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r QualityGatePreflightRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !gateScriptFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// Check if the script contains python unittest discovery
		if testDiscoveryRe.MatchString(scanText) && !preflightCheckRe.MatchString(scanText) {
			loc := testDiscoveryRe.FindStringIndex(scanText)
			lineNum := startLine + strings.Count(scanText[:loc[0]], "\n")

			if block.addedLines[lineNum] || r.workingTree {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "quality-gate-preflight-dependency",
						Severity:    "medium",
						File:        block.file,
						Line:        lineNum,
						Message:     "Quality gate executes Python test runner without an early dependency preflight check",
						Remediation: "Add an early preflight check (python3 -c \"import ...\") before running expensive test suites.",
					})
				}
			}
		}
	}

	return findings
}
