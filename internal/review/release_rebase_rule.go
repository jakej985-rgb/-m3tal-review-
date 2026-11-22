package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// ReleaseRebaseRule flags automated rebasing onto remote branches in release workflows.
// Rebasing onto origin/<branch> after a preflight quality gate means the published
// release artifacts contain code that bypassed the preflight validation.
type ReleaseRebaseRule struct {
	ruleRuntime
}

func (ReleaseRebaseRule) Name() string { return "release-rebase-race" }

var (
	releaseWorkflowRe = regexp.MustCompile(`(?:^|/)\.github/workflows/.*(?:release|publish|deploy).*\.ya?ml$`)
	gitRebaseCmdRe    = regexp.MustCompile(`\bgit\s+rebase\s+(?:origin/\w+|[a-zA-Z0-9_\-./]+)`)
)

func (r ReleaseRebaseRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r ReleaseRebaseRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !releaseWorkflowRe.MatchString(block.file) {
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

			if gitRebaseCmdRe.MatchString(line) {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "release-rebase-race",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Release workflow rebases onto remote branch; rebased commits bypass preflight quality gate",
						Remediation: "Do not rebase onto remote heads after preflight verification; abort release if remote branch has advanced, or re-run the full gate on the rebased SHA.",
					})
				}
			}
		}
	}

	return findings
}
