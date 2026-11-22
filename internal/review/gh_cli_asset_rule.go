package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// GhCliAssetRule flags incorrect asset property queries against GitHub CLI (gh).
// `gh release view --json assets` outputs asset objects with a `.url` property,
// NOT `.browser_download_url` (which exists only in raw GitHub REST API responses).
// Querying `.browser_download_url` via jq or python against `gh release view` returns null.
type GhCliAssetRule struct {
	ruleRuntime
}

func (GhCliAssetRule) Name() string { return "gh-cli-asset-url" }

var (
	shellOrWorkflowFileRe = regexp.MustCompile(`(?:^|/)(?:.*\.sh|.*\.bash|\.github/workflows/.*\.ya?ml)$`)
	ghReleaseViewAssetsRe = regexp.MustCompile(`gh\s+release\s+view\b[^\n]*--json\s+assets\b`)
	browserDownloadUrlRe  = regexp.MustCompile(`\.browser_download_url\b`)
)

func (r GhCliAssetRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r GhCliAssetRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !shellOrWorkflowFileRe.MatchString(block.file) {
			continue
		}

		lines := strings.Split(block.text, "\n")
		for i, line := range lines {
			lineNum := block.firstLine + i
			if !block.addedLines[lineNum] {
				continue
			}

			// If line or block combines `gh release view` and `browser_download_url`:
			if browserDownloadUrlRe.MatchString(line) && (ghReleaseViewAssetsRe.MatchString(line) || ghReleaseViewAssetsRe.MatchString(block.text)) {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "gh-cli-asset-url",
						Severity:    "medium",
						File:        block.file,
						Line:        lineNum,
						Message:     "GitHub CLI (`gh release view --json assets`) models asset download URLs as `.url`, not `.browser_download_url`",
						Remediation: "Replace `.browser_download_url` with `.url` when parsing JSON output from `gh release view`.",
					})
				}
			}
		}
	}

	return findings
}
