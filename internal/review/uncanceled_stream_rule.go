package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// UncanceledStreamRule detects when a StreamSubscription is assigned to null,
// overwritten, or discarded without invoking `.cancel()`. Dropping a subscription reference
// without cancellation leaves the underlying event listener active in the background,
// causing dangling callbacks and memory leaks.
type UncanceledStreamRule struct {
	ruleRuntime
}

func (UncanceledStreamRule) Name() string { return "uncanceled-stream-subscription" }

var (
	dartSourceFileRe = regexp.MustCompile(`\.(?:dart|ts|js)$`)

	// nullAssignmentRe detects assigning a subscription variable to null
	nullSubAssignmentRe = regexp.MustCompile(`\b(_?\w*Subscription[<>\w]*)\s*=\s*null\s*;`)

	// cancelCallRe detects calling cancel on the subscription
	cancelCallRe = regexp.MustCompile(`\b(_?\w*Subscription[<>\w]*)\??\s*\.\s*cancel\s*\(`)
)

func (r UncanceledStreamRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r UncanceledStreamRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !dartSourceFileRe.MatchString(block.file) {
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

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			if matches := nullSubAssignmentRe.FindStringSubmatch(trimmed); len(matches) > 1 {
				varName := matches[1]

				// Check if varName.cancel() was called within the previous ~10 lines
				hasCanceled := false
				for j := 1; j <= 12 && i-j >= 0; j++ {
					prevLine := lines[i-j]
					if strings.Contains(prevLine, varName) && strings.Contains(prevLine, "cancel") {
						hasCanceled = true
						break
					}
				}

				if !hasCanceled {
					if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
						key := block.file + ":" + strconv.Itoa(lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "uncanceled-stream-subscription",
								Severity:    "high",
								File:        block.file,
								Line:        lineNum,
								Message:     "StreamSubscription '" + varName + "' is assigned to null without calling cancel()",
								Remediation: "Always await or invoke '" + varName + "?.cancel()' before setting subscription references to null.",
							})
						}
					}
				}
			}
		}
	}

	return findings
}
