package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// EventLoopStarvationRule detects batch workers and loops that yield using microtasks
// (such as scheduleMicrotask or Future.microtask) instead of top-level event loop macrotasks.
// In Flutter and Dart, the microtask queue has absolute priority over the event loop, so
// yielding to microtasks continuously starves frame rendering and incoming UI/I/O events.
type EventLoopStarvationRule struct {
	ruleRuntime
}

func (EventLoopStarvationRule) Name() string {
	return "dart-microtask-frame-starvation"
}

var (
	// microtaskYieldRe detects yielding using microtasks
	microtaskYieldRe = regexp.MustCompile(`\b(?:scheduleMicrotask\s*\(|Future(?:\s*<[^>]+>)?\.microtask\s*\()`)

	// loopOrBatchContextRe detects loops or batch processing methods
	loopOrBatchContextRe = regexp.MustCompile(`(?i)(?:for\s*\(|while\s*\(|batch|chunk|yield|stream|process|pipeline)`)
)

func (r EventLoopStarvationRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r EventLoopStarvationRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !dartSourceFileRe.MatchString(block.file) || isTestFile(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if !microtaskYieldRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			if microtaskYieldRe.MatchString(line) {
				// Check surrounding context (previous 15 lines and next 15 lines) for loop or batch context
				startIdx := i - 15
				if startIdx < 0 {
					startIdx = 0
				}
				endIdx := i + 15
				if endIdx > len(lines) {
					endIdx = len(lines)
				}
				contextSnippet := strings.Join(lines[startIdx:endIdx], "\n")

				if loopOrBatchContextRe.MatchString(contextSnippet) {
					lineNum := startLine + i
					if len(block.addedLines) > 0 {
						touchesAdded := false
						firstAdded := -1
						for l := startLine + startIdx; l < startLine+endIdx; l++ {
							if block.addedLines[l] {
								touchesAdded = true
								if firstAdded == -1 {
									firstAdded = l
								}
							}
						}
						if !touchesAdded {
							continue
						}
						if !block.addedLines[lineNum] && firstAdded != -1 {
							lineNum = firstAdded
						}
					}
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "dart-microtask-frame-starvation",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "Loop or batch processor yields execution via microtasks instead of top-level event loop macrotasks",
							Remediation: "Yield using 'await Future<void>.delayed(Duration.zero)' rather than microtasks so frame rendering and UI events are serviced between batches.",
						})
					}
				}
			}
		}
	}

	return findings
}
