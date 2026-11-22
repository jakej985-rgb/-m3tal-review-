package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// UnhandledStreamRule detects hardware and transport stream subscriptions that omit
// `onError:` or `onDone:` handlers. When a USB cable is abruptly disconnected, socket drops,
// or buffer corrupts, omitting these lifecycle handlers causes dropped errors to escape
// to the root zone or leaves connection state machines permanently stuck in connected states.
type UnhandledStreamRule struct {
	ruleRuntime
}

func (UnhandledStreamRule) Name() string { return "unhandled-stream-lifecycle" }

var (
	streamTransportFileRe = regexp.MustCompile(`(?i)(?:bridge|serial|hardware|transport|driver|peripheral).*\.(?:dart|ts|js)$`)

	// streamListenRe matches .listen calls on stream variables
	streamListenRe = regexp.MustCompile(`\b(?:connection\.lines|port\.stream|_stream|stream)\s*\.\s*listen\s*\(`)
)

func (r UnhandledStreamRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r UnhandledStreamRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !streamTransportFileRe.MatchString(block.file) {
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

			if streamListenRe.MatchString(trimmed) {
				// Inspect the full call within the next ~6 lines
				callBlock := trimmed
				for j := 1; j <= 6 && i+j < len(lines); j++ {
					callBlock += " " + strings.TrimSpace(lines[i+j])
					if strings.Contains(lines[i+j], ");") {
						break
					}
				}

				hasOnError := strings.Contains(callBlock, "onError:")
				hasOnDone := strings.Contains(callBlock, "onDone:")

				if !hasOnError || !hasOnDone {
					if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
						key := block.file + ":" + strconv.Itoa(lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "unhandled-stream-lifecycle",
								Severity:    "medium",
								File:        block.file,
								Line:        lineNum,
								Message:     "Hardware data stream subscription omits 'onError:' or 'onDone:' lifecycle handlers",
								Remediation: "Provide explicit 'onError:' and 'onDone:' callbacks to handle physical cable disconnects and stream errors safely.",
							})
						}
					}
				}
			}
		}
	}

	return findings
}
