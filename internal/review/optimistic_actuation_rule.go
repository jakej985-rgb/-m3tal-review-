package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// OptimisticActuationRule detects hardware control implementations that optimistically
// mark actuators, outputs, or emergency-stops as safe/off in UI or telemetry streams
// before the physical device acknowledges or executes the command, or that swallow
// write transport errors without returning failure to the caller.
type OptimisticActuationRule struct {
	ruleRuntime
}

func (OptimisticActuationRule) Name() string { return "optimistic-actuation-safety" }

var (
	actuatorFileRe = regexp.MustCompile(`(?i)(?:bridge|serial|hardware|actuator|device).*\.(?:dart|ts|js|go|py|kt|java|cpp)$`)

	// optimisticStateUpdateRe detects state/telemetry updates turning off outputs before write
	optimisticTelemetryUpdateRe = regexp.MustCompile(`(?i)(?:_telemetry\s*=\s*_telemetry\.copyWith\s*\(\s*(?:pin\w+|outputs?|actuators?|relay|laser|motor)\w*\s*:\s*false|_telemetryController\.add\b)`)

	// writeCommandRe detects wire write calls
	writeCommandCallRe = regexp.MustCompile(`(?i)(?:await\s+)?(?:_write|writeLine|write|send)\s*\(`)

	// swallowedWriteErrorRe detects write methods that catch exceptions without throwing or returning error status
	swallowedWriteErrorRe = regexp.MustCompile(`(?i)Future<void>\s+_write\s*\([^)]*\)\s*async\s*\{[\s\S]{0,400}?catch\s*\([^)]*\)\s*\{[\s\S]{0,300}?(?:_log|_logger|\.print)[\s\S]{0,200}?\}\s*\}`)
)

func (r OptimisticActuationRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r OptimisticActuationRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !actuatorFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		lines := strings.Split(scanText, "\n")
		pendingOptimisticLine := 0

		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			if optimisticTelemetryUpdateRe.MatchString(trimmed) {
				pendingOptimisticLine = lineNum
				continue
			}

			if pendingOptimisticLine > 0 && lineNum-pendingOptimisticLine <= 5 {
				if writeCommandCallRe.MatchString(trimmed) {
					if block.addedLines[pendingOptimisticLine] || r.workingTree {
						key := block.file + ":" + strconv.Itoa(pendingOptimisticLine)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "optimistic-actuation-safety",
								Severity:    "high",
								File:        block.file,
								Line:        pendingOptimisticLine,
								Message:     "Actuator or emergency-stop state is optimistically marked off before the hardware confirms command execution",
								Remediation: "Do not update output/telemetry state to off before write confirmation; track unconfirmed stops and wait for hardware ACK.",
							})
						}
					}
					pendingOptimisticLine = 0
				}
			} else if pendingOptimisticLine > 0 && lineNum-pendingOptimisticLine > 5 {
				pendingOptimisticLine = 0
			}
		}

		// Also check for swallowed write errors
		if loc := swallowedWriteErrorRe.FindStringIndex(scanText); loc != nil {
			lineNum := startLine + strings.Count(scanText[:loc[0]], "\n")
			if block.addedLines[lineNum] || r.workingTree {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "optimistic-actuation-safety",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Hardware command write swallows transport exceptions without propagating failure to callers",
						Remediation: "Return a boolean success result or rethrow write exceptions so callers know when actuation fails.",
					})
				}
			}
		}
	}

	return findings
}
