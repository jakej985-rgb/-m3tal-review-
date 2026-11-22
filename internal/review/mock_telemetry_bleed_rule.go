package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// MockTelemetryBleedRule detects physical hardware drivers and bridges that initialize
// live telemetry state with default simulator fixtures or mock constants (e.g. `const PinTelemetry()`),
// causing unread sensors or sketches with custom output formats to emit fake simulation values
// as live physical readings.
type MockTelemetryBleedRule struct {
	ruleRuntime
}

func (MockTelemetryBleedRule) Name() string { return "mock-telemetry-bleed" }

var (
	physicalDriverFileRe = regexp.MustCompile(`(?i)(?:physical.*bridge|serial.*bridge|hardware.*driver).*\.(?:dart|ts|js|go|py|kt)$`)

	// mockTelemetryInitRe detects initializing physical telemetry with default const model
	mockTelemetryInitRe = regexp.MustCompile(`(?i)(?:PinTelemetry\s+_telemetry\s*=\s*const\s+PinTelemetry\s*\(\s*\)|_telemetry\s*=\s*(?:const\s+)?(?:PinTelemetry|TelemetryData|SensorTelemetry)\s*\(\s*\))`)

	// explicitPhysicalInitRe detects explicit physical telemetry initialization with empty/null readings
	explicitPhysicalInitRe = regexp.MustCompile(`(?i)(?:PinTelemetry\.physicalEmpty|PinTelemetry\.disconnected|PinTelemetry\.unavailable|a0Voltage:\s*null)`)
)

func (r MockTelemetryBleedRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r MockTelemetryBleedRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !physicalDriverFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// If the file explicitly uses physicalEmpty or unavailable telemetry, skip
		if explicitPhysicalInitRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			if mockTelemetryInitRe.MatchString(trimmed) {
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "mock-telemetry-bleed",
							Severity:    "medium",
							File:        block.file,
							Line:        lineNum,
							Message:     "Physical hardware bridge initializes live telemetry with simulator mock defaults instead of explicit unavailable states",
							Remediation: "Initialize physical bridge telemetry with an explicit empty/unavailable factory (e.g. PinTelemetry.physicalEmpty()) to avoid emitting simulation values as live physical readings.",
						})
					}
				}
			}
		}
	}

	return findings
}
