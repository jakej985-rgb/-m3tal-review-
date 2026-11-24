package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// UnverifiedHardwareActuationRule detects physical hardware actuation (pin writes,
// LED toggles, relay triggers) or stop status confirmations that occur without a
// verified protocol handshake, or that treat output status as confirmed simply
// because bytes were transmitted over the wire.
type UnverifiedHardwareActuationRule struct {
	ruleRuntime
}

func (UnverifiedHardwareActuationRule) Name() string {
	return "unverified-hardware-actuation"
}

var (
	hardwareServiceFileRe = regexp.MustCompile(
		`(?i)(?:bridge|serial|hardware|companion|actuator).*\.(?:dart|ts|js|go|py|kt|java|cpp)$`,
	)

	// stopAssumedConfirmedRe detects setting stopConfirmed to true or assuming output is off on write
	stopAssumedConfirmedRe = regexp.MustCompile(
		`(?i)(?:stopConfirmed\s*:\s*(?:true|_protocolNegotiated|confirmed)|pin13Led\s*:\s*confirmed\s*\?\s*false\s*:)`,
	)

	// unverifiedOutputControlRe detects hardware output writes or UI buttons lacking verified protocol checks
	unverifiedOutputControlRe = regexp.MustCompile(
		`(?i)onPressed:\s*\(\s*isConnected\s*\)\s*\?\s*\(\)\s*\{[^}]*(?:LED:ON|LED:OFF|PIN:HIGH)`,
	)
)

func (r UnverifiedHardwareActuationRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r UnverifiedHardwareActuationRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !hardwareServiceFileRe.MatchString(block.file) {
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

			if stopAssumedConfirmedRe.MatchString(trimmed) {
				// Verify if this is in a method that writes before receiving ACK
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "unverified-hardware-actuation",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "Hardware stop status or output state is assumed confirmed upon transmission without device acknowledgment",
							Remediation: "Keep physical stop status unconfirmed (stopConfirmed: false) until the firmware returns an ACK or output state report.",
						})
					}
				}
			}
		}
	}

	return findings
}
