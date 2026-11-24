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
	hardwareExcludePattern = regexp.MustCompile(
		`(?i)(?:_test\.[a-z0-9]+|(?:^|/)(?:tests?|testdata|fixtures?)/|(?:^|/)internal/review/)`,
	)

	// stopAssumedConfirmedRe detects setting stopConfirmed to true or assuming output is off on write
	stopAssumedConfirmedRe = regexp.MustCompile(
		`(?i)(?:stopConfirmed\s*:\s*(?:true|_protocolNegotiated|confirmed)|pin13Led\s*:\s*confirmed\s*\?\s*false\s*:)`,
	)

	// unverifiedOutputControlRe detects hardware output writes or UI buttons lacking verified protocol checks
	unverifiedOutputControlRe = regexp.MustCompile(
		`(?i)onPressed:\s*\(?\s*isConnected\s*\)?\s*\?\s*(?:\(\s*\)\s*\{|=>)[^}]*` +
			`(?:LED:ON|LED:OFF|PIN:HIGH|PIN:LOW|ACTUATE|RELAY)`,
	)
)

func (r UnverifiedHardwareActuationRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func hasPrecedingAck(lines []string, index int) bool {
	for k := 1; k <= 15 && index-k >= 0; k++ {
		prev := lines[index-k]
		lowerPrev := strings.ToLower(prev)
		if strings.Contains(prev, "ACK:") || strings.Contains(prev, "PONG:") ||
			strings.Contains(prev, "PIN13:LOW") || strings.Contains(prev, "LED:0") ||
			strings.Contains(lowerPrev, "ack.issuccess") || strings.Contains(lowerPrev, "isack") ||
			strings.Contains(lowerPrev, "waitforack") || strings.Contains(lowerPrev, "onack") ||
			strings.Contains(lowerPrev, "ackreceived") || strings.Contains(lowerPrev, "sendstopcommand") ||
			strings.Contains(lowerPrev, "ack = await") || strings.Contains(lowerPrev, "ack :=") ||
			strings.Contains(lowerPrev, "if (ack") || strings.Contains(lowerPrev, "if ack") ||
			strings.Contains(lowerPrev, "ack != nil") || strings.Contains(lowerPrev, "ack != null") ||
			strings.Contains(lowerPrev, "ack.ok") || strings.Contains(lowerPrev, "ack == true") ||
			strings.Contains(lowerPrev, "responsestatus.ack") || strings.Contains(lowerPrev, "ackstatus") ||
			strings.Contains(lowerPrev, ".issuccess") || strings.Contains(lowerPrev, ".success") ||
			strings.Contains(lowerPrev, "_updatetelemetry") || strings.Contains(lowerPrev, "parsetelemetry") ||
			strings.Contains(lowerPrev, "firstmatch(line)") || strings.Contains(lowerPrev, "firstmatch") {
			return true
		}
	}
	return false
}

func checkUnverifiedOutputControl(lines []string, index int) bool {
	line := lines[index]
	if !strings.Contains(line, "onPressed:") || !strings.Contains(line, "isConnected") {
		return false
	}
	lower := strings.ToLower(line)
	if strings.Contains(lower, "protocol") || strings.Contains(lower, "verified") ||
		strings.Contains(lower, "handshake") || strings.Contains(lower, "authorized") ||
		strings.Contains(lower, "ready") {
		return false
	}
	for k := 0; k <= 10 && index+k < len(lines); k++ {
		fw := lines[index+k]
		if strings.Contains(fw, "LED:ON") || strings.Contains(fw, "LED:OFF") ||
			strings.Contains(fw, "PIN:HIGH") || strings.Contains(fw, "PIN:LOW") ||
			strings.Contains(fw, "ACTUATE") || strings.Contains(fw, "RELAY") ||
			strings.Contains(fw, "setPin") || strings.Contains(fw, "writeCommand") {
			return true
		}
		if k > 0 && (strings.Contains(fw, "},") || strings.Contains(fw, "});") || strings.Contains(fw, "};")) {
			break
		}
	}
	return false
}

func (r UnverifiedHardwareActuationRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !hardwareServiceFileRe.MatchString(block.file) || hardwareExcludePattern.MatchString(block.file) {
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

			if stopAssumedConfirmedRe.MatchString(trimmed) && !hasPrecedingAck(lines, i) {
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum) + ":stop"
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:     "unverified-hardware-actuation",
							Severity: "high",
							File:     block.file,
							Line:     lineNum,
							Message: "Hardware stop status or output state is assumed confirmed upon transmission " +
								"without device acknowledgment",
							Remediation: "Keep physical stop status unconfirmed (stopConfirmed: false) until " +
								"the firmware returns an ACK or output state report.",
						})
					}
				}
			}

			if unverifiedOutputControlRe.MatchString(trimmed) || checkUnverifiedOutputControl(lines, i) {
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum) + ":control"
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:     "unverified-hardware-actuation",
							Severity: "high",
							File:     block.file,
							Line:     lineNum,
							Message: "Hardware output control is gated only on transport connection status " +
								"without protocol verification",
							Remediation: "Gate hardware controls on verified protocol state " +
								"(e.g. isConnected && isProtocolVerified) to prevent actuation before protocol negotiation.",
						})
					}
				}
			}
		}
	}

	return findings
}
