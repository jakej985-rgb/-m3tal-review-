package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// HardwareDisconnectRule detects hardware/serial driver disconnect implementations
// that close ports or transport connections without first requesting and verifying
// a safe state (or transmitting an explicit stop command) on the physical peripheral.
// When powered boards remain connected via USB, closing the link without a wire stop
// command leaves actuators (motors, relays, lasers, LEDs) continuously energized.
type HardwareDisconnectRule struct {
	ruleRuntime
}

func (HardwareDisconnectRule) Name() string { return "hardware-disconnect-safe-state" }

var (
	hardwareDriverFileRe = regexp.MustCompile(`(?i)(?:bridge|serial|hardware|driver|peripheral|transport).*\.(?:dart|ts|js|go|py|kt|java|cpp)$`)

	// disconnectMethodRe matches disconnect/close method declarations
	disconnectMethodRe = regexp.MustCompile(`(?i)(?:Future<\w+>\s+|async\s+)?(?:disconnect|closeConnection|closePort|terminateLink)\s*\([^)]*\)\s*(?:async\s*)?\{`)

	// portCloseCallRe matches closing the connection handle
	portCloseCallRe = regexp.MustCompile(`(?i)(?:_closeConnection|_closePort|connection\.close|port\.close|_transport\.close|_transport\.disconnect)\s*\(`)

	// wireStopCommandRe matches transmitting stop or safe-state commands across the wire
	wireStopCommandRe = regexp.MustCompile(`(?i)(?:writeLine|write|_write|sendCommand|transmit|send)\s*\(\s*(?:['"](?:SAFE_STATE|EMERGENCY_STOP|STOP|HALT)['"]|safeCommand|stopCommand)`)

	// localSafeStateOnlyRe detects calling local safety interlock without wire transmission
	localSafeStateOnlyRe = regexp.MustCompile(`(?i)(?:_safetyInterlock|interlock|safetyTracker)\s*\.\s*(?:enterSafeState|setSafeState|resetLimiter)\s*\(`)
)

func (r HardwareDisconnectRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r HardwareDisconnectRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !hardwareDriverFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		lines := strings.Split(scanText, "\n")
		inDisconnect := false
		disconnectStartLine := 0
		hasPortClose := false
		hasWireStop := false
		hasLocalSafeOnly := false
		braceCount := 0

		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if !inDisconnect {
				if disconnectMethodRe.MatchString(line) {
					inDisconnect = true
					disconnectStartLine = lineNum
					hasPortClose = false
					hasWireStop = false
					hasLocalSafeOnly = false
					braceCount = strings.Count(line, "{") - strings.Count(line, "}")
				}
				continue
			}

			braceCount += strings.Count(line, "{") - strings.Count(line, "}")

			if portCloseCallRe.MatchString(trimmed) {
				hasPortClose = true
			}
			if wireStopCommandRe.MatchString(trimmed) {
				hasWireStop = true
			}
			if localSafeStateOnlyRe.MatchString(trimmed) {
				hasLocalSafeOnly = true
			}

			// End of disconnect method
			if braceCount <= 0 {
				if hasPortClose && (!hasWireStop || hasLocalSafeOnly && !hasWireStop) {
					if block.addedLines[disconnectStartLine] || r.workingTree {
						key := block.file + ":" + strconv.Itoa(disconnectStartLine)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "hardware-disconnect-safe-state",
								Severity:    "high",
								File:        block.file,
								Line:        disconnectStartLine,
								Message:     "Hardware disconnect closes connection without transmitting a safe-state or stop command to the peripheral",
								Remediation: "Transmit and verify a safe-state/emergency-stop command over the wire before closing the physical connection handle.",
							})
						}
					}
				}
				inDisconnect = false
			}
		}
	}

	return findings
}
