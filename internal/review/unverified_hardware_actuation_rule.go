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
)

func (r UnverifiedHardwareActuationRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func stripLineComment(line string) string {
	if idx := strings.Index(line, "//"); idx != -1 {
		return line[:idx]
	}
	return line
}

func isAckGuardHeader(header string) bool {
	if !strings.HasPrefix(header, "if") && !strings.Contains(header, "if (") &&
		!strings.Contains(header, "if(") && !strings.Contains(header, "onack") &&
		!strings.Contains(header, "onstopack") {
		return false
	}
	if strings.Contains(header, "else") {
		return false
	}
	if strings.Contains(header, "send") && !strings.Contains(header, ".issuccess") &&
		!strings.Contains(header, ".isack") {
		return false
	}

	return strings.Contains(header, ".issuccess") ||
		strings.Contains(header, ".success") ||
		strings.Contains(header, ".isack") ||
		strings.Contains(header, "ack == true") ||
		strings.Contains(header, "ack != null") ||
		strings.Contains(header, "ack != nil") ||
		strings.Contains(header, "ack.ok") ||
		strings.Contains(header, "packettype.ack") ||
		strings.Contains(header, "is stopack") ||
		strings.Contains(header, "is ack") ||
		strings.Contains(header, "ackstatus.success") ||
		strings.Contains(header, "ackstatus.confirmed") ||
		strings.Contains(header, "onack") ||
		strings.Contains(header, "onstopack")
}

func isGuardedByAck(lines []string, index int) bool {
	depth := 0
	for k := index - 1; k >= 0 && index-k <= 40; k-- {
		line := stripLineComment(lines[k])
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		for c := len(trimmed) - 1; c >= 0; c-- {
			if trimmed[c] == '}' {
				depth++
			} else if trimmed[c] == '{' {
				if depth > 0 {
					depth--
				} else {
					header := trimmed
					for h := k - 1; h >= 0 && k-h <= 3; h-- {
						prev := strings.TrimSpace(stripLineComment(lines[h]))
						if strings.HasSuffix(prev, ";") || strings.HasSuffix(prev, "}") {
							break
						}
						header = prev + " " + header
					}

					lowerHeader := strings.ToLower(header)
					return isAckGuardHeader(lowerHeader)
				}
			}
		}

		if depth == 0 && (strings.HasPrefix(trimmed, "case ") || strings.HasPrefix(trimmed, "case:")) {
			lowerCase := strings.ToLower(trimmed)
			if strings.Contains(lowerCase, "ack") || strings.Contains(lowerCase, "pong") {
				return true
			}
		}
	}
	return false
}

func isHardwareActuationCommand(line string) bool {
	clean := stripLineComment(line)
	return strings.Contains(clean, "LED:ON") ||
		strings.Contains(clean, "LED:OFF") ||
		strings.Contains(clean, "PIN:HIGH") ||
		strings.Contains(clean, "PIN:LOW") ||
		strings.Contains(clean, "ACTUATE") ||
		strings.Contains(clean, "RELAY") ||
		strings.Contains(clean, "setPin") ||
		strings.Contains(clean, "writeCommand")
}

func checkUnverifiedOutputControl(
	lines []string,
	index int,
	startLine int,
) (matched bool, guardLine int, actionLine int) {
	line := lines[index]
	if !strings.Contains(line, "onPressed:") || !strings.Contains(line, "isConnected") {
		return false, 0, 0
	}

	guardLine = startLine + index

	var conditionBuilder strings.Builder
	qIndex := -1
	qLineOffset := 0

	for k := 0; k <= 5 && index+k < len(lines); k++ {
		cur := lines[index+k]
		if qPos := strings.Index(cur, "?"); qPos != -1 {
			conditionBuilder.WriteString(" ")
			conditionBuilder.WriteString(cur[:qPos])
			qIndex = qPos
			qLineOffset = k
			break
		}
		conditionBuilder.WriteString(" ")
		conditionBuilder.WriteString(cur)
	}

	if qIndex == -1 {
		return false, 0, 0
	}

	fullCondition := strings.ToLower(conditionBuilder.String())
	if strings.Contains(fullCondition, "protocol") || strings.Contains(fullCondition, "verified") ||
		strings.Contains(fullCondition, "handshake") || strings.Contains(fullCondition, "authorized") ||
		strings.Contains(fullCondition, "ready") {
		return false, 0, 0
	}

	callbackStartLine := index + qLineOffset
	afterQ := lines[callbackStartLine][qIndex+1:]

	trimmedAfterQ := strings.TrimSpace(afterQ)
	if !strings.Contains(trimmedAfterQ, "{") && !strings.Contains(trimmedAfterQ, "=>") {
		return false, 0, 0
	}

	braceDepth := 0
	inBlock := false

	for k := qLineOffset; k <= 15 && index+k < len(lines); k++ {
		curLine := lines[index+k]
		lineScan := curLine
		if k == qLineOffset {
			lineScan = afterQ
		}

		for c := 0; c < len(lineScan); c++ {
			if lineScan[c] == '{' {
				braceDepth++
				inBlock = true
			} else if lineScan[c] == '}' {
				braceDepth--
			}
		}

		if isHardwareActuationCommand(curLine) {
			actionLine = startLine + index + k
			return true, guardLine, actionLine
		}

		if inBlock && braceDepth <= 0 {
			break
		}

		trimmed := strings.TrimSpace(curLine)
		if !inBlock && (strings.Contains(lineScan, " :") || strings.HasSuffix(trimmed, ",")) {
			break
		}
	}

	return false, 0, 0
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

			if stopAssumedConfirmedRe.MatchString(trimmed) && !isGuardedByAck(lines, i) {
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

			matched, guardLine, actionLine := checkUnverifiedOutputControl(lines, i, startLine)
			if matched {
				reportLine := guardLine
				if block.addedLines[actionLine] && !block.addedLines[guardLine] {
					reportLine = actionLine
				}
				if block.addedLines[guardLine] || block.addedLines[actionLine] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(reportLine) + ":control"
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:     "unverified-hardware-actuation",
							Severity: "high",
							File:     block.file,
							Line:     reportLine,
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
