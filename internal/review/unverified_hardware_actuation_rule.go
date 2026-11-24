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

	negativeAckPredRe = regexp.MustCompile(
		`(?i)(?:!\s*(?:[a-zA-Z0-9_]+\.)?(?:issuccess|success|isack|ok)\b|` +
			`\b(?:[a-zA-Z0-9_]+\.)?(?:issuccess|success|isack|ok)\s*(?:==\s*false|!=\s*true)|` +
			`^!\s*(?:ack|reply|packet|stopack)\b|` +
			`\b(?:ack|reply|packet|stopack)\s*(?:==\s*false|!=\s*true|==\s*null|==\s*nil)\b|` +
			`\bis!\s+(?:ack|stopack)\b|` +
			`!=\s*(?:packettype\.(?:ack|pong|stopack)|ackstatus\.(?:success|confirmed)|['"](?:ack|pong)['"]|stopack|ack)\b)`,
	)

	affirmativeAckPredRe = regexp.MustCompile(
		`(?i)(?:\b(?:[a-zA-Z0-9_]+\.)?(?:issuccess|success|isack)\b|` +
			`\b(?:ack|reply|packet|stopack)\s*(?:==\s*true|!=\s*false|!=\s*null|!=\s*nil)\b|` +
			`^(?:ack|reply|stopack)$|` +
			`\bis\s+(?:ack|stopack)\b|` +
			`==\s*(?:packettype\.(?:ack|pong|stopack)|ackstatus\.(?:success|confirmed)|['"](?:ack|pong)['"]|stopack)\b|` +
			`\b(?:packettype\.ack|packettype\.pong|ackstatus\.success|ackstatus\.confirmed)\b|` +
			`\b(?:ack:|pong:|pin13:low|led:0|firstmatch)\b)`,
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

func adjustTopLevelDepth(ch byte, depth *int) {
	switch ch {
	case '(', '[', '{':
		*depth = *depth + 1
	case ')', ']', '}':
		if *depth > 0 {
			*depth = *depth - 1
		}
	}
}

func isQuoteByte(ch byte) bool {
	return ch == '"' || ch == '\'' || ch == '`'
}

func splitTopLevel(s string, op string) []string {
	var parts []string
	parenDepth := 0
	inString := false
	var stringChar byte
	start := 0
	opLen := len(op)

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inString {
			if ch == '\\' {
				i = i + 1
			} else if ch == stringChar {
				inString = false
			}
			continue
		}
		if isQuoteByte(ch) {
			inString = true
			stringChar = ch
			continue
		}
		adjustTopLevelDepth(ch, &parenDepth)
		if parenDepth == 0 && i+opLen <= len(s) && s[i:i+opLen] == op {
			parts = append(parts, s[start:i])
			start = i + opLen
			i = start - 1
		}
	}
	if start > 0 {
		parts = append(parts, s[start:])
		return parts
	}
	return nil
}

func guaranteesAffirmativeAck(cond string) bool {
	cond = unwrapOuterParens(strings.TrimSpace(cond))
	if branches := splitTopLevel(cond, "||"); len(branches) > 0 {
		for _, b := range branches {
			if !guaranteesAffirmativeAck(b) {
				return false
			}
		}
		return true
	}
	if terms := splitTopLevel(cond, "&&"); len(terms) > 0 {
		hasAffirmative := false
		for _, t := range terms {
			trimmed := strings.TrimSpace(t)
			if negativeAckPredRe.MatchString(trimmed) {
				return false
			}
			if affirmativeAckPredRe.MatchString(trimmed) {
				hasAffirmative = true
			}
		}
		return hasAffirmative
	}
	leaf := strings.TrimSpace(cond)
	if negativeAckPredRe.MatchString(leaf) {
		return false
	}
	return affirmativeAckPredRe.MatchString(leaf)
}

func isAckGuardHeader(header string) bool {
	if !strings.HasPrefix(header, "if") && !strings.Contains(header, "if (") &&
		!strings.Contains(header, "if(") && !strings.Contains(header, "onack") &&
		!strings.Contains(header, "onstopack") {
		return false
	}
	if strings.Contains(header, "onack") || strings.Contains(header, "onstopack") {
		return true
	}
	if strings.Contains(header, "else") {
		idx := strings.Index(header, "else if")
		if idx != -1 {
			header = strings.TrimSpace(header[idx+4:])
		} else {
			return false
		}
	}
	if strings.Contains(header, "send") && !strings.Contains(header, ".issuccess") &&
		!strings.Contains(header, ".isack") {
		return false
	}

	cond := header
	if openParen := strings.Index(header, "("); openParen != -1 {
		if closeParen := strings.LastIndex(header, ")"); closeParen > openParen {
			cond = header[openParen+1 : closeParen]
		}
	} else if strings.HasPrefix(header, "if ") {
		cond = strings.TrimPrefix(header, "if ")
	}
	return guaranteesAffirmativeAck(cond)
}

func isAckSwitchCaseLabel(lowerCase string) bool {
	return (strings.Contains(lowerCase, "packettype.ack") ||
		strings.Contains(lowerCase, "packettype.pong") ||
		strings.Contains(lowerCase, "ackstatus.success") ||
		strings.Contains(lowerCase, "ackstatus.confirmed") ||
		strings.Contains(lowerCase, "case 'ack':") ||
		strings.Contains(lowerCase, "case \"ack\":") ||
		strings.Contains(lowerCase, "case 'pong':") ||
		strings.Contains(lowerCase, "case \"pong\":")) &&
		!strings.Contains(lowerCase, "error") &&
		!strings.Contains(lowerCase, "fail") &&
		!strings.Contains(lowerCase, "timeout")
}

func collectOpeningBraceHeader(lines []string, k int, trimmed string) string {
	header := trimmed
	for h := k - 1; h >= 0 && k-h <= 10; h-- {
		prev := strings.TrimSpace(stripLineComment(lines[h]))
		if strings.HasSuffix(prev, ";") || strings.HasSuffix(prev, "}") {
			break
		}
		header = prev + " " + header
		if strings.HasPrefix(prev, "if") || strings.Contains(prev, "if (") ||
			strings.Contains(prev, "if(") || strings.HasPrefix(prev, "else") {
			break
		}
	}
	return header
}

func handleEnclosingBrace(lines []string, k int, trimmed string) (isAck bool, stop bool) {
	header := collectOpeningBraceHeader(lines, k, trimmed)
	lowerHeader := strings.ToLower(header)
	if isAckGuardHeader(lowerHeader) {
		return true, false
	}
	if strings.Contains(lowerHeader, "void ") ||
		strings.Contains(lowerHeader, "class ") ||
		strings.Contains(lowerHeader, "=>") ||
		(strings.HasPrefix(lowerHeader, "()") && strings.Contains(lowerHeader, "{")) {
		return false, true
	}
	return false, false
}

func isGuardedByAck(lines []string, index int) bool {
	depth := 0
	inNonAckCase := false

	for k := index - 1; k >= 0 && index-k <= 50; k-- {
		line := stripLineComment(lines[k])
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if depth == 0 && (strings.HasPrefix(trimmed, "case ") || strings.HasPrefix(trimmed, "case:") ||
			strings.HasPrefix(trimmed, "default:")) {
			if !inNonAckCase {
				if isAckSwitchCaseLabel(strings.ToLower(trimmed)) {
					return true
				}
				inNonAckCase = true
			}
			continue
		}

		for c := len(trimmed) - 1; c >= 0; c-- {
			if trimmed[c] == '}' {
				depth++
				continue
			}
			if trimmed[c] != '{' {
				continue
			}
			if depth > 0 {
				depth--
				continue
			}
			inNonAckCase = false
			isAck, stop := handleEnclosingBrace(lines, k, trimmed)
			if isAck {
				return true
			}
			if stop {
				return false
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

func findTernaryQ(line string) int {
	for i := 0; i < len(line); i++ {
		if line[i] == '?' {
			if i > 0 && line[i-1] == '?' {
				continue
			}
			if i+1 < len(line) && (line[i+1] == '.' || line[i+1] == '?') {
				continue
			}
			return i
		}
	}
	return -1
}

func scanLineBraces(lineScan string, braceDepth *int, inBlock *bool) {
	inString := false
	var stringChar byte
	for c := 0; c < len(lineScan); c++ {
		ch := lineScan[c]
		if inString {
			if ch == '\\' {
				c++
				continue
			}
			if ch == stringChar {
				inString = false
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inString = true
			stringChar = ch
			continue
		}
		if ch == '{' {
			*braceDepth++
			*inBlock = true
		} else if ch == '}' {
			*braceDepth--
		}
	}
}

func isVerificationMandatory(cond string) bool {
	cond = unwrapOuterParens(strings.TrimSpace(cond))
	if branches := splitTopLevel(cond, "||"); len(branches) > 0 {
		for _, b := range branches {
			if !isVerificationMandatory(b) {
				return false
			}
		}
		return true
	}
	if terms := splitTopLevel(cond, "&&"); len(terms) > 0 {
		for _, t := range terms {
			if isVerificationMandatory(t) {
				return true
			}
		}
		return false
	}
	leaf := strings.TrimSpace(cond)
	if strings.HasPrefix(leaf, "!") || strings.Contains(leaf, "== false") || strings.Contains(leaf, "!= true") {
		return false
	}
	lower := strings.ToLower(leaf)
	return strings.Contains(lower, "protocol") ||
		strings.Contains(lower, "verified") ||
		strings.Contains(lower, "handshake") ||
		strings.Contains(lower, "authorized") ||
		strings.Contains(lower, "ready")
}

func checkUnverifiedOutputControl(
	lines []string,
	index int,
	startLine int,
) (matched bool, guardLine int, actionLines []int) {
	line := stripLineComment(lines[index])
	if !strings.Contains(line, "onPressed:") || !strings.Contains(line, "isConnected") {
		return false, 0, nil
	}

	guardLine = startLine + index

	var conditionBuilder strings.Builder
	qIndex := -1
	qLineOffset := 0

	for k := 0; k <= 5 && index+k < len(lines); k++ {
		cur := stripLineComment(lines[index+k])
		if qPos := findTernaryQ(cur); qPos != -1 {
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
		return false, 0, nil
	}

	condStr := conditionBuilder.String()
	if colonIdx := strings.Index(condStr, "onPressed:"); colonIdx != -1 {
		condStr = condStr[colonIdx+len("onPressed:"):]
	}

	if isVerificationMandatory(condStr) {
		return false, 0, nil
	}

	callbackStartLine := index + qLineOffset
	afterQ := lines[callbackStartLine][qIndex+1:]

	trimmedAfterQ := strings.TrimSpace(stripLineComment(afterQ))
	if !strings.Contains(trimmedAfterQ, "{") && !strings.Contains(trimmedAfterQ, "=>") {
		return false, 0, nil
	}

	braceDepth := 0
	inBlock := false

	for k := qLineOffset; k <= 20 && index+k < len(lines); k++ {
		curLine := stripLineComment(lines[index+k])
		lineScan := curLine
		if k == qLineOffset {
			lineScan = afterQ
		}

		scanLineBraces(lineScan, &braceDepth, &inBlock)

		if isHardwareActuationCommand(curLine) {
			actionLines = append(actionLines, startLine+index+k)
		}

		if inBlock && braceDepth <= 0 {
			break
		}

		trimmed := strings.TrimSpace(curLine)
		if !inBlock && (strings.Contains(lineScan, " :") || strings.HasSuffix(trimmed, ",")) {
			break
		}
	}

	if len(actionLines) > 0 {
		return true, guardLine, actionLines
	}

	return false, 0, nil
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

			matched, guardLine, actionLines := checkUnverifiedOutputControl(lines, i, startLine)
			if matched {
				r.reportUnverifiedControl(block, guardLine, actionLines, seen, &findings)
			}
		}
	}

	return findings
}

func (r UnverifiedHardwareActuationRule) reportUnverifiedControl(
	block diffSourceBlock,
	guardLine int,
	actionLines []int,
	seen map[string]bool,
	findings *[]Finding,
) {
	actionLine := actionLines[0]
	for _, aLine := range actionLines {
		if block.addedLines[aLine] {
			actionLine = aLine
			break
		}
	}
	reportLine := guardLine
	if block.addedLines[actionLine] && !block.addedLines[guardLine] {
		reportLine = actionLine
	}
	if block.addedLines[guardLine] || block.addedLines[actionLine] || r.workingTree {
		key := block.file + ":" + strconv.Itoa(reportLine) + ":control"
		if !seen[key] {
			seen[key] = true
			*findings = append(*findings, Finding{
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
