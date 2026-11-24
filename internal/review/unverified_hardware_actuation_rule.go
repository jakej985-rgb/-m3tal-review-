package review

import (
	"context"
	"regexp"
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
			`\b(?:ack|stopack)(?:\.|\?\.)ok(?:\s*==\s*true)?\b|` +
			`\b(?:ack|reply|packet|stopack)\s*(?:==\s*true|!=\s*null|!=\s*nil)\b|` +
			`^(?:ack|reply|stopack)$|` +
			`\bis\s+(?:ack|stopack)\b|` +
			`==\s*(?:packettype\.(?:ack|pong|stopack)|ackstatus\.(?:success|confirmed)|['"](?:ack|pong)['"]|stopack)\b|` +
			`\b(?:packettype\.ack|packettype\.pong|ackstatus\.success|ackstatus\.confirmed)\b|` +
			`\b(?:ack:|pong:|pin13:low|led:0|firstmatch)\b)`,
	)

	goAffirmativeAckPredRe = regexp.MustCompile(
		`(?i)\b(?:ack|reply|packet|stopack)\s*!=\s*false\b`,
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
		decrementDepth(depth)
	}
}

func splitTopLevel(s string, op string) []string {
	var parts []string
	parenDepth := 0
	inString := false
	var stringChar byte
	start := 0
	opLen := len(op)

	for i := 0; i < len(s); i++ {
		if nextI, ok := scanStringLiteral(s, i, &inString, &stringChar); ok {
			i = nextI
			continue
		}
		adjustTopLevelDepth(s[i], &parenDepth)
		if parenDepth == 0 && i+opLen <= len(s) && s[i:i+opLen] == op {
			parts = append(parts, s[start:i])
			start = i + opLen
			i = start - 1
		}
	}
	if start == 0 {
		return nil
	}
	return append(parts, s[start:])
}

func guaranteesAffirmativeAck(cond string, isGo bool) bool {
	cond = unwrapOuterParens(strings.TrimSpace(cond))
	if strings.HasPrefix(cond, "!") {
		inner := unwrapOuterParens(strings.TrimSpace(cond[1:]))
		if negativeAckPredRe.MatchString(inner) ||
			affirmativeAckPredRe.MatchString(inner) ||
			guaranteesAffirmativeAck(inner, isGo) {
			return false
		}
	}
	if branches := splitTopLevel(cond, "||"); len(branches) > 0 {
		for _, b := range branches {
			if !guaranteesAffirmativeAck(b, isGo) {
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
			if guaranteesAffirmativeAck(trimmed, isGo) {
				hasAffirmative = true
			}
		}
		return hasAffirmative
	}
	leaf := strings.TrimSpace(cond)
	if negativeAckPredRe.MatchString(leaf) {
		return false
	}
	if affirmativeAckPredRe.MatchString(leaf) {
		return true
	}
	return isGo && goAffirmativeAckPredRe.MatchString(leaf)
}

func isVarChecked(cond string, varName string) (bool, bool) {
	varLen := len(varName)
	for i := 0; i+varLen <= len(cond); i++ {
		if cond[i:i+varLen] != varName {
			continue
		}
		if i > 0 && isIdentOrDot(cond[i-1]) {
			continue
		}
		if i+varLen < len(cond) && isIdentOrDot(cond[i+varLen]) {
			continue
		}
		prefix := strings.TrimRight(cond[:i], " \t")
		if strings.HasSuffix(prefix, "!") {
			return false, true
		}
		rest := strings.TrimLeft(cond[i+varLen:], " \t")
		if strings.HasPrefix(rest, "== false") || strings.HasPrefix(rest, "==false") ||
			strings.HasPrefix(rest, "!= true") || strings.HasPrefix(rest, "!=true") {
			return false, true
		}
		if strings.HasPrefix(rest, "== true") || strings.HasPrefix(rest, "==true") ||
			strings.HasPrefix(rest, "!= false") || strings.HasPrefix(rest, "!=false") {
			return true, false
		}
		return true, false
	}
	return false, false
}

func extractGoAssignStmt(stmt string) (string, string, bool) {
	if idx := strings.Index(stmt, ":="); idx != -1 {
		return strings.TrimSpace(stmt[:idx]), strings.TrimSpace(stmt[idx+2:]), true
	}
	for i := 0; i < len(stmt); i++ {
		if stmt[i] == '=' {
			if i > 0 && (stmt[i-1] == '=' || stmt[i-1] == '!' || stmt[i-1] == '<' ||
				stmt[i-1] == '>' || stmt[i-1] == ':') {
				continue
			}
			if i+1 < len(stmt) && stmt[i+1] == '=' {
				i++
				continue
			}
			return strings.TrimSpace(stmt[:i]), strings.TrimSpace(stmt[i+1:]), true
		}
	}
	return "", "", false
}

func checkGoInitializer(cond string, isGo bool) (bool, bool) {
	semiParts := splitTopLevel(cond, ";")
	if len(semiParts) <= 1 {
		return false, false
	}
	initStmt := strings.TrimSpace(semiParts[0])
	controllingCond := strings.TrimSpace(semiParts[len(semiParts)-1])
	if varName, expr, ok := extractGoAssignStmt(initStmt); ok {
		if guaranteesAffirmativeAck(expr, isGo) {
			isPos, isNeg := isVarChecked(controllingCond, varName)
			if isNeg {
				return true, false
			}
			if isPos {
				return true, true
			}
		}
	}
	return true, guaranteesAffirmativeAck(controllingCond, isGo)
}

func isAckGuardHeader(header string, isGo bool) bool {
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
	if idx := strings.Index(header, "if "); idx != -1 {
		cond = header[idx+2:]
	} else if idx := strings.Index(header, "if("); idx != -1 {
		cond = header[idx+2:]
	}
	cond = strings.TrimSpace(cond)
	cond = strings.TrimSuffix(cond, "{")
	cond = unwrapOuterParens(strings.TrimSpace(cond))
	if hasInit, ok := checkGoInitializer(cond, isGo); hasInit {
		return ok
	}
	return guaranteesAffirmativeAck(cond, isGo)
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

func isCaseLabel(s string) bool {
	return strings.HasPrefix(s, "case ") || strings.HasPrefix(s, "case:") || strings.HasPrefix(s, "default:")
}

func checkCaseAck(trimmed string, inNonAckCase *bool) bool {
	if *inNonAckCase {
		return false
	}
	if isAckSwitchCaseLabel(strings.ToLower(trimmed)) {
		return true
	}
	*inNonAckCase = true
	return false
}

func handleEnclosingBrace(lines []string, k int, trimmed string, isGo bool) (bool, bool) {
	header := collectOpeningBraceHeader(lines, k, trimmed)
	lowerHeader := strings.ToLower(header)
	if isAckGuardHeader(lowerHeader, isGo) {
		return true, false
	}
	stop := strings.Contains(lowerHeader, "void ") ||
		strings.Contains(lowerHeader, "class ") ||
		strings.Contains(lowerHeader, "=>") ||
		(strings.HasPrefix(lowerHeader, "()") && strings.Contains(lowerHeader, "{"))
	return false, stop
}

func scanLineForAckBrace(
	lines []string,
	k int,
	trimmed string,
	depth *int,
	inNonAckCase *bool,
	isGo bool,
) (foundAck bool, stopScan bool) {
	for c := len(trimmed) - 1; c >= 0; c-- {
		if trimmed[c] == '}' {
			*depth = *depth + 1
		} else if trimmed[c] == '{' {
			if decrementDepth(depth) {
				continue
			}
			*inNonAckCase = false
			if a, s := handleEnclosingBrace(lines, k, trimmed, isGo); a || s {
				return a, s
			}
		}
	}
	return foundAck, stopScan
}

func isGuardedByAck(lines []string, index int, isGo bool) bool {
	depth := 0
	inNonAckCase := false
	guarded := false

	for k := index - 1; k >= 0 && index-k <= 50; k-- {
		line := stripLineComment(lines[k])
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if depth == 0 && isCaseLabel(trimmed) {
			if checkCaseAck(trimmed, &inNonAckCase) {
				return true
			}
			continue
		}

		if isAck, stop := scanLineForAckBrace(lines, k, trimmed, &depth, &inNonAckCase, isGo); isAck || stop {
			guarded = isAck
			break
		}
	}
	return guarded
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
	pos := -1
	for i := 0; i < len(line); i++ {
		if line[i] == '?' {
			if i > 0 && line[i-1] == '?' {
				continue
			}
			if i+1 < len(line) && (line[i+1] == '.' || line[i+1] == '?') {
				continue
			}
			pos = i
			break
		}
	}
	return pos
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
		allValid := true
		for _, b := range branches {
			if !isVerificationMandatory(b) {
				allValid = false
				break
			}
		}
		return allValid
	}
	if terms := splitTopLevel(cond, "&&"); len(terms) > 0 {
		anyValid := false
		for _, t := range terms {
			if isVerificationMandatory(t) {
				anyValid = true
				break
			}
		}
		return anyValid
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

func extractTernaryCondition(lines []string, index int) (string, int, int, bool) {
	var conditionBuilder strings.Builder
	for k := 0; k <= 5 && index+k < len(lines); k++ {
		cur := stripLineComment(lines[index+k])
		if qPos := findTernaryQ(cur); qPos != -1 {
			conditionBuilder.WriteString(" ")
			conditionBuilder.WriteString(cur[:qPos])
			return conditionBuilder.String(), k, qPos, true
		}
		conditionBuilder.WriteString(" ")
		conditionBuilder.WriteString(cur)
	}
	return "", 0, 0, false
}

func collectActionLines(
	lines []string,
	index, startLine, qLineOffset int,
	afterQ string,
) []int {
	var actionLines []int
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
	return actionLines
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
	condStr, qLineOffset, qIndex, ok := extractTernaryCondition(lines, index)
	if !ok {
		return false, 0, nil
	}

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

	actionLines = collectActionLines(lines, index, startLine, qLineOffset, afterQ)
	if len(actionLines) > 0 {
		return true, guardLine, actionLines
	}
	return false, 0, nil
}

func (r UnverifiedHardwareActuationRule) checkHardwareBlock(
	b diffSourceBlock, text string, start int, seen map[string]bool,
) []Finding {
	var hardwareFindings []Finding
	lines := strings.Split(text, "\n")
	isGo := strings.HasSuffix(b.file, ".go")
	for i, line := range lines {
		lineNum := start + i
		trimmedLine := strings.TrimSpace(line)
		if isCommentPrefix(trimmedLine) {
			continue
		}
		if stopAssumedConfirmedRe.MatchString(trimmedLine) && !isGuardedByAck(lines, i, isGo) {
			if (b.addedLines[lineNum] || r.workingTree) && !dedupeFinding(seen, b.file+":stop", lineNum) {
				hardwareFindings = append(hardwareFindings, Finding{
					Rule:     "unverified-hardware-actuation",
					Severity: "high",
					File:     b.file,
					Line:     lineNum,
					Message: "Hardware stop status or output state is assumed confirmed upon transmission " +
						"without device acknowledgment",
					Remediation: "Keep physical stop status unconfirmed (stopConfirmed: false) until " +
						"the firmware returns an ACK or output state report.",
				})
			}
		}

		if matched, guardLine, actionLines := checkUnverifiedOutputControl(lines, i, start); matched {
			r.reportUnverifiedControl(b, guardLine, actionLines, seen, &hardwareFindings)
		}
	}
	return hardwareFindings
}

func (r UnverifiedHardwareActuationRule) CheckContext(ctx context.Context, diff string) []Finding {
	return executeBlockRule(ctx, diff, r.repositoryRoot, r.workingTree, func(f string) bool {
		return hardwareServiceFileRe.MatchString(f) && !hardwareExcludePattern.MatchString(f)
	}, r.checkHardwareBlock)
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
	if (block.addedLines[guardLine] || block.addedLines[actionLine] || r.workingTree) &&
		!dedupeFinding(seen, block.file+":control", reportLine) {
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
