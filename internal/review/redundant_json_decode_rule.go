package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// RedundantJsonDecodeRule detects routing guards or data transformers that decode the
// same raw JSON string multiple times in the same decision path (e.g. validating
// decodability via tryDecodeList and then immediately re-decoding in a membership check).
// Decoding should be performed once with the parsed model list reused.
type RedundantJsonDecodeRule struct {
	ruleRuntime
}

func (RedundantJsonDecodeRule) Name() string {
	return "redundant-json-decode"
}

var (
	redundantJsonFileRe = regexp.MustCompile(
		`(?i)(?:router|route|guard|navigation|datasource|loader).*\.(?:dart|ts|js|go|py|kt)$`,
	)
	redundantJsonExcludeRe = regexp.MustCompile(
		`(?i)(?:_test\.[a-z0-9]+|(?:^|/)(?:tests?|testdata|fixtures?)/)`,
	)

	// repeatedDecoderCallRe matches calling decoders on an input variable
	repeatedDecoderCallRe = regexp.MustCompile(
		`(?i)\b(tryDecodeList|jsonDecode|json\.decode|deserializeList)\s*\(\s*([a-zA-Z0-9_]+)\s*\)`,
	)

	decodesProfilesRe = regexp.MustCompile(
		`(?i)(?:(?:var|final|const|[A-Za-z0-9_<>]+)\s+([a-zA-Z0-9_]+)\s*=\s*)?_decodesProfiles\s*\(\s*([a-zA-Z0-9_]+)\s*\)`,
	)
	containsProfileRe = regexp.MustCompile(
		`(?i)_containsLoadableProfile\s*\(\s*([a-zA-Z0-9_]+)\s*[,)]`,
	)
)

func (r RedundantJsonDecodeRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

type ternaryPair struct {
	qPos     int
	colonPos int
	depth    int
}

func parseTernaryPairs(line string) []ternaryPair {
	var pairs []ternaryPair
	pendingQ := make(map[int][]int)
	inString := false
	var stringChar byte
	depth := 0

	for i := 0; i < len(line); i++ {
		ch := line[i]
		if inString {
			if ch == '\\' {
				i++
				continue
			}
			if ch == stringChar {
				inString = false
			}
			continue
		}
		if ch == '"' || ch == '\'' || ch == '`' {
			inString = true
			stringChar = ch
			continue
		}

		if ch == '(' || ch == '[' || ch == '{' {
			depth++
			continue
		}
		if ch == ')' || ch == ']' || ch == '}' {
			delete(pendingQ, depth)
			if depth > 0 {
				depth--
			}
			continue
		}

		if ch == '?' {
			if i+1 < len(line) && (line[i+1] == '?' || line[i+1] == '.') {
				i++
				continue
			}
			if i > 0 && line[i-1] == '?' {
				continue
			}
			pendingQ[depth] = append(pendingQ[depth], i)
			continue
		}

		if ch == ':' {
			if i+1 < len(line) && line[i+1] == ':' {
				i++
				continue
			}
			if i > 0 && line[i-1] == ':' {
				continue
			}
			qs := pendingQ[depth]
			if len(qs) > 0 {
				qPos := qs[len(qs)-1]
				pendingQ[depth] = qs[:len(qs)-1]
				pairs = append(pairs, ternaryPair{
					qPos:     qPos,
					colonPos: i,
					depth:    depth,
				})
			}
		}
	}
	return pairs
}

func isTernaryArms(line string, start1, end1, start2, end2 int) bool {
	pairs := parseTernaryPairs(line)
	for _, p := range pairs {
		if p.qPos < start1 && start1 < p.colonPos && p.colonPos < start2 {
			return true
		}
	}
	return false
}

func hasSameLineDuplicate(trimmed string, indices [][]int) bool {
	for a := 0; a < len(indices); a++ {
		for b := a + 1; b < len(indices); b++ {
			if trimmed[indices[a][4]:indices[a][5]] == trimmed[indices[b][4]:indices[b][5]] &&
				!isTernaryArms(trimmed, indices[a][0], indices[a][1], indices[b][0], indices[b][1]) {
				return true
			}
		}
	}
	return false
}

func pickReportLine(l1, l2 int, added map[int]bool) int {
	if added[l2] {
		return l2
	}
	return l1
}

func areLinesAddedOrWholeScan(block diffSourceBlock, line1, line2 int) bool {
	if len(block.addedLines) > 0 {
		return block.addedLines[line1] || block.addedLines[line2]
	}
	return true
}

func isLineAddedOrWholeScan(block diffSourceBlock, lineNum int) bool {
	if len(block.addedLines) > 0 {
		return block.addedLines[lineNum]
	}
	return true
}

type jsonDecodeContext struct {
	lines     []string
	startLine int
	block     diffSourceBlock
	emit      func(int, string, string)
}

func (r RedundantJsonDecodeRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !redundantJsonFileRe.MatchString(block.file) || redundantJsonExcludeRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		dCtx := jsonDecodeContext{
			lines:     strings.Split(scanText, "\n"),
			startLine: startLine,
			block:     block,
			emit: func(lineNum int, msg string, rem string) {
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "redundant-json-decode",
						Severity:    "medium",
						File:        block.file,
						Line:        lineNum,
						Message:     msg,
						Remediation: rem,
					})
				}
			},
		}

		for i, line := range dCtx.lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			r.checkProfileHelpers(dCtx, i)
			r.checkDecoderCalls(dCtx, i)
		}
	}

	return findings
}

func (r RedundantJsonDecodeRule) checkProfileHelpers(dCtx jsonDecodeContext, i int) {
	trimmed := strings.TrimSpace(dCtx.lines[i])
	dMatches := decodesProfilesRe.FindStringSubmatch(trimmed)
	if len(dMatches) == 0 {
		return
	}
	alias := dMatches[1]
	arg := dMatches[2]
	lineNum := dCtx.startLine + i

	for j := i + 1; j <= min(i+4, len(dCtx.lines)-1); j++ {
		nextTrimmed := strings.TrimSpace(dCtx.lines[j])
		if strings.HasPrefix(nextTrimmed, "//") {
			continue
		}
		cMatches := containsProfileRe.FindStringSubmatch(nextTrimmed)
		if len(cMatches) == 0 {
			if strings.HasPrefix(nextTrimmed, "}") || strings.HasPrefix(nextTrimmed, "return ") {
				break
			}
			continue
		}
		targetArg := cMatches[1]
		if targetArg != arg && (alias == "" || targetArg != alias) {
			break
		}
		lineNum2 := dCtx.startLine + j
		if !areLinesAddedOrWholeScan(dCtx.block, lineNum, lineNum2) {
			break
		}
		dCtx.emit(
			pickReportLine(lineNum, lineNum2, dCtx.block.addedLines),
			"Redundant JSON decoding: payload is decoded for validation and decoded again for lookup",
			"Decode the JSON payload once and inspect the parsed collection directly "+
				"rather than re-parsing in subsequent helpers.",
		)
		break
	}
}

func (r RedundantJsonDecodeRule) checkDecoderCalls(dCtx jsonDecodeContext, i int) {
	trimmed := strings.TrimSpace(dCtx.lines[i])
	indices := repeatedDecoderCallRe.FindAllStringSubmatchIndex(trimmed, -1)
	if len(indices) == 0 {
		return
	}
	lineNum := dCtx.startLine + i

	if len(indices) > 1 && isLineAddedOrWholeScan(dCtx.block, lineNum) && hasSameLineDuplicate(trimmed, indices) {
		dCtx.emit(
			lineNum,
			"Redundant JSON decoding: same variable decoded multiple times in expression",
			"Cache the decoded JSON object in a local variable before inspecting properties.",
		)
		return
	}

	arg := trimmed[indices[0][4]:indices[0][5]]
	maxLookahead := 3
	if remaining := len(dCtx.lines) - 1 - i; remaining < maxLookahead {
		maxLookahead = remaining
	}
	for offset := 1; offset <= maxLookahead; offset++ {
		next := strings.TrimSpace(dCtx.lines[i+offset])
		if strings.HasPrefix(next, "//") {
			continue
		}
		if shouldStopSequentialScan(next, arg) {
			break
		}
		if r.matchNextSequentialDecode(dCtx, next, arg, lineNum, dCtx.startLine+i+offset) {
			break
		}
	}
}

func shouldStopSequentialScan(line string, arg string) bool {
	if strings.HasPrefix(line, "else") || strings.Contains(line, "} else") || strings.HasPrefix(line, "}") {
		return true
	}
	assignPatterns := []string{
		arg + " =",
		arg + " :=",
		arg + " ??=",
		arg + "??=",
		arg + " +=",
		arg + " -=",
		arg + " ||=",
		arg + " &&=",
	}
	for _, p := range assignPatterns {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

func (r RedundantJsonDecodeRule) matchNextSequentialDecode(
	dCtx jsonDecodeContext,
	line string,
	arg string,
	lineNum1 int,
	lineNum2 int,
) bool {
	for _, nIdx := range repeatedDecoderCallRe.FindAllStringSubmatchIndex(line, -1) {
		if line[nIdx[4]:nIdx[5]] != arg {
			continue
		}
		if !areLinesAddedOrWholeScan(dCtx.block, lineNum1, lineNum2) {
			return true
		}
		dCtx.emit(
			pickReportLine(lineNum1, lineNum2, dCtx.block.addedLines),
			"Redundant JSON decoding: same variable decoded multiple times across statements",
			"Cache the decoded JSON object in a local variable before inspecting properties.",
		)
		return true
	}
	return false
}
