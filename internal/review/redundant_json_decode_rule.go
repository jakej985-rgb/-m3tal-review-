package review

import (
	"context"
	"regexp"
	"slices"
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
		`(?i)\b(tryDecodeList|jsonDecode|json\.decode|JSON\.parse|deserializeList)\s*\(\s*([a-zA-Z0-9_]+)\s*\)`,
	)

	decodesProfilesRe = regexp.MustCompile(
		`(?i)(?:(?:var|final|const|[A-Za-z0-9_<>]+)\s+([a-zA-Z0-9_]+)\s*=\s*)?_decodesProfiles\s*\(\s*([a-zA-Z0-9_]+)\s*\)`,
	)
	containsProfileRe = regexp.MustCompile(
		`(?i)_containsLoadableProfile\s*\(\s*([a-zA-Z0-9_]+)\s*[,)]`,
	)
	nullableCastSuffixRe = regexp.MustCompile(
		`\b(?:as|is)\s+[A-Za-z0-9_<>,\s]+$`,
	)
	paramDeclExtractRe = regexp.MustCompile(
		`(?:\(|,\s*)(?:[a-zA-Z0-9_<>?]+\s+)([a-zA-Z0-9_]+)\s*[,)]`,
	)
	methodHeaderRe = regexp.MustCompile(
		`(?i)\b(?:void|dynamic|var|final|future|task|function|def|func|[A-Z][a-zA-Z0-9_<>?]*)\s+` +
			`([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*(?:async\s*)?[{=]`,
	)
	constructorHeaderRe = regexp.MustCompile(
		`\b[A-Z][a-zA-Z0-9_]*\s*\(([^)]*)\)\s*[{=]`,
	)
	jsMethodHeaderRe = regexp.MustCompile(
		`^\s*(?:static\s+)?(?:async\s+)?\*?\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)\s*(?:async\s*)?[{=]`,
	)
	localDeclExtractRe = regexp.MustCompile(
		`\b(?:final|var|String|int|double|bool|Map|dynamic|[A-Z][a-zA-Z0-9_<>?]*)\s+([a-zA-Z0-9_]+)\s*=`,
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

func handleQuestionMark(line string, i int, depth int, pendingQ map[int][]int) (int, bool) {
	if i+1 < len(line) && (line[i+1] == '?' || line[i+1] == '.') {
		return i + 1, false
	}
	if i > 0 && line[i-1] == '?' {
		return i, false
	}
	rest := strings.TrimLeft(line[i+1:], " \t")
	if nullableCastSuffixRe.MatchString(line[:i]) && isCastTypeSuffixFollower(rest) {
		return i, false
	}
	pendingQ[depth] = append(pendingQ[depth], i)
	return i, true
}

func handleColon(line string, i int, depth int, pendingQ map[int][]int, pairs *[]ternaryPair) int {
	if i+1 < len(line) && line[i+1] == ':' {
		return i + 1
	}
	if i > 0 && line[i-1] == ':' {
		return i
	}
	qs := pendingQ[depth]
	if len(qs) > 0 {
		qPos := qs[len(qs)-1]
		pendingQ[depth] = qs[:len(qs)-1]
		*pairs = append(*pairs, ternaryPair{
			qPos:     qPos,
			colonPos: i,
			depth:    depth,
		})
	}
	nextColIdx := i
	return nextColIdx
}

func handleParenDepth(ch byte, depth *int, pendingQ map[int][]int) bool {
	if ch == '(' || ch == '[' || ch == '{' {
		*depth = *depth + 1
		return true
	}
	handled := false
	if ch == ')' || ch == ']' || ch == '}' {
		delete(pendingQ, *depth)
		decrementDepth(depth)
		handled = true
	}
	return handled
}

func parseTernaryPairs(line string) []ternaryPair {
	var pairs []ternaryPair
	pendingQ := make(map[int][]int)
	var strChar byte
	inStr, depth := false, 0

	for idx := 0; idx < len(line); idx++ {
		if nextIdx, ok := scanStringLiteral(line, idx, &inStr, &strChar); ok {
			idx = nextIdx
			continue
		}
		ch := line[idx]
		if handleParenDepth(ch, &depth, pendingQ) {
			continue
		}
		if ch == '?' {
			idx, _ = handleQuestionMark(line, idx, depth, pendingQ)
			continue
		}
		if ch == ':' {
			idx = handleColon(line, idx, depth, pendingQ, &pairs)
		}
	}
	return pairs
}

func isCastTypeSuffixFollower(rest string) bool {
	return strings.HasPrefix(rest, ":") ||
		strings.HasPrefix(rest, "??") ||
		strings.HasPrefix(rest, ",") ||
		strings.HasPrefix(rest, ")") ||
		strings.HasPrefix(rest, "]") ||
		strings.HasPrefix(rest, ";")
}

func isTernaryArms(line string, start1, end1, start2, end2 int) bool {
	_ = end1
	_ = end2
	matched := false
	for _, p := range parseTernaryPairs(line) {
		if p.qPos < start1 && start1 < p.colonPos && p.colonPos < start2 {
			matched = true
			break
		}
	}
	return matched
}

func hasSameLineDuplicate(trimmed string, indices [][]int) bool {
	dupFound := false
	for a, idxA := range indices {
		for _, idxB := range indices[a+1:] {
			if trimmed[idxA[4]:idxA[5]] == trimmed[idxB[4]:idxB[5]] &&
				!isTernaryArms(trimmed, idxA[0], idxA[1], idxB[0], idxB[1]) {
				dupFound = true
				break
			}
		}
		if dupFound {
			break
		}
	}
	return dupFound
}

func pickReportLine(l1, l2 int, added map[int]bool) int {
	if added[l2] {
		return l2
	}
	return l1
}

func areLinesAdded(block diffSourceBlock, line1, line2 int) bool {
	return block.addedLines[line1] || block.addedLines[line2]
}

func isLineAdded(block diffSourceBlock, lineNum int) bool {
	return block.addedLines[lineNum]
}

type jsonDecodeContext struct {
	lines     []string
	startLine int
	block     diffSourceBlock
	emit      func(int, string, string)
}

func (r RedundantJsonDecodeRule) checkBlock(
	b diffSourceBlock, text string, start int, seen map[string]bool,
) []Finding {
	var jsonFindings []Finding
	dCtx := jsonDecodeContext{
		lines:     strings.Split(text, "\n"),
		startLine: start,
		block:     b,
		emit: func(lineNum int, msg string, rem string) {
			if dedupeFinding(seen, b.file, lineNum) {
				return
			}
			jsonFindings = append(jsonFindings, Finding{
				Rule:        "redundant-json-decode",
				Severity:    "medium",
				File:        b.file,
				Line:        lineNum,
				Message:     msg,
				Remediation: rem,
			})
		},
	}

	for i, line := range dCtx.lines {
		trimmed := strings.TrimSpace(line)
		if isCommentPrefix(trimmed) {
			continue
		}

		r.checkProfileHelpers(dCtx, i)
		r.checkDecoderCalls(dCtx, i)
	}
	return jsonFindings
}

func (r RedundantJsonDecodeRule) CheckContext(ctx context.Context, diff string) []Finding {
	return executeBlockRule(ctx, diff, r.repositoryRoot, r.workingTree, func(f string) bool {
		return redundantJsonFileRe.MatchString(f) && !redundantJsonExcludeRe.MatchString(f)
	}, r.checkBlock)
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
		if !areLinesAdded(dCtx.block, lineNum, lineNum2) {
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
	trimmed := strings.TrimSpace(stripStringsAndComments(dCtx.lines[i]))
	indices := repeatedDecoderCallRe.FindAllStringSubmatchIndex(trimmed, -1)
	if len(indices) == 0 {
		return
	}
	lineNum := dCtx.startLine + i

	if len(indices) > 1 && isLineAdded(dCtx.block, lineNum) && hasSameLineDuplicate(trimmed, indices) {
		dCtx.emit(
			lineNum,
			"Redundant JSON decoding: same variable decoded multiple times in expression",
			"Cache the decoded JSON object in a local variable before inspecting properties.",
		)
		return
	}

	arg := trimmed[indices[0][4]:indices[0][5]]
	shadowed := isArgShadowed(dCtx.lines, i, arg)
	maxLookahead := 3
	if remaining := len(dCtx.lines) - 1 - i; remaining < maxLookahead {
		maxLookahead = remaining
	}
	r.scanForwardDecoder(dCtx, i, maxLookahead, arg, shadowed, lineNum)
}

func (r RedundantJsonDecodeRule) scanForwardDecoder(
	dCtx jsonDecodeContext,
	i, maxLookahead int,
	arg string,
	shadowed bool,
	lineNum int,
) {
	for offset := 1; offset <= maxLookahead; offset++ {
		next := strings.TrimSpace(stripStringsAndComments(dCtx.lines[i+offset]))
		if next == "" {
			continue
		}
		if shouldStopSequentialScan(next, arg, shadowed) ||
			r.matchNextSequentialDecode(dCtx, next, arg, lineNum, dCtx.startLine+offset+i) {
			return
		}
	}
}

func isIdentOrDot(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') || ch == '_' || ch == '.'
}

var assignOpPrefixes = []string{
	"??=", "||=", "&&=", ":=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=",
}

func isAssignmentOperator(s string) bool {
	for _, p := range assignOpPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return len(s) > 0 && s[0] == '=' && (len(s) == 1 || (s[1] != '=' && s[1] != '>'))
}

func stripStringsAndComments(line string) string {
	var b strings.Builder
	b.Grow(len(line))
	inString := false
	var stringChar byte

	for i := 0; i < len(line); i++ {
		if !inString && line[i] == '`' {
			i = keepTemplateInterpolations(line, i, &b)
			continue
		}
		if nextI, ok := scanStringLiteral(line, i, &inString, &stringChar); ok {
			i = nextI
			continue
		}
		ch := line[i]
		if ch == '/' && i+1 < len(line) && line[i+1] == '/' {
			break
		}
		if ch == '/' && i+1 < len(line) && line[i+1] == '*' {
			end := strings.Index(line[i+2:], "*/")
			if end != -1 {
				i = i + 2 + end + 1
				continue
			}
			break
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// keepTemplateInterpolations masks the literal text of a JS/TS template string starting at
// the opening backtick in line[open], but writes executable `${...}` expressions to b
// (separated by spaces). It returns the index of the closing backtick (or end of line).
func keepTemplateInterpolations(line string, open int, b *strings.Builder) int {
	i := open + 1
	for i < len(line) {
		switch {
		case line[i] == '\\':
			i += 2
			continue
		case line[i] == '`':
			b.WriteByte(' ')
			return i
		case line[i] == '$' && i+1 < len(line) && line[i+1] == '{':
			end := findInterpolationEnd(line, i+2)
			b.WriteByte(' ')
			// Re-sanitize the expression so strings/comments inside it stay masked.
			b.WriteString(stripStringsAndComments(line[i+2 : end]))
			b.WriteByte(' ')
			i = end + 1
			continue
		}
		i++
	}
	return len(line)
}

// findInterpolationEnd returns the index of the `}` closing a `${` expression whose body
// starts at from, counting only structural braces (not those in strings or comments).
func findInterpolationEnd(line string, from int) int {
	depth := 1
	inString := false
	var stringChar byte
	for j := from; j < len(line); j++ {
		if nextJ, ok := scanStringLiteral(line, j, &inString, &stringChar); ok {
			j = nextJ
			continue
		}
		if line[j] == '/' && j+1 < len(line) && line[j+1] == '*' {
			if end := strings.Index(line[j+2:], "*/"); end != -1 {
				j = j + 2 + end + 1
				continue
			}
			return len(line)
		}
		switch line[j] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return j
			}
		}
	}
	return len(line)
}

func containsBareIdent(s string, ident string) bool {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_')
	})
	return slices.Contains(fields, ident)
}

func matchExtractedIdent(re *regexp.Regexp, line string, arg string) bool {
	m := re.FindStringSubmatch(line)
	return len(m) > 1 && m[1] == arg
}

func isMethodOrFuncHeader(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	for _, kw := range []string{
		"if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(", "catch ", "catch(",
		"with ", "with(",
	} {
		if strings.HasPrefix(trimmed, kw) {
			return "", false
		}
	}
	if m := methodHeaderRe.FindStringSubmatch(line); len(m) > 2 {
		return m[2], true
	}
	if m := constructorHeaderRe.FindStringSubmatch(line); len(m) > 1 {
		return m[1], true
	}
	if m := jsMethodHeaderRe.FindStringSubmatch(trimmed); len(m) > 2 {
		name := m[1]
		if name != "if" && name != "for" && name != "while" && name != "switch" &&
			name != "catch" && name != "with" && name != "function" && name != "return" {
			return m[2], true
		}
	}
	return "", false
}

func methodDeclaresParam(line, arg string) (declared bool) {
	if params, isHeader := isMethodOrFuncHeader(line); isHeader {
		return containsBareIdent(params, arg) || matchExtractedIdent(paramDeclExtractRe, line, arg)
	}
	return declared
}

func updateBraceDepth(clean string, depth *int) {
	for c := len(clean) - 1; c >= 0; c-- {
		if clean[c] == '}' {
			*depth++
		} else if clean[c] == '{' {
			*depth--
		}
	}
}

func isMethodBoundary(lines []string, k int, arg string) (isMethod bool, declares bool) {
	if _, ok := isMethodOrFuncHeader(lines[k]); ok {
		return true, methodDeclaresParam(lines[k], arg)
	}
	if k > 0 {
		if _, ok := isMethodOrFuncHeader(lines[k-1]); ok {
			return true, methodDeclaresParam(lines[k-1], arg)
		}
	}
	return
}

func isArgShadowed(lines []string, currentLineIdx int, arg string) (shadowed bool) {
	start := currentLineIdx - 1
	limit := max(0, start-40)
	depth := 0
	for k := start; k >= limit; k-- {
		line := lines[k]
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "class ") {
			break
		}
		clean := stripStringsAndComments(line)
		updateBraceDepth(clean, &depth)
		if depth < 0 {
			if isMethod, declares := isMethodBoundary(lines, k, arg); isMethod {
				return declares
			}
			depth = 0
			continue
		}
		if depth > 0 {
			continue
		}
		if methodDeclaresParam(line, arg) || matchExtractedIdent(localDeclExtractRe, line, arg) {
			return true
		}
	}
	return shadowed
}

func isLocalVarAssignment(line string, arg string, shadowed bool) bool {
	cleanLine := stripStringsAndComments(line)
	argLen := len(arg)
	isAssigned := false
	for i := 0; i+argLen <= len(cleanLine); i++ {
		if cleanLine[i:i+argLen] != arg {
			continue
		}
		if i > 0 && isIdentOrDot(cleanLine[i-1]) {
			if shadowed || i < 5 || cleanLine[i-5:i] != "this." {
				continue
			}
			if i > 5 && isIdentOrDot(cleanLine[i-6]) {
				continue
			}
		}
		if i+argLen < len(cleanLine) && isIdentOrDot(cleanLine[i+argLen]) {
			continue
		}
		if isAssignmentOperator(strings.TrimLeft(cleanLine[i+argLen:], " \t")) {
			isAssigned = true
			break
		}
	}
	return isAssigned
}

func shouldStopSequentialScan(line string, arg string, shadowed bool) bool {
	if strings.HasPrefix(line, "else") || strings.Contains(line, "} else") || strings.HasPrefix(line, "}") {
		return true
	}
	return isLocalVarAssignment(line, arg, shadowed)
}

func (r RedundantJsonDecodeRule) matchNextSequentialDecode(
	dCtx jsonDecodeContext,
	line string,
	arg string,
	lineNum1 int,
	lineNum2 int,
) bool {
	matched := false
	for _, nIdx := range repeatedDecoderCallRe.FindAllStringSubmatchIndex(line, -1) {
		if line[nIdx[4]:nIdx[5]] != arg {
			continue
		}
		if areLinesAdded(dCtx.block, lineNum1, lineNum2) {
			dCtx.emit(
				pickReportLine(lineNum1, lineNum2, dCtx.block.addedLines),
				"Redundant JSON decoding: same variable decoded multiple times across statements",
				"Cache the decoded JSON object in a local variable before inspecting properties.",
			)
		}
		matched = true
		break
	}
	return matched
}
