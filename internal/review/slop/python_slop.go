package slop

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

func (r SlopRule) checkPythonSyntax(file string, added []int) []Finding {
	source, err := r.readSourceForAnalysis(file)
	if err != nil {
		return r.analysisReadError(file, err)
	}
	return analyzePythonSlop(file, string(source), addedLineMap(added))
}

func (r SlopRule) checkPythonAddedLineRegex(fd FileDiff) []Finding {
	findings := r.checkAddedLineRegex(fd)
	seen := make(map[int]bool)
	for _, finding := range findings {
		if finding.Message == "Redundant boolean comparison" {
			seen[finding.Line] = true
		}
	}
	segments := pythonDiffSource(fd)
	if len(segments) > 1 || len(segments) == 1 && segments[0].firstLine != 1 {
		findings = append(findings, Finding{
			Rule:        "code-slop-analysis-error",
			Severity:    "high",
			File:        fd.Path,
			Line:        0,
			Message:     "Could not safely determine Python string state from partial diff context",
			Remediation: "Provide the complete Python source or configure the review with a repository root.",
		})
		return findings
	}
	for _, segment := range segments {
		var source strings.Builder
		var tripleQuote, normalQuote byte
		tripleSize := 0
		for lineIndex, text := range segment.lines {
			code := stripPythonComment(text, &tripleQuote, &tripleSize, &normalQuote)
			line := segment.firstLine + lineIndex
			if segment.added[lineIndex+1] && !seen[line] && pythonBoolComparison.MatchString(code) {
				findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: fd.Path, Line: line, Message: "Redundant boolean comparison", Remediation: "Only remove this comparison when the operand is guaranteed to be boolean; otherwise the comparison can change behavior."})
				seen[line] = true
			}
			if lineIndex > 0 {
				source.WriteByte('\n')
			}
			source.WriteString(text)
		}
		for _, finding := range pythonFStringBooleanFindings(fd.Path, source.String(), segment.added) {
			finding.Line += segment.firstLine - 1
			if !seen[finding.Line] {
				findings = append(findings, finding)
				seen[finding.Line] = true
			}
		}
	}
	return findings
}

type pythonDiffSegment struct {
	firstLine int
	lines     []string
	added     map[int]bool
}

func pythonDiffSource(fd FileDiff) []pythonDiffSegment {
	lineText := make(map[int]string, len(fd.AddedText)+len(fd.ContextText))
	addedLines := addedLineMap(fd.AddedLines)
	for line, text := range fd.ContextText {
		lineText[line] = text
	}
	for line, text := range fd.AddedText {
		lineText[line] = text
	}
	lineNumbers := make([]int, 0, len(lineText))
	for line := range lineText {
		if line > 0 {
			lineNumbers = append(lineNumbers, line)
		}
	}
	sort.Ints(lineNumbers)
	var segments []pythonDiffSegment
	for _, line := range lineNumbers {
		if len(segments) == 0 || line != segments[len(segments)-1].firstLine+len(segments[len(segments)-1].lines) {
			segments = append(segments, pythonDiffSegment{firstLine: line, added: make(map[int]bool)})
		}
		segment := &segments[len(segments)-1]
		segment.lines = append(segment.lines, lineText[line])
		if addedLines[line] {
			segment.added[len(segment.lines)] = true
		}
	}
	return segments
}

func analyzePythonSlop(file, source string, added map[int]bool) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	lines := make([]pythonSourceLine, 0)
	tripleQuote := byte(0)
	tripleQuoteSize := 0
	normalQuote := byte(0)
	for lineNo, raw := range strings.Split(source, "\n") {
		line := stripPythonComment(raw, &tripleQuote, &tripleQuoteSize, &normalQuote)
		lines = append(lines, pythonSourceLine{number: lineNo + 1, code: line, indent: pythonIndent(line)})
	}
	var stack []pythonBlock
	headerKind := make(map[int]string)
	lastTerminated := make(map[int]bool)
	for i := 0; i < len(lines); {
		trimmed := strings.TrimSpace(lines[i].code)
		if trimmed == "" {
			i++
			continue
		}
		indent := lines[i].indent
		for len(stack) > 0 && indent <= stack[len(stack)-1].indent {
			stack = stack[:len(stack)-1]
		}
		logical, end := pythonLogicalStatement(lines, i)
		for key := range lastTerminated {
			if key > indent {
				delete(lastTerminated, key)
			}
		}
		if lastTerminated[indent] {
			if added[lines[i].number] {
				appendSlopFinding(&findings, seen, file, lines[i].number, "Unreachable code after terminating statement", "Remove the dead code or restructure the control flow.")
			}
			lastTerminated[indent] = false
		}
		isSuite := strings.HasSuffix(strings.TrimSpace(logical), ":")
		isControl := isSuite && pythonControlHeader.MatchString(strings.TrimSpace(logical))
		isScope := isSuite && pythonScopeHeader.MatchString(strings.TrimSpace(logical))
		isCase := isSuite && pythonCaseHeader.MatchString(strings.TrimSpace(logical))
		if isControl || isScope || isCase {
			body := end + 1
			for body < len(lines) && strings.TrimSpace(lines[body].code) == "" {
				body++
			}
			if body >= len(lines) || lines[body].indent <= indent {
				return []Finding{{
					Rule:        "code-slop-analysis-error",
					Severity:    "high",
					File:        file,
					Line:        0,
					Message:     fmt.Sprintf("Could not safely analyze Python structure: expected an indented suite after line %d", lines[i].number),
					Remediation: "Fix the Python indentation or incomplete block, then rerun the review.",
				}}
			}
		}
		if isControl {
			kind := strings.Fields(trimmed)
			kindName := ""
			if len(kind) > 0 {
				kindName = strings.TrimSuffix(kind[0], ":")
				if kindName == "async" && len(kind) > 1 {
					kindName = strings.TrimSuffix(kind[1], ":")
				}
			}
			if (kindName == "else" || kindName == "elif") && (headerKind[indent] == "if" || headerKind[indent] == "elif") && pythonSuiteEndsWithTerminator(lines, i) {
				if added[lines[i].number] {
					appendSlopFinding(&findings, seen, file, lines[i].number, "Else branch after a terminating statement", "Dedent the else body; it can follow the if directly because the if body always exits.")
				}
			}
			headerKind[indent] = kindName
			depth := pythonControlDepth(stack) + 1
			if added[lines[i].number] && depth >= 4 {
				appendSlopFinding(&findings, seen, file, lines[i].number, "Excessive syntax nesting depth (4+ levels)", "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.")
			}
			if added[lines[i].number] && pythonPassOnlySuite(lines, i) {
				appendSlopFinding(&findings, seen, file, lines[i].number, "Empty block", "Remove the empty block or replace pass with meaningful behavior.")
			}
			stack = append(stack, pythonBlock{indent: indent, control: true})
		} else if isScope {
			if strings.HasPrefix(trimmed, "def ") || strings.HasPrefix(trimmed, "async def ") {
				if pythonMutableDefaultArg(logical) {
					for lineIndex := i; lineIndex <= end; lineIndex++ {
						if added[lines[lineIndex].number] {
							appendSlopFinding(&findings, seen, file, lines[lineIndex].number, "Mutable default argument", "Mutable defaults are shared across calls; use None and create the value inside the function.")
							break
						}
					}
				}
			}
			stack = append(stack, pythonBlock{indent: indent, scope: true})
		} else if isCase && added[lines[i].number] && pythonPassOnlySuite(lines, i) {
			appendSlopFinding(&findings, seen, file, lines[i].number, "Empty block", "Remove the empty block or replace pass with meaningful behavior.")
		}
		if pythonBoolComparison.MatchString(logical) {
			for lineIndex := i; lineIndex <= end; lineIndex++ {
				if added[lines[lineIndex].number] {
					appendSlopFinding(&findings, seen, file, lines[lineIndex].number, "Redundant boolean comparison", "Only remove this comparison when the operand is guaranteed to be boolean; otherwise the comparison can change behavior.")
					break
				}
			}
		}
		if len(pythonBoolOperator.FindAllString(logical, -1)) >= 5 {
			for lineIndex := i; lineIndex <= end; lineIndex++ {
				if added[lines[lineIndex].number] {
					appendSlopFinding(&findings, seen, file, lines[lineIndex].number, "Long boolean operator chain (5+ operators)", "Extract the condition into a named variable or split it into smaller checks.")
					break
				}
			}
		}
		lastTerminated[indent] = isPythonTerminatorStatement(logical)
		i = end + 1
	}
	for _, finding := range pythonFStringBooleanFindings(file, source, added) {
		appendSlopFinding(&findings, seen, file, finding.Line, finding.Message, finding.Remediation)
	}
	for _, finding := range pythonExtraFindings(file, source, added) {
		appendSlopFinding(&findings, seen, file, finding.Line, finding.Message, finding.Remediation)
	}
	return findings
}

func pythonFStringBooleanFindings(file, source string, added map[int]bool) []Finding {
	var findings []Finding
	for i := 0; i < len(source); {
		if source[i] == '#' {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}
		if source[i] != '\'' && source[i] != '"' {
			i++
			continue
		}
		quoteStart := i
		prefixStart := quoteStart
		for prefixStart > 0 && ((source[prefixStart-1] >= 'a' && source[prefixStart-1] <= 'z') || (source[prefixStart-1] >= 'A' && source[prefixStart-1] <= 'Z')) {
			prefixStart--
		}
		prefix := strings.ToLower(source[prefixStart:quoteStart])
		isFString := prefix == "f" || prefix == "fr" || prefix == "rf"
		quote := source[i]
		triple := i+2 < len(source) && source[i+1] == quote && source[i+2] == quote
		delim := 1
		if triple {
			delim = 3
		}
		i += delim
		for i < len(source) {
			if source[i] == '\\' {
				i += 2
				continue
			}
			if triple && i+2 < len(source) && source[i] == quote && source[i+1] == quote && source[i+2] == quote {
				i += 3
				break
			}
			if !triple && source[i] == quote {
				i++
				break
			}
			if isFString && source[i] == '{' {
				if i+1 < len(source) && source[i+1] == '{' {
					i += 2
					continue
				}
				start := i + 1
				end := pythonFExpressionEnd(source, start)
				if end < 0 {
					break
				}
				expression := source[start:end]
				if pythonBoolComparison.MatchString(expression) {
					lineStart := strings.Count(source[:start], "\n") + 1
					lineEnd := strings.Count(source[:end], "\n") + 1
					for line := lineStart; line <= lineEnd; line++ {
						if added[line] {
							findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: file, Line: line, Message: "Redundant boolean comparison", Remediation: "Only remove this comparison when the operand is guaranteed to be boolean; otherwise the comparison can change behavior."})
							break
						}
					}
				}
				i = end + 1
				continue
			}
			i++
		}
	}
	return findings
}

func pythonFExpressionEnd(source string, start int) int {
	depth := 1
	var quote byte
	for i := start; i < len(source); i++ {
		c := source[i]
		if quote != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

type pythonBlock struct {
	indent  int
	control bool
	scope   bool
}

type pythonSourceLine struct {
	number int
	code   string
	indent int
}

func pythonControlDepth(stack []pythonBlock) int {
	depth := 0
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i].scope {
			break
		}
		if stack[i].control {
			depth++
		}
	}
	return depth
}

func pythonLogicalStatement(lines []pythonSourceLine, start int) (string, int) {
	var parts []string
	depth := 0
	end := start
	for ; end < len(lines); end++ {
		line := strings.TrimSpace(lines[end].code)
		parts = append(parts, line)
		depth += pythonDelimiterDelta(line)
		if depth <= 0 && !pythonLineContinues(line) {
			break
		}
	}
	return strings.Join(parts, " "), end
}

func pythonDelimiterDelta(line string) int {
	delta := 0
	for _, r := range line {
		switch r {
		case '(', '[', '{':
			delta++
		case ')', ']', '}':
			delta--
		}
	}
	return delta
}

func pythonLineContinues(line string) bool {
	line = strings.TrimSpace(line)
	if strings.HasSuffix(line, "\\") {
		return true
	}
	fields := strings.Fields(line)
	if len(fields) > 0 {
		switch fields[len(fields)-1] {
		case "and", "or", "not":
			return true
		}
	}
	for _, suffix := range []string{"==", "!=", "+", "-", ","} {
		if strings.HasSuffix(line, suffix) {
			return true
		}
	}
	return false
}

func pythonPassOnlySuite(lines []pythonSourceLine, header int) bool {
	headerIndent := lines[header].indent
	foundPass := false
	for i := header + 1; i < len(lines); i++ {
		code := strings.TrimSpace(lines[i].code)
		if code == "" {
			continue
		}
		if lines[i].indent <= headerIndent {
			return foundPass
		}
		if !foundPass {
			if code != "pass" {
				return false
			}
			foundPass = true
			continue
		}
		return false
	}
	return foundPass
}

// pythonSuiteEndsWithTerminator reports whether the suite preceding the
// control header at index header ends with a return/raise/break/continue.
func pythonSuiteEndsWithTerminator(lines []pythonSourceLine, header int) bool {
	for i := header - 1; i >= 0; i-- {
		code := strings.TrimSpace(lines[i].code)
		if code == "" {
			continue
		}
		return isPythonTerminatorStatement(code)
	}
	return false
}

// pythonMutableDefaultArg reports whether a def signature assigns a mutable
// literal or empty-call default, e.g. "def f(x=[], y={})".
func pythonMutableDefaultArg(header string) bool {
	for i := 0; i < len(header); i++ {
		if header[i] != '=' {
			continue
		}
		if i > 0 && strings.ContainsRune("=!<>:", rune(header[i-1])) {
			continue
		}
		if i+1 < len(header) && header[i+1] == '=' {
			continue
		}
		j := i + 1
		for j < len(header) && (header[j] == ' ' || header[j] == '\t') {
			j++
		}
		if j >= len(header) {
			continue
		}
		if header[j] == '[' || header[j] == '{' {
			return true
		}
		for _, call := range []string{"set(", "list(", "dict("} {
			if strings.HasPrefix(header[j:], call) {
				return true
			}
		}
	}
	return false
}

var (
	pythonControlHeader  = regexp.MustCompile(`^(?:(?:async\s+)?(?:if|elif|else|for|while|try|except|finally|with|match))\b`)
	pythonScopeHeader    = regexp.MustCompile(`^(?:async\s+)?(?:def|class)\b`)
	pythonBoolComparison = regexp.MustCompile(`(?:==|!=)\s*\(*\s*(?:True|False)\b|\b(?:True|False)\s*\)*\s*(?:==|!=)`)
	pythonCaseHeader     = regexp.MustCompile(`^case\b`)
	pythonBoolOperator   = regexp.MustCompile(`\b(?:and|or)\b`)
)

func pythonIndent(line string) int {
	indent := 0
	for _, r := range line {
		if r == ' ' {
			indent++
		} else if r == '\t' {
			indent = (indent/8 + 1) * 8
		} else {
			break
		}
	}
	return indent
}

func stripPythonComment(line string, tripleQuote *byte, tripleSize *int, normalQuote *byte) string {
	clean := []byte(line)
	quote := *normalQuote
	continuedQuote := byte(0)
	for i := 0; i < len(line); i++ {
		if *tripleQuote != 0 {
			if i+*tripleSize <= len(line) && strings.Repeat(string(*tripleQuote), *tripleSize) == line[i:i+*tripleSize] {
				for j := 0; j < *tripleSize; j++ {
					clean[i+j] = ' '
				}
				i += *tripleSize - 1
				*tripleQuote = 0
				*tripleSize = 0
				continue
			}
			clean[i] = ' '
			continue
		}
		c := line[i]
		if quote != 0 {
			clean[i] = ' '
			if c == '\\' {
				if i+1 < len(clean) {
					clean[i+1] = ' '
					i++
				} else {
					continuedQuote = quote
				}
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if c == '#' {
			*normalQuote = continuedQuote
			return string(clean[:i])
		}
		if c == '\'' || c == '"' {
			if i+2 < len(line) && line[i+1] == c && line[i+2] == c {
				*tripleQuote = c
				*tripleSize = 3
				clean[i], clean[i+1], clean[i+2] = ' ', ' ', ' '
				i += 2
			} else {
				quote = c
				clean[i] = ' '
			}
		}
	}
	*normalQuote = continuedQuote
	return string(clean)
}

var (
	pythonTypeCompare  = regexp.MustCompile(`\btype\s*\(\s*[\w.]+\s*\)\s*={1,2}\s*[A-Z]\w*`)
	pythonIsLiteral    = regexp.MustCompile(`\bis\s+(?:not\s+)?(?:\d|["'])`)
	pythonGlobalStmt   = regexp.MustCompile(`^\s*global\s+\w+`)
	pythonMutableClass = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*(?:\[\s*\]|\{\s*\}|set\s*\(|list\s*\(|dict\s*\()`)
	pythonDefHeader    = regexp.MustCompile(`^\s*(?:async\s+)?def\s+\w+`)
	pythonClassHeader  = regexp.MustCompile(`^\s*class\s+\w+`)
	pythonFinallyHdr   = regexp.MustCompile(`^\s*finally\s*:`)
	pythonTerminating  = regexp.MustCompile(`^\s*(?:return\b|break\b|continue\b)`)
)

// pythonExtraFindings covers Python-specific style/correctness heuristics:
// type()== comparisons, is-with-literals, global statements, mutable class
// attributes, return/break/continue inside finally, and long functions.
func pythonExtraFindings(file, source string, added map[int]bool) []Finding {
	var findings []Finding
	rawLines := strings.Split(source, "\n")
	// Mutable class attributes: track class bodies; a plain `name = []/{}/()`
	// at class-body indent is shared mutable state.
	classIndent := -1
	funcIndent := -1
	for i, raw := range rawLines {
		lineNo := i + 1
		code := strings.TrimSpace(raw)
		indent := pythonIndent(raw)
		if classIndent >= 0 && indent <= classIndent {
			classIndent = -1
		}
		if m := pythonClassHeader.FindStringSubmatch(raw); m != nil {
			classIndent = indent
			funcIndent = -1
			continue
		}
		if pythonDefHeader.MatchString(raw) {
			funcIndent = indent
			continue
		}
		if funcIndent >= 0 && indent <= funcIndent {
			funcIndent = -1
		}
		if classIndent >= 0 && indent == classIndent+4 {
			if pythonMutableClass.MatchString(raw) {
				if added[lineNo] {
					findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: file, Line: lineNo, Message: "Mutable class attribute", Remediation: "Move the mutable default into __init__ or use a tuple/immutable default."})
				}
			}
		}
		if added[lineNo] {
			switch {
			case pythonTypeCompare.MatchString(code):
				findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: file, Line: lineNo, Message: "type() comparison instead of isinstance()", Remediation: "Use isinstance(x, T) which also handles subclasses."})
			case pythonIsLiteral.MatchString(code):
				findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: file, Line: lineNo, Message: "'is'/'is not' compared against a literal", Remediation: "Use == / != for value comparison; 'is' is for identity."})
			case pythonGlobalStmt.MatchString(code):
				findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: file, Line: lineNo, Message: "global statement mutates module state", Remediation: "Pass state explicitly or refactor to avoid hidden global mutation."})
			case funcIndent >= 0 && indent > funcIndent && (strings.HasPrefix(code, "import ") || strings.HasPrefix(code, "from ")):
				findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: file, Line: lineNo, Message: "Import inside function body", Remediation: "Move imports to module level unless lazy loading is intentional."})
			}
		}
	}
	// return/break/continue inside finally swallows in-flight exceptions.
	finallyIndent := -1
	for i, raw := range rawLines {
		lineNo := i + 1
		indent := pythonIndent(raw)
		if finallyIndent >= 0 && strings.TrimSpace(raw) != "" && indent <= finallyIndent {
			finallyIndent = -1
		}
		if pythonFinallyHdr.MatchString(raw) {
			finallyIndent = indent
			continue
		}
		if finallyIndent >= 0 && indent > finallyIndent && pythonTerminating.MatchString(raw) && added[lineNo] {
			findings = append(findings, Finding{Rule: "code-slop", Severity: "medium", File: file, Line: lineNo, Message: "Terminating statement inside finally", Remediation: "return/break/continue in finally suppresses in-flight exceptions; restructure error handling."})
		}
	}
	// Long functions (>80 lines) measured by dedent.
	for i, raw := range rawLines {
		if !pythonDefHeader.MatchString(raw) || !added[i+1] {
			continue
		}
		defIndent := pythonIndent(raw)
		end := i + 1
		for end < len(rawLines) {
			next := strings.TrimSpace(rawLines[end])
			if next != "" && pythonIndent(rawLines[end]) <= defIndent {
				break
			}
			end++
		}
		if end-i-1 > 80 {
			findings = append(findings, Finding{Rule: "code-slop", Severity: "low", File: file, Line: i + 1, Message: "Function exceeds 80 lines", Remediation: "Consider splitting the function into smaller, focused helpers."})
		}
	}
	return findings
}
