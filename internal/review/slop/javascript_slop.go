package slop

import (
	"fmt"
	"regexp"
	"strings"
)

type sourceToken struct {
	text  string
	line  int
	start int
	end   int
}

// lexBraceSource returns identifiers and punctuation, discarding comments and
// literal text while scanning executable expressions inside template literals.
func lexBraceSource(source string) []sourceToken {
	var tokens []sourceToken
	line := 1
	for i := 0; i < len(source); {
		c := source[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		if c == '/' && i+1 < len(source) && source[i+1] == '/' {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(source) && source[i+1] == '*' {
			start := i
			startLine := line
			i += 2
			closed := false
			for i < len(source) {
				if source[i] == '\n' {
					line++
				}
				if source[i] == '*' && i+1 < len(source) && source[i+1] == '/' {
					i += 2
					closed = true
					break
				}
				i++
			}
			if !closed {
				tokens = append(tokens, sourceToken{text: "<unterminated-comment>", line: startLine, start: start, end: i})
			}
			continue
		}
		if c == '/' && regexLiteralCanStart(tokens) {
			start := i
			startLine := line
			var closed bool
			i, closed = skipRegexLiteral(source, i, &line)
			if !closed {
				tokens = append(tokens, sourceToken{text: "<unterminated-regex>", line: startLine, start: start, end: i})
			}
			continue
		}
		if c == '`' {
			var templateTokens []sourceToken
			i = lexTemplateLiteral(source, i, &line, &templateTokens)
			tokens = append(tokens, templateTokens...)
			continue
		}
		if c == '\'' || c == '"' {
			quote := c
			start := i
			startLine := line
			i++
			closed := false
			for i < len(source) {
				if source[i] == '\n' {
					line++
				}
				if source[i] == '\\' && i+1 < len(source) {
					if source[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if source[i] == quote {
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				tokens = append(tokens, sourceToken{text: "<unterminated-string>", line: startLine, start: start, end: i})
			}
			continue
		}
		if isSourceIdentStart(c) {
			start := i
			for i < len(source) && isSourceIdentPart(source[i]) {
				i++
			}
			tokens = append(tokens, sourceToken{text: source[start:i], line: line, start: start, end: i})
			continue
		}
		if c == '=' && i+1 < len(source) && source[i+1] == '>' {
			tokens = append(tokens, sourceToken{text: "=>", line: line, start: i, end: i + 2})
			i += 2
			continue
		}
		if c == '=' || c == '!' {
			start := i
			i++
			for i < len(source) && source[i] == '=' && i-start < 3 {
				i++
			}
			tokens = append(tokens, sourceToken{text: source[start:i], line: line, start: start, end: i})
			continue
		}
		if strings.ContainsRune("{}();[],:?+-*%&|^~<>", rune(c)) {
			tokens = append(tokens, sourceToken{text: string(c), line: line, start: i, end: i + 1})
		}
		i++
	}
	return tokens
}

func lexTemplateLiteral(source string, start int, line *int, tokens *[]sourceToken) int {
	for i := start + 1; i < len(source); {
		if source[i] == '\\' && i+1 < len(source) {
			if source[i+1] == '\n' {
				*line++
			}
			i += 2
			continue
		}
		if source[i] == '`' {
			return i + 1
		}
		if source[i] == '\n' {
			*line++
			i++
			continue
		}
		if source[i] == '$' && i+1 < len(source) && source[i+1] == '{' {
			expressionStart := i + 2
			expressionEnd := findTemplateExpressionEnd(source, expressionStart)
			if expressionEnd < 0 {
				*tokens = append(*tokens, sourceToken{text: "{", line: *line, start: i + 1, end: i + 2})
				return len(source)
			}
			expression := source[expressionStart:expressionEnd]
			for _, token := range lexBraceSource(expression) {
				token.line += *line - 1
				token.start += expressionStart
				token.end += expressionStart
				*tokens = append(*tokens, token)
			}
			*line += strings.Count(expression, "\n")
			i = expressionEnd + 1
			continue
		}
		i++
	}
	*tokens = append(*tokens, sourceToken{text: "<unterminated-template>", line: *line, start: start, end: len(source)})
	return len(source)
}

func findTemplateExpressionEnd(source string, start int) int {
	depth := 1
	for i := start; i < len(source); {
		if source[i] == '/' && i+1 < len(source) && source[i+1] == '/' {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}
		if source[i] == '/' && i+1 < len(source) && source[i+1] == '*' {
			i += 2
			for i < len(source) && !(source[i] == '*' && i+1 < len(source) && source[i+1] == '/') {
				i++
			}
			if i+1 < len(source) {
				i += 2
			}
			continue
		}
		if source[i] == '\'' || source[i] == '"' {
			i = skipQuotedLiteral(source, i)
			continue
		}
		if source[i] == '`' {
			i = skipNestedTemplate(source, i)
			continue
		}
		if source[i] == '/' && regexLiteralCanStart(lexBraceSource(source[start:i])) {
			line := 1
			var closed bool
			i, closed = skipRegexLiteral(source, i, &line)
			if !closed {
				return -1
			}
			continue
		}
		switch source[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
		i++
	}
	return -1
}

func skipQuotedLiteral(source string, start int) int {
	quote := source[start]
	for i := start + 1; i < len(source); i++ {
		if source[i] == '\\' {
			i++
			continue
		}
		if source[i] == quote || source[i] == '\n' {
			return i + 1
		}
	}
	return len(source)
}

func skipNestedTemplate(source string, start int) int {
	for i := start + 1; i < len(source); {
		if source[i] == '\\' {
			i += 2
			continue
		}
		if source[i] == '`' {
			return i + 1
		}
		if source[i] == '$' && i+1 < len(source) && source[i+1] == '{' {
			end := findTemplateExpressionEnd(source, i+2)
			if end < 0 {
				return len(source)
			}
			i = end + 1
			continue
		}
		i++
	}
	return len(source)
}

func regexLiteralCanStart(tokens []sourceToken) bool {
	if len(tokens) == 0 {
		return true
	}
	last := tokens[len(tokens)-1].text
	if last == ">" && len(tokens) > 1 && tokens[len(tokens)-2].text == "=" {
		return true // A regex literal can be the expression body of an arrow function.
	}
	switch last {
	case "(", "{", "[", ";", ",", ":", "?", "=", "!", "+", "-", "*", "%", "&", "|", "^", "~", "<", ">", "return", "case", "throw", "yield", "await":
		return true
	default:
		return false
	}
}

func skipRegexLiteral(source string, start int, line *int) (int, bool) {
	inCharacterClass := false
	for i := start + 1; i < len(source); i++ {
		switch source[i] {
		case '\n':
			*line++
			return i + 1, false
		case '\\':
			i++
		case '[':
			inCharacterClass = true
		case ']':
			inCharacterClass = false
		case '/':
			if inCharacterClass {
				continue
			}
			i++
			for i < len(source) && isSourceIdentPart(source[i]) {
				i++
			}
			return i, true
		}
	}
	return len(source), false
}

func isSourceIdentStart(c byte) bool {
	return c == '_' || c == '$' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isSourceIdentPart(c byte) bool {
	return isSourceIdentStart(c) || c >= '0' && c <= '9'
}

type braceControl struct {
	line     int
	addDepth bool
}

func analyzeBraceSlop(file, language, source string, added map[int]bool) []Finding {
	tokens := lexBraceSource(source)
	if err := braceStructureError(tokens); err != nil {
		return []Finding{{
			Rule:        "code-slop-analysis-error",
			Severity:    "high",
			File:        file,
			Line:        0,
			Message:     "Could not safely analyze " + language + " structure: " + err.Error(),
			Remediation: "Fix mismatched braces or delimiters, then rerun the review.",
		}}
	}
	controls := make(map[int]braceControl)
	jsConfig := braceLanguageConfig{
		controls:            wordSet("if", "for", "while", "switch", "catch"),
		directBlocks:        wordSet("else", "try", "finally", "do"),
		depthBlocks:         wordSet("try", "do"),
		allowUnbracedBodies: true,
	}
	controlWords := map[string]bool{"if": true, "for": true, "while": true, "switch": true, "catch": true}
	for i, tok := range tokens {
		if controlWords[tok.text] {
			if tok.text == "catch" && i > 0 && tokens[i-1].text != "}" {
				continue // Ignore Promise.catch(...) method calls.
			}
			open := i + 1
			if open >= len(tokens) || tokens[open].text != "(" {
				continue
			}
			depth := 0
			for open < len(tokens) {
				switch tokens[open].text {
				case "(":
					depth++
				case ")":
					depth--
					if depth == 0 {
						open++
						goto matchedCondition
					}
				}
				open++
			}
			continue
		matchedCondition:
			if open < len(tokens) && tokens[open].text == "{" {
				controls[open] = braceControl{line: tok.line, addDepth: true}
			}
			continue
		}
		if tok.text == "else" || tok.text == "try" || tok.text == "finally" || tok.text == "do" {
			open := i + 1
			if tok.text == "else" && open < len(tokens) && tokens[open].text == "if" {
				continue
			}
			if open < len(tokens) && tokens[open].text == "{" {
				controls[open] = braceControl{line: tok.line, addDepth: tok.text == "try" || tok.text == "do"}
			}
		}
	}
	unbracedStarts, unbracedEnds := languageUnbracedNesting(asBraceTokens(tokens), jsConfig)
	jsTokens := asBraceTokens(tokens)
	scopeOpen := findFunctionScopeBlocks(jsTokens, controls)

	var findings []Finding
	type jsFrame struct {
		counted, scope     bool
		parentDepth        int
		parentDeepReported bool
	}
	var stack []jsFrame
	depth := 0
	deepReported := false
	seen := make(map[string]bool)
	for i, tok := range tokens {
		if depth < 4 {
			deepReported = false
		}
		if line, ok := unbracedStarts[i]; ok {
			depth++
			if depth >= 4 && added[line] && !deepReported {
				appendSlopFinding(&findings, seen, file, line, "Excessive syntax nesting depth (4+ levels)", "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.")
				deepReported = true
			}
		}
		if added[tok.line] && depth >= 4 && !deepReported {
			appendSlopFinding(&findings, seen, file, tok.line, "Excessive syntax nesting depth (4+ levels)", "Refactor to reduce nesting depth.")
			deepReported = true
		}
		switch tok.text {
		case "{":
			control, isControl := controls[i]
			counted := isControl && control.addDepth
			scope := scopeOpen[i]
			frame := jsFrame{counted: counted, scope: scope}
			if scope {
				frame.parentDepth = depth
				frame.parentDeepReported = deepReported
				depth = 0
				deepReported = false
			}
			stack = append(stack, frame)
			if !isControl {
				continue
			}
			if counted {
				depth++
			}
			if depth >= 4 && added[control.line] && !deepReported {
				appendSlopFinding(&findings, seen, file, control.line, "Excessive syntax nesting depth (4+ levels)", "Refactor to reduce nesting depth. Consider using early returns or breaking logic into smaller functions.")
				deepReported = true
			}
			if isControl && i+1 < len(tokens) && tokens[i+1].text == "}" && added[control.line] && isEmptyBraceBody(source[tok.end:tokens[i+1].start]) {
				appendSlopFinding(&findings, seen, file, control.line, "Empty block", "Remove the empty block or add a comment explaining why it is empty.")
			}
		case "}":
			if len(stack) > 0 {
				frame := stack[len(stack)-1]
				if frame.counted {
					depth--
				}
				stack = stack[:len(stack)-1]
				if frame.scope {
					depth = frame.parentDepth
					deepReported = frame.parentDeepReported
				} else if depth < 4 {
					deepReported = false
				}
			}
		}
		if unbracedEnds[i] > 0 {
			depth -= unbracedEnds[i]
		}
	}

	// Boolean comparisons are checked from tokens so strings and comments do
	// not create findings.
	analysisTokens := make([]braceLanguageToken, len(tokens))
	for i, token := range tokens {
		analysisTokens[i] = braceLanguageToken{text: token.text, line: token.line, start: token.start, end: token.end}
	}
	for i := 1; i+1 < len(tokens); i++ {
		if tokens[i].text != "==" && tokens[i].text != "===" && tokens[i].text != "!=" && tokens[i].text != "!==" {
			continue
		}
		if tokens[i].text == "==" || tokens[i].text == "!=" {
			continue // Loose equality can coerce values that are not booleans.
		}
		findingLine, comparisonAdded := comparisonAddedLine(analysisTokens, i, added)
		if !comparisonAdded {
			continue
		}
		if isBooleanOperand(analysisTokens, i-1, true, wordSet("true", "false")) || isBooleanOperand(analysisTokens, i+1, false, wordSet("true", "false")) {
			appendSlopFinding(&findings, seen, file, findingLine, "Redundant boolean comparison", "Remove the explicit comparison to true/false. Use the boolean expression directly.")
		}
	}
	return findings
}

func asBraceTokens(tokens []sourceToken) []braceLanguageToken {
	converted := make([]braceLanguageToken, len(tokens))
	for i, token := range tokens {
		converted[i] = braceLanguageToken{text: token.text, line: token.line, start: token.start, end: token.end}
	}
	return converted
}

func braceStructureError(tokens []sourceToken) error {
	type delimiter struct {
		text string
		line int
	}
	var stack []delimiter
	pairs := map[string]string{")": "(", "]": "[", "}": "{"}
	for _, tok := range tokens {
		if strings.HasPrefix(tok.text, "<unterminated-") {
			return fmt.Errorf("unterminated literal on line %d", tok.line)
		}
		switch tok.text {
		case "(", "[", "{":
			stack = append(stack, delimiter{text: tok.text, line: tok.line})
		case ")", "]", "}":
			if len(stack) == 0 || stack[len(stack)-1].text != pairs[tok.text] {
				return fmt.Errorf("unmatched %q on line %d", tok.text, tok.line)
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) > 0 {
		top := stack[len(stack)-1]
		return fmt.Errorf("unclosed %q from line %d", top.text, top.line)
	}
	return nil
}

func isJSBool(text string) bool { return text == "true" || text == "false" }

var braceComments = regexp.MustCompile(`(?s)/\*.*?\*/|//[^\n]*`)

func isEmptyBraceBody(body string) bool {
	return strings.TrimSpace(braceComments.ReplaceAllString(body, "")) == ""
}

func (r SlopRule) checkJavaScriptSyntax(file string, added []int) []Finding {
	source, err := r.readSourceForAnalysis(file)
	if err != nil {
		return r.analysisReadError(file, err)
	}
	return analyzeBraceSlop(file, "JavaScript", string(source), addedLineMap(added))
}

func (r SlopRule) checkJavaScriptRegex(fd FileDiff) []Finding {
	return r.checkAddedLineRegex(fd)
}
