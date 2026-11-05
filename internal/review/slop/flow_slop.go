package slop

import "strings"

// flowTerminators returns statement keywords that unconditionally exit the
// enclosing block for the named brace language.
func flowTerminators(name string) map[string]bool {
	set := wordSet("return", "break", "continue")
	switch name {
	case "JavaScript", "TypeScript", "Java", "C#", "PHP", "Kotlin", "Swift", "C++":
		set["throw"] = true
		if name == "PHP" {
			set["exit"] = true
			set["die"] = true
		}
	case "Rust":
		set["panic"] = true
	}
	return set
}

func braceBoolOperators(name string) map[string]bool {
	if name == "PHP" {
		return wordSet("&&", "||", "and", "or")
	}
	return wordSet("&&", "||")
}

// braceMatchMap maps each closing delimiter index to its opening delimiter.
func braceMatchMap(tokens []braceLanguageToken) map[int]int {
	match := make(map[int]int)
	var stack []int
	pairs := map[string]string{")": "(", "]": "[", "}": "{"}
	for i, tok := range tokens {
		switch tok.text {
		case "(", "[", "{":
			stack = append(stack, i)
		case ")", "]", "}":
			if len(stack) == 0 {
				continue
			}
			open := stack[len(stack)-1]
			if tokens[open].text != pairs[tok.text] {
				continue
			}
			match[i] = open
			stack = stack[:len(stack)-1]
		}
	}
	return match
}

var braceBlockOwners = wordSet(
	"if", "elif", "else", "while", "for", "foreach", "loop", "match", "when",
	"switch", "catch", "try", "finally", "do", "guard", "fn", "func", "function",
	"def", "class", "struct", "enum", "trait", "impl", "mod", "namespace",
	"package", "init", "deinit", "sub", "begin",
)

// braceBlockIsIfBody reports whether the "{" at open belongs to an if/elif
// condition body, by scanning backwards for the controlling keyword.
func braceBlockIsIfBody(tokens []braceLanguageToken, match map[int]int, open int) bool {
	for j := open - 1; j >= 0; j-- {
		text := tokens[j].text
		switch text {
		case ";", "{", "}":
			return false
		case ")", "]":
			if opener, ok := match[j]; ok {
				j = opener
				continue
			}
		}
		if braceBlockOwners[text] {
			return text == "if" || text == "elif"
		}
	}
	return false
}

// braceElseAfterReturnFindings flags "else"/"elseif" branches whose preceding
// if-body always terminates, making the else nesting unnecessary.
func braceElseAfterReturnFindings(file string, tokens []braceLanguageToken, added map[int]bool, terminators map[string]bool) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	match := braceMatchMap(tokens)
	for i, tok := range tokens {
		if tok.text != "else" && tok.text != "elseif" {
			continue
		}
		if i == 0 || tokens[i-1].text != "}" {
			continue
		}
		closeIdx := i - 1
		open, ok := match[closeIdx]
		if !ok || open < 0 || !braceBlockIsIfBody(tokens, match, open) {
			continue
		}
		start := lastBraceStatementStart(tokens, open+1, closeIdx)
		if start < 0 || start >= closeIdx || !terminators[tokens[start].text] {
			continue
		}
		if added[tok.line] {
			appendSlopFinding(&findings, seen, file, tok.line, "Else branch after a terminating statement", "Dedent the else body; it can follow the if directly because the if body always exits.")
		}
	}
	return findings
}

// lastBraceStatementStart returns the index of the first token of the last
// top-level statement within tokens[from:to].
func lastBraceStatementStart(tokens []braceLanguageToken, from, to int) int {
	depth := 0
	stmtStart := from
	last := -1
	for i := from; i < to; i++ {
		switch tokens[i].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		}
		if depth != 0 || tokens[i].text != ";" {
			continue
		}
		s := stmtStart
		for s < i && tokens[s].text == ";" {
			s++
		}
		if s < i {
			last = s
		}
		stmtStart = i + 1
	}
	s := stmtStart
	for s < to && tokens[s].text == ";" {
		s++
	}
	if s < to {
		return s
	}
	return last
}

// braceDeadCodeFindings flags statements that follow a terminating statement
// within the same brace-delimited block.
func braceDeadCodeFindings(file string, tokens []braceLanguageToken, added map[int]bool, terminators map[string]bool) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	match := braceMatchMap(tokens)
	openToClose := make(map[int]int, len(match))
	for closeIdx, openIdx := range match {
		if tokens[closeIdx].text == "}" {
			openToClose[openIdx] = closeIdx
		}
	}
	nonStatement := wordSet("else", "catch", "finally", "while", "case", "default", "elif", "except")
	for open := 0; open < len(tokens); open++ {
		if tokens[open].text != "{" {
			continue
		}
		closeIdx, ok := openToClose[open]
		if !ok {
			continue
		}
		depth := 0
		stmtStart := open + 1
		prevTerminated := false
		reported := false
		for i := open + 1; i < closeIdx; i++ {
			text := tokens[i].text
			switch text {
			case "(", "[", "{":
				depth++
			case ")", "]", "}":
				depth--
			}
			if depth != 0 {
				continue
			}
			if text != ";" && text != "}" {
				continue
			}
			first := stmtStart
			for first < i && tokens[first].text == ";" {
				first++
			}
			if first >= i {
				stmtStart = i + 1
				continue
			}
			keyword := tokens[first].text
			if prevTerminated && !nonStatement[keyword] && !reported {
				if added[tokens[first].line] {
					appendSlopFinding(&findings, seen, file, tokens[first].line, "Unreachable code after terminating statement", "Remove the dead code or restructure the control flow.")
					reported = true
				}
			}
			prevTerminated = terminators[keyword]
			stmtStart = i + 1
		}
	}
	return findings
}

// braceBoolChainFindings flags boolean operator chains with 5+ operators.
func braceBoolChainFindings(file string, tokens []braceLanguageToken, added map[int]bool, ops map[string]bool) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	count := 0
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		switch tok.text {
		case ";", "{", "}", ",":
			count = 0
			continue
		}
		op := tok.text
		if (op == "&" || op == "|") && i+1 < len(tokens) && tokens[i+1].text == op {
			op += op
			i++
		}
		if !ops[op] {
			continue
		}
		count++
		if count >= 5 {
			if added[tok.line] {
				appendSlopFinding(&findings, seen, file, tok.line, "Long boolean operator chain (5+ operators)", "Extract the condition into a named variable or split it into smaller checks.")
			}
			count = 0
		}
	}
	return findings
}

// braceNonStrictEqualityFindings flags "=="/"!=" comparisons in languages
// where a strict variant exists, excluding the common == null idiom.
func braceNonStrictEqualityFindings(file, remediation string, tokens []braceLanguageToken, added map[int]bool) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	loose := wordSet("null", "undefined", "void", "NULL")
	for i := 1; i+1 < len(tokens); i++ {
		if tokens[i].text != "==" && tokens[i].text != "!=" {
			continue
		}
		if loose[tokens[i-1].text] || loose[tokens[i+1].text] {
			continue
		}
		line, ok := comparisonAddedLine(tokens, i, added)
		if !ok {
			continue
		}
		appendSlopFinding(&findings, seen, file, line, "Non-strict equality comparison", remediation)
	}
	return findings
}

var slopLogCalls = wordSet("console", "log", "logger", "print", "println", "debug", "trace")

// braceSwallowedExceptionFindings flags catch blocks whose only statement is
// a logging call, which typically hides errors.
func braceSwallowedExceptionFindings(file string, tokens []braceLanguageToken, added map[int]bool) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	match := braceMatchMap(tokens)
	openToClose := make(map[int]int, len(match))
	for closeIdx, openIdx := range match {
		openToClose[openIdx] = closeIdx
	}
	for i, tok := range tokens {
		if tok.text != "catch" {
			continue
		}
		j := i + 1
		if j < len(tokens) && tokens[j].text == "(" {
			if close, ok := openToClose[j]; ok {
				j = close + 1
			}
		}
		if j >= len(tokens) || tokens[j].text != "{" {
			continue
		}
		closeIdx, ok := openToClose[j]
		if !ok || !catchBlockOnlyLogs(tokens, j+1, closeIdx) {
			continue
		}
		if added[tok.line] {
			appendSlopFinding(&findings, seen, file, tok.line, "Exception swallowed by log-only catch", "Handle the error meaningfully or document why logging is sufficient.")
		}
	}
	return findings
}

// catchBlockOnlyLogs reports whether the brace block contains exactly one
// top-level statement that is a call to a logging function.
func catchBlockOnlyLogs(tokens []braceLanguageToken, from, to int) bool {
	depth := 0
	stmtStart := from
	statements := 0
	first := -1
	for i := from; i <= to; i++ {
		if i == to || ((tokens[i].text == ";" || tokens[i].text == "}") && depth == 0) {
			s := stmtStart
			for s < i && tokens[s].text == ";" {
				s++
			}
			if s < i {
				statements++
				if first < 0 {
					first = s
				}
			}
			stmtStart = i + 1
			continue
		}
		switch tokens[i].text {
		case "(", "[", "{":
			depth++
		case ")", "]", "}":
			depth--
		}
	}
	if statements != 1 || first < 0 {
		return false
	}
	name := tokens[first].text
	if !slopLogCalls[name] {
		return false
	}
	// The lexer drops "." tokens, so "console.error(" appears as
	// console, error, ( — accept a call or a method-name identifier next.
	if first+1 >= len(tokens) {
		return false
	}
	next := tokens[first+1].text
	return next == "(" || len(next) > 0 && isSourceIdentStart(next[0])
}

func braceFlowFindings(file, name string, tokens []braceLanguageToken, added map[int]bool) []Finding {
	terminators := flowTerminators(name)
	var findings []Finding
	findings = append(findings, braceElseAfterReturnFindings(file, tokens, added, terminators)...)
	findings = append(findings, braceDeadCodeFindings(file, tokens, added, terminators)...)
	findings = append(findings, braceBoolChainFindings(file, tokens, added, braceBoolOperators(name))...)
	return findings
}

var pythonTerminator = wordSet("return", "raise", "break", "continue")

func isPythonTerminatorStatement(code string) bool {
	fields := strings.Fields(code)
	return len(fields) > 0 && pythonTerminator[fields[0]]
}
