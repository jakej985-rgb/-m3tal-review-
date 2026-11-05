package slop

import (
	"fmt"
	"strings"
)

type braceLanguageConfig struct {
	name                  string
	controls              map[string]bool
	directBlocks          map[string]bool
	optionalParen         bool
	boolLiterals          map[string]bool
	phpComments           bool
	phpAltSyntax          bool
	tripleStrings         bool
	rustRawStrings        bool
	nestedBlockComments   bool
	cppRawStrings         bool
	csharpVerbatimStrings bool
	csharpRawStrings      bool
	swiftRawStrings       bool
	phpHeredoc            bool
	preprocessor          bool
	depthBlocks           map[string]bool
	allowUnbracedBodies   bool
	cppIfModifiers        bool
	javaTryResources      bool
	swiftRegexLiterals    bool
	csharpInterpolation   bool
	kotlinInterpolation   bool
	swiftInterpolation    bool
	phpInterpolation      bool
	rustLetPatterns       bool
	strictBoolOperators   bool
}

type braceLanguageToken struct {
	text             string
	line, start, end int
}

func wordSet(words ...string) map[string]bool {
	set := make(map[string]bool, len(words))
	for _, word := range words {
		set[word] = true
	}
	return set
}

func analyzeBraceLanguage(file, source string, added map[int]bool, cfg braceLanguageConfig) []Finding {
	if cfg.preprocessor {
		variants, err := preprocessorVariants(source)
		if err != nil {
			return []Finding{{Rule: "code-slop-analysis-error", Severity: "high", File: file, Line: 0, Message: "Could not safely analyze " + cfg.name + " preprocessor branches: " + err.Error(), Remediation: "Simplify conditional compilation or review each build configuration separately."}}
		}
		cfg.preprocessor = false
		var findings []Finding
		seen := make(map[string]bool)
		for _, variant := range variants {
			for _, finding := range analyzeBraceLanguage(file, variant, added, cfg) {
				appendSlopFinding(&findings, seen, file, finding.Line, finding.Message, finding.Remediation)
			}
		}
		return findings
	}
	if cfg.phpComments {
		source = maskPHPOutsideTags(source)
	}
	tokens := lexBraceLanguage(source, cfg)
	if err := braceLanguageStructureError(tokens); err != nil {
		return []Finding{{Rule: "code-slop-analysis-error", Severity: "high", File: file, Line: 0, Message: "Could not safely analyze " + cfg.name + " structure: " + err.Error(), Remediation: "Fix mismatched braces or delimiters, then rerun the review."}}
	}
	controlOpen := make(map[int]braceControl)
	altStarts, altEnds := map[int]int{}, map[int]bool{}
	if cfg.phpAltSyntax {
		var err error
		altStarts, altEnds, err = phpAlternativeSyntax(tokens)
		if err != nil {
			return []Finding{{Rule: "code-slop-analysis-error", Severity: "high", File: file, Line: 0, Message: "Could not safely analyze PHP structure: " + err.Error(), Remediation: "Fix alternate-syntax control blocks, then rerun the review."}}
		}
	}
	for i, tok := range tokens {
		if cfg.controls[tok.text] && !isDoWhileTrailer(tokens, i) {
			start := i + 1
			if cfg.cppIfModifiers && tok.text == "if" && start < len(tokens) && tokens[start].text == "consteval" {
				if start+1 < len(tokens) && tokens[start+1].text == "{" {
					controlOpen[start+1] = braceControl{line: tok.line, addDepth: true}
				}
				continue
			}
			if cfg.cppIfModifiers && tok.text == "if" && start+2 < len(tokens) && tokens[start].text == "!" && tokens[start+1].text == "consteval" {
				if tokens[start+2].text == "{" {
					controlOpen[start+2] = braceControl{line: tok.line, addDepth: true}
				}
				continue
			}
			if cfg.cppIfModifiers && tok.text == "if" && start < len(tokens) && tokens[start].text == "constexpr" {
				start++
			}
			if !cfg.optionalParen && start < len(tokens) && tokens[start].text != "(" {
				return []Finding{{Rule: "code-slop-analysis-error", Severity: "high", File: file, Line: 0, Message: "Could not safely analyze " + cfg.name + " structure: expected a parenthesized " + tok.text + " condition on line " + fmt.Sprint(tok.line), Remediation: "Fix the control statement syntax, then rerun the review."}}
			}
			if open := findLanguageBody(tokens, start, cfg.optionalParen, cfg.rustLetPatterns); open >= 0 {
				controlOpen[open] = braceControl{line: tok.line, addDepth: true}
			}
		}
		if cfg.directBlocks[tok.text] && i+1 < len(tokens) {
			open := i + 1
			if cfg.javaTryResources && tok.text == "try" && tokens[open].text == "(" {
				open = closingDelimiter(tokens, open, "(", ")") + 1
			}
			if open < len(tokens) && tokens[open].text == "{" {
				controlOpen[open] = braceControl{line: tok.line, addDepth: cfg.depthBlocks[tok.text]}
			}
		}
	}
	unbracedStarts, unbracedEnds := map[int]int{}, map[int]int{}
	if cfg.allowUnbracedBodies {
		unbracedStarts, unbracedEnds = languageUnbracedNesting(tokens, cfg)
	}
	scopeOpen := findFunctionScopeBlocks(tokens, controlOpen)
	var findings []Finding
	seen := make(map[string]bool)
	type braceFrame struct {
		counted            bool
		scope              bool
		parentDepth        int
		parentDeepReported bool
	}
	var stack []braceFrame
	depth := 0
	deepReported := false
	for i, tok := range tokens {
		if depth < 4 {
			deepReported = false
		}
		if cfg.phpAltSyntax && (tok.text == "else" || tok.text == "elseif") && i+2 < len(tokens) && tokens[i+1].text == ":" && (isPHPAlternativeEnd(tokens[i+2].text) || tokens[i+2].text == "else" || tokens[i+2].text == "elseif") && added[tok.line] {
			appendSlopFinding(&findings, seen, file, tok.line, "Empty block", "Remove the empty block or add an explanatory comment.")
		}
		if line, ok := altStarts[i]; ok {
			depth++
			if depth >= 4 && added[line] && !deepReported {
				appendSlopFinding(&findings, seen, file, line, "Excessive syntax nesting depth (4+ levels)", "Refactor to reduce nesting depth.")
				deepReported = true
			}
			if i+1 < len(tokens) && (tokens[i+1].text == "else" || tokens[i+1].text == "elseif" || isPHPAlternativeEnd(tokens[i+1].text)) && added[line] {
				appendSlopFinding(&findings, seen, file, line, "Empty block", "Remove the empty block or add an explanatory comment.")
			}
		}
		if altEnds[i] {
			depth--
		}
		if line, ok := unbracedStarts[i]; ok {
			depth++
			if depth >= 4 && added[line] && !deepReported {
				appendSlopFinding(&findings, seen, file, line, "Excessive syntax nesting depth (4+ levels)", "Refactor to reduce nesting depth.")
				deepReported = true
			}
		}
		if added[tok.line] && depth >= 4 && !deepReported {
			appendSlopFinding(&findings, seen, file, tok.line, "Excessive syntax nesting depth (4+ levels)", "Refactor to reduce nesting depth.")
			deepReported = true
		}
		switch tok.text {
		case "{":
			control, isControl := controlOpen[i]
			scope := scopeOpen[i]
			frame := braceFrame{counted: isControl && control.addDepth, scope: scope}
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
			if control.addDepth {
				depth++
			}
			if control.addDepth && depth >= 4 && added[control.line] && !deepReported {
				appendSlopFinding(&findings, seen, file, control.line, "Excessive syntax nesting depth (4+ levels)", "Refactor to reduce nesting depth.")
				deepReported = true
			}
			if i+1 < len(tokens) && tokens[i+1].text == "}" && added[control.line] && strings.TrimSpace(source[tok.end:tokens[i+1].start]) == "" {
				appendSlopFinding(&findings, seen, file, control.line, "Empty block", "Remove the empty block or add an explanatory comment.")
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
	for i := 1; i+1 < len(tokens); i++ {
		findingLine, comparisonAdded := comparisonAddedLine(tokens, i, added)
		if !isBooleanComparisonOperator(tokens[i].text, cfg) || !comparisonAdded {
			continue
		}
		if cfg.strictBoolOperators && (tokens[i].text == "==" || tokens[i].text == "!=" || tokens[i].text == "<>") {
			continue
		}
		if (cfg.name == "C" || cfg.name == "C++") && (tokens[i].text == "==" || tokens[i].text == "!=") && !hasTypedCBoolOperand(tokens, i, cfg.name == "C++") {
			continue
		}
		if isBooleanOperand(tokens, i-1, true, cfg.boolLiterals) || isBooleanOperand(tokens, i+1, false, cfg.boolLiterals) {
			message, remediation := booleanComparisonAdvice(cfg.name)
			appendSlopFinding(&findings, seen, file, findingLine, message, remediation)
		}
	}
	findings = append(findings, braceFlowFindings(file, cfg.name, tokens, added)...)
	return findings
}

func isBooleanComparisonOperator(operator string, cfg braceLanguageConfig) bool {
	return operator == "==" || operator == "===" || operator == "!=" || operator == "!==" || cfg.phpComments && operator == "<>"
}

func booleanComparisonAdvice(languageName string) (string, string) {
	switch languageName {
	case "JavaScript", "TypeScript", "PHP":
		return "Redundant boolean comparison", "Only remove this comparison when the operand is guaranteed to be boolean; otherwise the comparison can change behavior."
	default:
		return "Redundant boolean comparison", "Remove the explicit comparison to a boolean literal."
	}
}

func hasTypedCBoolOperand(tokens []braceLanguageToken, operator int, cppAutoInference bool) bool {
	if isBooleanOperand(tokens, operator-1, true, wordSet("true", "false")) && isBooleanOperand(tokens, operator+1, false, wordSet("true", "false")) {
		return true
	}
	var identifier string
	if isBooleanOperand(tokens, operator-1, true, wordSet("true", "false")) {
		identifier = simpleComparisonIdentifier(tokens, operator+1, true)
	} else if isBooleanOperand(tokens, operator+1, false, wordSet("true", "false")) {
		identifier = simpleComparisonIdentifier(tokens, operator-1, false)
	}
	if identifier == "" {
		return false
	}
	types := wordSet("bool", "_Bool", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "auto")
	qualifiers := wordSet("const", "volatile", "restrict")
	declarations, scalarBoolDeclarations := 0, 0
	for index := 1; index < len(tokens); index++ {
		if tokens[index].text != identifier {
			continue
		}
		typeIndex := index - 1
		for typeIndex >= 0 && qualifiers[tokens[typeIndex].text] {
			typeIndex--
		}
		if typeIndex < 0 || !types[tokens[typeIndex].text] {
			continue
		}
		declarations++
		pointerDeclaration := false
		for between := typeIndex + 1; between < index; between++ {
			if tokens[between].text == "*" {
				pointerDeclaration = true
				break
			}
		}
		explicitBool := tokens[typeIndex].text == "bool" || tokens[typeIndex].text == "_Bool"
		autoBool := cppAutoInference && tokens[typeIndex].text == "auto" && autoBoolInitializer(tokens, index)
		if (explicitBool || autoBool) && !pointerDeclaration {
			scalarBoolDeclarations++
		}
	}
	// Name-based type inference is only safe when the file has one recognizable
	// declaration for the name. Multiple declarations can be shadows in different
	// scopes, and pointer declarations are not scalar boolean values. C++
	// references remain eligible because they refer to a scalar bool value.
	return declarations == 1 && scalarBoolDeclarations == 1
}

func autoBoolInitializer(tokens []braceLanguageToken, identifier int) bool {
	if identifier+2 < len(tokens) && tokens[identifier+1].text == "=" {
		return tokens[identifier+2].text == "true" || tokens[identifier+2].text == "false"
	}
	if identifier+3 < len(tokens) && tokens[identifier+1].text == "{" && tokens[identifier+3].text == "}" {
		return tokens[identifier+2].text == "true" || tokens[identifier+2].text == "false"
	}
	return false
}

func simpleComparisonIdentifier(tokens []braceLanguageToken, index int, right bool) string {
	if index < 0 || index >= len(tokens) {
		return ""
	}
	start, end := index, index
	if right && tokens[index].text == "(" {
		if close := matchingLanguageParen(tokens, index, true); close >= 0 {
			end = close
		}
	} else if !right && tokens[index].text == ")" {
		if open := matchingLanguageParen(tokens, index, false); open >= 0 {
			start = open
		}
	}
	for start < end && tokens[start].text == "(" && matchingLanguageParen(tokens, start, true) == end {
		start++
		end--
	}
	if start == end && tokens[start].text != "" && isSourceIdentStart(tokens[start].text[0]) {
		return tokens[start].text
	}
	return ""
}

func maskPHPOutsideTags(source string) string {
	masked := []byte(source)
	_, found := nextPHPOpenTag(source, 0)
	if !found {
		if hasXMLProlog(source) {
			maskSourceLine(masked, 0, len(source))
			return string(masked)
		}
		return source // Permit diff fragments that contain only PHP code.
	}
	active := false
	for i := 0; i < len(source); {
		if !active {
			start, ok := nextPHPOpenTag(source, i)
			if !ok {
				maskSourceLine(masked, i, len(source))
				break
			}
			maskSourceLine(masked, i, start)
			i = start + 2
			if strings.HasPrefix(strings.ToLower(source[start:]), "<?php") {
				i = start + 5
			} else if i < len(source) && source[i] == '=' {
				i++
			}
			active = true
			continue
		}
		end := strings.Index(source[i:], "?>")
		if end < 0 {
			break
		}
		end += i
		maskSourceLine(masked, end, end+2)
		i = end + 2
		active = false
	}
	return string(masked)
}

func hasXMLProlog(source string) bool {
	source = strings.TrimPrefix(source, "\uFEFF")
	source = strings.TrimLeft(source, " \t\r\n")
	return strings.HasPrefix(source, "<?xml")
}

func nextPHPOpenTag(source string, from int) (int, bool) {
	for from < len(source) {
		relative := strings.Index(source[from:], "<?")
		if relative < 0 {
			return 0, false
		}
		start := from + relative
		if !strings.HasPrefix(strings.ToLower(source[start:]), "<?xml") {
			return start, true
		}
		from = start + 5
	}
	return 0, false
}

func comparisonAddedLine(tokens []braceLanguageToken, operator int, added map[int]bool) (int, bool) {
	start, end := operator-1, operator+1
	if start >= 0 && tokens[start].text == ")" {
		if open := matchingLanguageParen(tokens, start, false); open >= 0 {
			start = open
		}
	}
	if end < len(tokens) && tokens[end].text == "(" {
		if close := matchingLanguageParen(tokens, end, true); close >= 0 {
			end = close
		}
	}
	for index := start; index <= end; index++ {
		if index >= 0 && index < len(tokens) && added[tokens[index].line] {
			return tokens[index].line, true
		}
	}
	return 0, false
}

func findFunctionBody(tokens []braceLanguageToken, start int) int {
	paren, bracket := 0, 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			paren++
		case ")":
			paren--
		case "[":
			bracket++
		case "]":
			bracket--
		case ";":
			if paren == 0 && bracket == 0 {
				return -1
			}
		case "{":
			if paren == 0 && bracket == 0 {
				return i
			}
		}
	}
	return -1
}

func findFunctionScopeBlocks(tokens []braceLanguageToken, controls map[int]braceControl) map[int]bool {
	scopes := make(map[int]bool)
	for i, token := range tokens {
		if token.text == "function" {
			if open := findFunctionBody(tokens, i+1); open >= 0 {
				scopes[open] = true
			}
		}
		if token.text == "=>" && i+1 < len(tokens) && tokens[i+1].text == "{" {
			scopes[i+1] = true
		}
	}
	for open, token := range tokens {
		if token.text != "{" || controls[open].line != 0 || open == 0 || tokens[open-1].text != ")" {
			continue
		}
		paren := matchingLanguageParen(tokens, open-1, false)
		if paren <= 0 {
			continue
		}
		name := tokens[paren-1].text
		switch name {
		case "if", "for", "foreach", "while", "switch", "catch", "synchronized", "using", "lock", "with":
			continue
		}
		scopes[open] = true
	}
	return scopes
}

func preprocessorVariants(source string) ([]string, error) {
	lines := strings.SplitAfter(source, "\n")
	index := 0
	variants, stop, err := expandPreprocessorSequence(lines, &index, map[string]bool{})
	if err != nil {
		return nil, err
	}
	if stop != "" {
		return nil, fmt.Errorf("unexpected %s directive", stop)
	}
	if len(variants) == 0 {
		return []string{source}, nil
	}
	return variants, nil
}

func expandPreprocessorSequence(lines []string, index *int, stopAt map[string]bool) ([]string, string, error) {
	variants := []string{""}
	for *index < len(lines) {
		directive, expression, afterDirective, directiveLines := parsePreprocessorDirectiveAt(lines, *index)
		if stopAt[directive] {
			return variants, directive, nil
		}
		if directive != "#if" && directive != "#ifdef" && directive != "#ifndef" {
			if directive != "" {
				var masked strings.Builder
				writeMaskedDirective(&masked, lines, directiveLines)
				line := masked.String()
				for i := range variants {
					variants[i] += line
				}
				*index = afterDirective
				continue
			}
			for i := range variants {
				variants[i] += lines[*index]
			}
			*index = afterDirective
			continue
		}
		blockStartLines := directiveLines
		*index = afterDirective
		branches := make([][]string, 0, 3)
		branchStarts := make([]int, 0, 3)
		branchEnds := make([]int, 0, 3)
		branchDirectives := make([][]int, 0, 3)
		conditions := []int{preprocessorCondition(directive, expression)} // -1 false, 0 unknown, +1 true
		hasElse := false
		stop := ""
		var endifLines []int
		for {
			branchStarts = append(branchStarts, *index)
			body, bodyStop, err := expandPreprocessorSequence(lines, index, map[string]bool{"#elif": true, "#elseif": true, "#else": true, "#endif": true})
			if err != nil {
				return nil, "", err
			}
			branches = append(branches, body)
			branchEnds = append(branchEnds, *index)
			stop = bodyStop
			if stop == "#elif" || stop == "#elseif" {
				_, expression, afterDirective, directiveLines = parsePreprocessorDirectiveAt(lines, *index)
				branchDirectives = append(branchDirectives, directiveLines)
				conditions = append(conditions, preprocessorCondition(stop, expression))
				*index = afterDirective
				continue
			}
			if stop == "#else" {
				hasElse = true
				_, _, afterDirective, directiveLines = parsePreprocessorDirectiveAt(lines, *index)
				branchDirectives = append(branchDirectives, directiveLines)
				conditions = append(conditions, 0)
				*index = afterDirective
				branchStarts = append(branchStarts, *index)
				body, stop, err = expandPreprocessorSequence(lines, index, map[string]bool{"#endif": true})
				if err != nil {
					return nil, "", err
				}
				branches = append(branches, body)
				branchEnds = append(branchEnds, *index)
			}
			if stop != "#endif" {
				return nil, "", fmt.Errorf("unterminated conditional directive")
			}
			_, _, afterDirective, endifLines = parsePreprocessorDirectiveAt(lines, *index)
			*index = afterDirective
			break
		}
		choices := make([]int, 0, len(branches)+1)
		canReach := true
		for branch, condition := range conditions {
			if !canReach {
				break
			}
			if condition >= 0 {
				choices = append(choices, branch)
			}
			if condition > 0 {
				canReach = false
			}
		}
		if canReach && !hasElse {
			choices = append(choices, -1)
		}
		combined := make([]string, 0, len(variants)*maxInt(1, len(choices)))
		for _, prefix := range variants {
			for _, choice := range choices {
				selectedBodies := []string{""}
				if choice >= 0 {
					selectedBodies = branches[choice]
				}
				for _, selectedBody := range selectedBodies {
					var block strings.Builder
					writeMaskedDirective(&block, lines, blockStartLines)
					for branch := range branches {
						if branch == choice {
							block.WriteString(selectedBody)
						} else {
							for lineIndex := branchStarts[branch]; lineIndex < branchEnds[branch]; lineIndex++ {
								block.WriteString(maskDirective(lines[lineIndex]))
							}
						}
						if branch < len(branchDirectives) {
							writeMaskedDirective(&block, lines, branchDirectives[branch])
						}
					}
					writeMaskedDirective(&block, lines, endifLines)
					combined = append(combined, prefix+block.String())
					if len(combined) > 64 {
						return nil, "", fmt.Errorf("conditional source expands to more than 64 build variants")
					}
				}
			}
		}
		variants = combined
	}
	return variants, "", nil
}

func parsePreprocessorDirective(line string) (string, string) {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "#") {
		return "", ""
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", ""
	}
	return fields[0], strings.TrimSpace(strings.TrimPrefix(trimmed, fields[0]))
}

func parsePreprocessorDirectiveAt(lines []string, start int) (string, string, int, []int) {
	directive, expression := parsePreprocessorDirective(lines[start])
	lineIndexes := []int{start}
	for strings.HasSuffix(strings.TrimRight(lines[start], " \t\r\n"), "\\") && start+1 < len(lines) {
		expression = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expression), "\\"))
		start++
		lineIndexes = append(lineIndexes, start)
		continued := strings.TrimSpace(lines[start])
		if strings.HasSuffix(continued, "\\") {
			continued = strings.TrimSpace(strings.TrimSuffix(continued, "\\"))
		}
		expression += " " + continued
		if !strings.HasSuffix(strings.TrimRight(lines[start], " \t\r\n"), "\\") {
			break
		}
	}
	return directive, expression, start + 1, lineIndexes
}

func writeMaskedDirective(builder *strings.Builder, lines []string, indexes []int) {
	for _, index := range indexes {
		builder.WriteString(maskDirective(lines[index]))
	}
}

func preprocessorCondition(directive, expression string) int {
	if directive == "#ifdef" || directive == "#ifndef" {
		return 0
	}
	switch strings.ToLower(strings.TrimSpace(expression)) {
	case "0", "false":
		return -1
	case "1", "true":
		return 1
	default:
		return 0
	}
}

func maskDirective(line string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		return ' '
	}, line)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maskSourceLine(source []byte, start, end int) {
	for i := start; i < end; i++ {
		source[i] = ' '
	}
}

func phpAlternativeSyntax(tokens []braceLanguageToken) (map[int]int, map[int]bool, error) {
	starts, ends := map[int]int{}, map[int]bool{}
	type block struct {
		end  string
		line int
	}
	var stack []block
	for i, token := range tokens {
		switch token.text {
		case "if", "for", "foreach", "while", "switch":
			if colon := phpAlternativeColon(tokens, i+1); colon >= 0 {
				starts[colon] = token.line
				end := map[string]string{"if": "endif", "for": "endfor", "foreach": "endforeach", "while": "endwhile", "switch": "endswitch"}[token.text]
				stack = append(stack, block{end: end, line: token.line})
			}
		case "endif", "endfor", "endforeach", "endwhile", "endswitch":
			if len(stack) == 0 || stack[len(stack)-1].end != token.text {
				return nil, nil, fmt.Errorf("unexpected %s on line %d", token.text, token.line)
			}
			ends[i] = true
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) > 0 {
		block := stack[len(stack)-1]
		return nil, nil, fmt.Errorf("expected %s to close block started on line %d", block.end, block.line)
	}
	return starts, ends, nil
}

func phpAlternativeColon(tokens []braceLanguageToken, start int) int {
	if start >= len(tokens) || tokens[start].text != "(" {
		return -1
	}
	depth := 0
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 && i+1 < len(tokens) && tokens[i+1].text == ":" {
				return i + 1
			}
		}
	}
	return -1
}

func isPHPAlternativeEnd(token string) bool {
	switch token {
	case "endif", "endfor", "endforeach", "endwhile", "endswitch":
		return true
	default:
		return false
	}
}

func braceAnalyzer(r SlopRule, file string, added []int, cfg braceLanguageConfig) []Finding {
	source, err := r.readSourceForAnalysis(file)
	if err != nil {
		return r.analysisReadError(file, err)
	}
	return analyzeBraceLanguage(file, string(source), addedLineMap(added), cfg)
}

func findLanguageBody(tokens []braceLanguageToken, start int, optionalParen, rustLetPatterns bool) int {
	if start >= len(tokens) {
		return -1
	}
	if !optionalParen {
		if tokens[start].text != "(" {
			return -1
		}
		depth := 0
		for i := start; i < len(tokens); i++ {
			if tokens[i].text == "(" {
				depth++
			} else if tokens[i].text == ")" {
				depth--
				if depth == 0 {
					if i+1 < len(tokens) && tokens[i+1].text == "{" {
						return i + 1
					}
					return -1
				}
			}
		}
		return -1
	}
	// Kotlin, Rust, and Swift normally put conditions in parentheses (Rust
	// also permits `if let pattern = value {`). If a parenthesized condition
	// has no immediately following block, it is an unbraced body; never scan
	// forward and accidentally attach a later function's block to it.
	if tokens[start].text == "(" {
		if close := closingDelimiter(tokens, start, "(", ")"); close >= 0 && close+1 < len(tokens) && tokens[close+1].text == "{" {
			return close + 1
		}
		return -1
	}
	paren, bracket, brace := 0, 0, 0
	seenAssignment := false
	skipPatternBraces := rustLetPatterns && tokens[start].text == "let"
	for i := start; i < len(tokens); i++ {
		switch tokens[i].text {
		case "(":
			paren++
		case ")":
			paren--
		case "[":
			bracket++
		case "]":
			bracket--
		case "=":
			if paren == 0 && bracket == 0 && brace == 0 {
				seenAssignment = true
			}
		case ";", "=>":
			if paren <= 0 && bracket <= 0 {
				return -1
			}
		case "{":
			if paren <= 0 && bracket <= 0 {
				if brace == 0 && skipPatternBraces && !seenAssignment {
					if close := closingDelimiter(tokens, i, "{", "}"); close >= 0 {
						i = close
						continue
					}
				}
				if brace == 0 {
					return i
				}
				brace++
			} else {
				brace++
			}
		case "}":
			if brace > 0 {
				brace--
			}
		}
	}
	return -1
}

func isDoWhileTrailer(tokens []braceLanguageToken, index int) bool {
	if index == 0 || tokens[index].text != "while" {
		return false
	}
	if tokens[index-1].text == "}" {
		open := matchingBrace(tokens, index-1)
		return open > 0 && tokens[open-1].text == "do"
	}
	if tokens[index-1].text == ";" {
		for i := index - 2; i >= 0; i-- {
			switch tokens[i].text {
			case "do":
				return true
			case ";", "{", "}":
				return false
			}
		}
	}
	return false
}

func matchingBrace(tokens []braceLanguageToken, close int) int {
	depth := 0
	for i := close; i >= 0; i-- {
		switch tokens[i].text {
		case "}":
			depth++
		case "{":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func closingDelimiter(tokens []braceLanguageToken, start int, open, close string) int {
	if start < 0 || start >= len(tokens) || tokens[start].text != open {
		return -1
	}
	depth := 0
	for i := start; i < len(tokens); i++ {
		if tokens[i].text == open {
			depth++
		} else if tokens[i].text == close {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// languageUnbracedNesting records control statements whose bodies are another
// statement instead of a brace block. The parser intentionally handles only
// statement boundaries needed for nesting attribution, not full syntax.
func languageUnbracedNesting(tokens []braceLanguageToken, cfg braceLanguageConfig) (map[int]int, map[int]int) {
	starts, ends := map[int]int{}, map[int]int{}
	cache := make(map[int]int)
	visiting := make(map[int]bool)
	var parseStatement func(int) int
	var parseControl func(int) int

	parseControl = func(index int) int {
		if end, ok := cache[index]; ok {
			return end
		}
		if visiting[index] {
			return index
		}
		visiting[index] = true
		headerEnd := index
		start := index + 1
		if tokens[index].text == "do" {
			headerEnd = index
		} else if cfg.cppIfModifiers && tokens[index].text == "if" && start+1 < len(tokens) && tokens[start].text == "!" && tokens[start+1].text == "consteval" {
			headerEnd = start + 1
		} else if cfg.cppIfModifiers && tokens[index].text == "if" && start < len(tokens) && tokens[start].text == "constexpr" {
			start++
		}
		if tokens[index].text == "do" {
			// `do` has no header; its single following statement is the body.
		} else if cfg.cppIfModifiers && tokens[index].text == "if" && start+1 < len(tokens) && tokens[start].text == "!" && tokens[start+1].text == "consteval" {
			headerEnd = start + 1
		} else if start < len(tokens) && tokens[start].text == "consteval" {
			headerEnd = start
		} else if !cfg.optionalParen {
			if close := closingDelimiter(tokens, start, "(", ")"); close >= 0 {
				headerEnd = close
			} else {
				delete(visiting, index)
				cache[index] = index
				return index
			}
		} else if start < len(tokens) && tokens[start].text == "(" {
			if close := closingDelimiter(tokens, start, "(", ")"); close >= 0 {
				headerEnd = close
			} else {
				delete(visiting, index)
				cache[index] = index
				return index
			}
		} else {
			for i := start; i < len(tokens); i++ {
				if tokens[i].text == "{" {
					headerEnd = i - 1
					break
				}
			}
		}
		bodyStart := headerEnd + 1
		if bodyStart >= len(tokens) {
			delete(visiting, index)
			cache[index] = len(tokens) - 1
			return len(tokens) - 1
		}
		bodyEnd := parseStatement(bodyStart)
		if tokens[bodyStart].text != "{" {
			starts[index] = tokens[index].line
			ends[bodyEnd]++
		}
		end := bodyEnd
		if tokens[index].text == "do" && end+1 < len(tokens) && tokens[end+1].text == "while" {
			if close := closingDelimiter(tokens, end+2, "(", ")"); close >= 0 {
				end = close
			}
		}
		if tokens[index].text == "if" && end+1 < len(tokens) && tokens[end+1].text == "else" {
			elseStart := end + 2
			if elseStart < len(tokens) {
				end = parseStatement(elseStart)
			}
		}
		delete(visiting, index)
		cache[index] = end
		return end
	}

	parseStatement = func(start int) int {
		if start >= len(tokens) {
			return len(tokens) - 1
		}
		if tokens[start].text == "{" {
			if close := closingDelimiter(tokens, start, "{", "}"); close >= 0 {
				return close
			}
			return len(tokens) - 1
		}
		if (cfg.controls[tokens[start].text] || cfg.depthBlocks[tokens[start].text]) && !isDoWhileTrailer(tokens, start) {
			return parseControl(start)
		}
		paren, bracket, brace := 0, 0, 0
		for i := start; i < len(tokens); i++ {
			switch tokens[i].text {
			case "(":
				paren++
			case ")":
				paren--
			case "[":
				bracket++
			case "]":
				bracket--
			case "{":
				brace++
			case "}":
				if brace == 0 {
					return i - 1
				}
				brace--
			case ";":
				if paren == 0 && bracket == 0 && brace == 0 {
					return i
				}
			}
			if i > start && tokens[i].line > tokens[i-1].line && paren == 0 && bracket == 0 && brace == 0 && !languageStatementContinues(tokens[i-1].text, tokens[i].text) {
				return i - 1
			}
		}
		return len(tokens) - 1
	}

	for i, tok := range tokens {
		if (cfg.controls[tok.text] || cfg.depthBlocks[tok.text]) && !isDoWhileTrailer(tokens, i) {
			parseControl(i)
		}
	}
	return starts, ends
}

func languageStatementContinues(previous, next string) bool {
	switch previous {
	case ".", "->", "::", ",", "=", "==", "!=", "<", ">", "+", "-", "*", "/", "&&", "||", "?", ":", "=>":
		return true
	}
	switch next {
	case ".", "->", "::", ")", "]", "}", ",", "else", "catch", "finally", "while":
		return true
	}
	return false
}

func lexBraceLanguage(source string, cfg braceLanguageConfig) []braceLanguageToken {
	var tokens []braceLanguageToken
	line := 1
	for i := 0; i < len(source); {
		c := source[i]
		if c == '\n' {
			line++
			i++
			continue
		}
		if cfg.rustRawStrings {
			if end, ok, closed := skipRustRawString(source, i); ok {
				if !closed {
					tokens = append(tokens, braceLanguageToken{text: "<unterminated-string>", line: line, start: i, end: end})
				}
				line += strings.Count(source[i:end], "\n")
				i = end
				continue
			}
		}
		if cfg.cppRawStrings {
			if end, ok, closed := skipCppRawString(source, i); ok {
				if !closed {
					tokens = append(tokens, braceLanguageToken{text: "<unterminated-string>", line: line, start: i, end: end})
				}
				line += strings.Count(source[i:end], "\n")
				i = end
				continue
			}
		}
		if cfg.csharpVerbatimStrings && !(cfg.csharpInterpolation && (i > 0 && source[i-1] == '$' || i+1 < len(source) && source[i+1] == '$')) {
			if end, ok, closed := skipCSharpVerbatimString(source, i); ok {
				if !closed {
					tokens = append(tokens, braceLanguageToken{text: "<unterminated-string>", line: line, start: i, end: end})
				}
				line += strings.Count(source[i:end], "\n")
				i = end
				continue
			}
		}
		if cfg.csharpRawStrings {
			if end, ok, closed := skipCSharpRawString(source, i); ok {
				if !closed {
					tokens = append(tokens, braceLanguageToken{text: "<unterminated-string>", line: line, start: i, end: end})
				}
				if cfg.csharpInterpolation {
					appendCSharpRawInterpolations(&tokens, source, i, end, line, cfg)
				}
				line += strings.Count(source[i:end], "\n")
				i = end
				continue
			}
		}
		if cfg.swiftRawStrings {
			if end, ok, closed := skipSwiftRawString(source, i); ok {
				if !closed {
					tokens = append(tokens, braceLanguageToken{text: "<unterminated-string>", line: line, start: i, end: end})
				}
				if cfg.swiftInterpolation {
					appendSwiftRawInterpolations(&tokens, source, i, end, line, cfg)
				}
				line += strings.Count(source[i:end], "\n")
				i = end
				continue
			}
		}
		if cfg.phpHeredoc {
			if end, ok, closed := skipPHPLiteral(source, i); ok {
				if !closed {
					tokens = append(tokens, braceLanguageToken{text: "<unterminated-string>", line: line, start: i, end: end})
				}
				line += strings.Count(source[i:end], "\n")
				i = end
				continue
			}
		}
		if cfg.preprocessor && c == '#' && isPreprocessorLine(source, i) {
			end := skipPreprocessorLines(source, i)
			line += strings.Count(source[i:end], "\n")
			i = end
			continue
		}
		if c == '/' && i+1 < len(source) && source[i+1] == '/' {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(source) && source[i+1] == '*' {
			i += 2
			depth := 1
			startLine := line
			for i < len(source) {
				if cfg.nestedBlockComments && source[i] == '/' && i+1 < len(source) && source[i+1] == '*' {
					depth++
					i += 2
					continue
				}
				if source[i] == '*' && i+1 < len(source) && source[i+1] == '/' {
					depth--
					if depth == 0 {
						i += 2
						break
					}
					i += 2
					continue
				}
				if source[i] == '\n' {
					line++
				}
				i++
			}
			if depth > 0 {
				tokens = append(tokens, braceLanguageToken{text: "<unterminated-comment>", line: startLine, start: i, end: i})
			}
			continue
		}
		if cfg.swiftRegexLiterals && c == '/' && swiftRegexCanStart(tokens) {
			startLine := line
			end, closed := skipSwiftRegex(source, i, &line)
			if !closed {
				tokens = append(tokens, braceLanguageToken{text: "<unterminated-regex>", line: startLine, start: i, end: end})
			}
			i = end
			continue
		}
		if cfg.phpComments && c == '#' && (i+1 >= len(source) || source[i+1] != '[') {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}
		if (c == '"' || c == '\'') && cfg.tripleStrings && i+2 < len(source) && source[i+1] == c && source[i+2] == c {
			start := i
			startLine := line
			i += 3
			closed := false
			for i+2 < len(source) && !(source[i] == c && source[i+1] == c && source[i+2] == c) {
				if exprStart, exprEnd, ok := interpolationAt(source, i, start, c, cfg); ok {
					appendInterpolatedTokens(&tokens, source, exprStart, exprEnd, start, startLine, cfg)
					i = exprEnd + 1
					continue
				}
				if source[i] == '\\' && i+1 < len(source) {
					if source[i+1] == '\n' {
						line++
					}
					i += 2
					continue
				}
				if source[i] == '\n' {
					line++
				}
				i++
			}
			if i+2 < len(source) {
				i += 3
				closed = true
			}
			if !closed {
				tokens = append(tokens, braceLanguageToken{text: "<unterminated-string>", line: startLine, start: start, end: i})
			}
			continue
		}
		if c == '"' || c == '\'' || c == 96 {
			quote := c
			start := i
			startLine := line
			interpolatedVerbatim := cfg.csharpInterpolation && cfg.csharpVerbatimStrings && quote == '"' && (strings.HasSuffix(source[:start], "$@") || strings.HasSuffix(source[:start], "@$"))
			i++
			closed := false
			for i < len(source) {
				if exprStart, exprEnd, ok := interpolationAt(source, i, start, quote, cfg); ok {
					appendInterpolatedTokens(&tokens, source, exprStart, exprEnd, start, startLine, cfg)
					i = exprEnd + 1
					continue
				}
				if source[i] == '\n' {
					if !cfg.phpComments && quote != 96 && !interpolatedVerbatim {
						break
					}
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
					if interpolatedVerbatim && i+1 < len(source) && source[i+1] == quote {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				tokens = append(tokens, braceLanguageToken{text: "<unterminated-string>", line: startLine, start: start, end: i})
			}
			continue
		}
		if isSourceIdentStart(c) {
			start := i
			for i < len(source) && isSourceIdentPart(source[i]) {
				i++
			}
			text := source[start:i]
			if cfg.phpComments {
				text = strings.ToLower(text)
			}
			tokens = append(tokens, braceLanguageToken{text: text, line: line, start: start, end: i})
			continue
		}
		if cfg.phpComments && c == '<' && i+1 < len(source) && source[i+1] == '>' {
			tokens = append(tokens, braceLanguageToken{text: "<>", line: line, start: i, end: i + 2})
			i += 2
			continue
		}
		if c == '=' || c == '!' {
			if c == '=' && i+1 < len(source) && source[i+1] == '>' {
				tokens = append(tokens, braceLanguageToken{text: "=>", line: line, start: i, end: i + 2})
				i += 2
				continue
			}
			start := i
			i++
			for i < len(source) && source[i] == '=' && i-start < 3 {
				i++
			}
			tokens = append(tokens, braceLanguageToken{text: source[start:i], line: line, start: start, end: i})
			continue
		}
		if strings.ContainsRune("{}();[],:<>+-*/&|^~?", rune(c)) {
			tokens = append(tokens, braceLanguageToken{text: string(c), line: line, start: i, end: i + 1})
		}
		i++
	}
	return tokens
}

func appendInterpolatedTokens(tokens *[]braceLanguageToken, source string, exprStart, exprEnd, quoteStart, quoteLine int, cfg braceLanguageConfig) {
	baseLine := quoteLine + strings.Count(source[quoteStart:exprStart], "\n")
	for _, token := range lexBraceLanguage(source[exprStart:exprEnd], cfg) {
		token.line += baseLine - 1
		token.start += exprStart
		token.end += exprStart
		*tokens = append(*tokens, token)
	}
}

func appendCSharpRawInterpolations(tokens *[]braceLanguageToken, source string, start, end, startLine int, cfg braceLanguageConfig) {
	quoteStart := start
	for quoteStart < end && source[quoteStart] == '$' {
		quoteStart++
	}
	if quoteStart == start || quoteStart >= end || source[quoteStart] != '"' {
		return
	}
	dollarCount := quoteStart - start
	quoteEnd := quoteStart
	for quoteEnd < end && source[quoteEnd] == '"' {
		quoteEnd++
	}
	for i := quoteEnd; i < end; {
		if dollarCount == 1 {
			if exprStart, exprEnd, ok := interpolationAt(source, i, quoteStart, '"', cfg); ok {
				appendInterpolatedTokens(tokens, source, exprStart, exprEnd, start, startLine, cfg)
				i = exprEnd + 1
				continue
			}
		}
		if dollarCount > 1 {
			if exprStart, exprEnd, ok := findCSharpMultiDollarExpression(source, i, end, dollarCount); ok {
				appendInterpolatedTokens(tokens, source, exprStart, exprEnd, start, startLine, cfg)
				i = exprEnd + 1
				continue
			}
		}
		i++
	}
}

func findCSharpMultiDollarExpression(source string, start, limit, dollars int) (int, int, bool) {
	for open := start; open < limit; open++ {
		if source[open] != '{' {
			continue
		}
		count := 0
		for open+count < limit && source[open+count] == '{' {
			count++
		}
		if count < dollars {
			open += count - 1
			continue
		}
		exprStart := open + dollars
		depth := 0
		var quote byte
		for i := exprStart; i < limit; i++ {
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
			if c == '{' {
				depth++
				continue
			}
			if c == '}' {
				run := 1
				for i+run < limit && source[i+run] == '}' {
					run++
				}
				if depth == 0 && run >= dollars {
					return exprStart, i, true
				}
				if depth > 0 {
					depth--
				}
			}
		}
		return 0, 0, false
	}
	return 0, 0, false
}

func appendSwiftRawInterpolations(tokens *[]braceLanguageToken, source string, start, end, startLine int, cfg braceLanguageConfig) {
	hashEnd := start
	for hashEnd < end && source[hashEnd] == '#' {
		hashEnd++
	}
	quoteStart := hashEnd
	quoteCount := 0
	for quoteStart+quoteCount < end && quoteCount < 3 && source[quoteStart+quoteCount] == '"' {
		quoteCount++
	}
	if quoteCount != 1 && quoteCount != 3 {
		return
	}
	contentStart := quoteStart + quoteCount
	contentEnd := end - quoteCount - (hashEnd - start)
	for i := contentStart; i < contentEnd; {
		if exprStart, exprEnd, ok := interpolationAt(source, i, quoteStart, '"', cfg); ok {
			appendInterpolatedTokens(tokens, source, exprStart, exprEnd, start, startLine, cfg)
			i = exprEnd + 1
			continue
		}
		i++
	}
}

func interpolationAt(source string, index, quoteStart int, quote byte, cfg braceLanguageConfig) (int, int, bool) {
	if index >= len(source) {
		return 0, 0, false
	}
	open, close := byte(0), byte(0)
	if cfg.csharpInterpolation && quote == '"' {
		prefix := source[:quoteStart]
		if strings.HasSuffix(prefix, "$") || strings.HasSuffix(prefix, "$@") || strings.HasSuffix(prefix, "@$") {
			if source[index] == '{' && (index == 0 || source[index-1] != '{') && (index+1 >= len(source) || source[index+1] != '{') {
				open, close = '{', '}'
			}
		}
	}
	if cfg.kotlinInterpolation && source[index] == '$' && index+1 < len(source) && source[index+1] == '{' {
		open, close = '{', '}'
		index++
	}
	if cfg.swiftInterpolation && source[index] == '\\' {
		rawHashes := 0
		for i := quoteStart - 1; i >= 0 && source[i] == '#'; i-- {
			rawHashes++
		}
		markerEnd := index + 1
		for markerEnd < len(source) && source[markerEnd] == '#' {
			markerEnd++
		}
		if markerEnd-index-1 == rawHashes && markerEnd < len(source) && source[markerEnd] == '(' {
			open, close = '(', ')'
			index = markerEnd
		}
	}
	if cfg.phpInterpolation && quote == '"' && source[index] == '{' && index+1 < len(source) && source[index+1] == '$' {
		open, close = '{', '}'
	}
	if open == 0 || source[index] != open {
		return 0, 0, false
	}
	contentStart := index + 1
	depth := 1
	var innerQuote byte
	for i := contentStart; i < len(source); i++ {
		c := source[i]
		if innerQuote != 0 {
			if c == '\\' {
				i++
				continue
			}
			if c == innerQuote {
				innerQuote = 0
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			innerQuote = c
			continue
		}
		if c == '/' && i+1 < len(source) && source[i+1] == '/' {
			for i < len(source) && source[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(source) && source[i+1] == '*' {
			i += 2
			for i+1 < len(source) && !(source[i] == '*' && source[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		if c == '\\' {
			i++
			continue
		}
		if c == open {
			depth++
		} else if c == close {
			depth--
			if depth == 0 {
				return contentStart, i, true
			}
		}
	}
	return 0, 0, false
}

func skipSwiftRegex(source string, start int, line *int) (int, bool) {
	inClass := false
	for i := start + 1; i < len(source); i++ {
		switch source[i] {
		case '\\':
			i++
		case '[':
			inClass = true
		case ']':
			inClass = false
		case '\n':
			*line++
			return i + 1, false
		case '/':
			if !inClass {
				return i + 1, true
			}
		}
	}
	return len(source), false
}

func isBooleanOperand(tokens []braceLanguageToken, index int, left bool, literals map[string]bool) bool {
	start, end := index, index
	if index < 0 || index >= len(tokens) {
		return false
	}
	if left && tokens[index].text == ")" {
		open := matchingLanguageParen(tokens, index, false)
		if open < 0 {
			return false
		}
		start = open
	} else if !left && tokens[index].text == "(" {
		close := matchingLanguageParen(tokens, index, true)
		if close < 0 {
			return false
		}
		end = close
	}
	for start < end && tokens[start].text == "(" && matchingLanguageParen(tokens, start, true) == end {
		start++
		end--
	}
	return start == end && literals[tokens[start].text]
}

func matchingLanguageParen(tokens []braceLanguageToken, index int, forward bool) int {
	depth := 0
	if forward {
		for i := index; i < len(tokens); i++ {
			switch tokens[i].text {
			case "(":
				depth++
			case ")":
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	} else {
		for i := index; i >= 0; i-- {
			switch tokens[i].text {
			case ")":
				depth++
			case "(":
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	return -1
}

func skipRustRawString(source string, start int) (int, bool, bool) {
	rIndex := start
	if strings.HasPrefix(source[start:], "br") {
		rIndex++
	} else if start >= len(source) || source[start] != 'r' {
		return start, false, false
	}
	quote := rIndex + 1
	for quote < len(source) && source[quote] == '#' {
		quote++
	}
	if quote >= len(source) || source[quote] != '"' {
		return start, false, false
	}
	closing := `"` + strings.Repeat("#", quote-rIndex-1)
	end := strings.Index(source[quote+1:], closing)
	if end < 0 {
		return len(source), true, false
	}
	return quote + 1 + end + len(closing), true, true
}

func skipCppRawString(source string, start int) (int, bool, bool) {
	prefixes := []string{"u8R\"", "uR\"", "UR\"", "LR\"", "R\""}
	prefix := ""
	for _, candidate := range prefixes {
		if strings.HasPrefix(source[start:], candidate) {
			prefix = candidate
			break
		}
	}
	if prefix == "" {
		return start, false, false
	}
	delimStart := start + len(prefix)
	open := strings.IndexByte(source[delimStart:], '(')
	if open < 0 || open > 16 {
		return start, false, false
	}
	delim := source[delimStart : delimStart+open]
	if strings.ContainsAny(delim, " ()\\\t\r\n") {
		return start, false, false
	}
	closing := ")" + delim + `"`
	end := strings.Index(source[delimStart+open+1:], closing)
	if end < 0 {
		return len(source), true, false
	}
	return delimStart + open + 1 + end + len(closing), true, true
}

func skipCSharpVerbatimString(source string, start int) (int, bool, bool) {
	quote := -1
	for _, prefix := range []string{`@$"`, `$@"`, `@"`} {
		if strings.HasPrefix(source[start:], prefix) {
			quote = start + len(prefix) - 1
			break
		}
	}
	if quote < 0 {
		return start, false, false
	}
	for i := quote + 1; i < len(source); i++ {
		if source[i] == '"' {
			if i+1 < len(source) && source[i+1] == '"' {
				i++
				continue
			}
			return i + 1, true, true
		}
	}
	return len(source), true, false
}

func skipCSharpRawString(source string, start int) (int, bool, bool) {
	quoteStart := start
	for quoteStart < len(source) && source[quoteStart] == '$' {
		quoteStart++
	}
	if quoteStart >= len(source) || source[quoteStart] != '"' {
		return start, false, false
	}
	quoteEnd := quoteStart
	for quoteEnd < len(source) && source[quoteEnd] == '"' {
		quoteEnd++
	}
	quoteCount := quoteEnd - quoteStart
	if quoteCount < 3 {
		return start, false, false
	}
	closing := strings.Repeat(`"`, quoteCount)
	end := strings.Index(source[quoteEnd:], closing)
	if end < 0 {
		return len(source), true, false
	}
	return quoteEnd + end + len(closing), true, true
}

func skipSwiftRawString(source string, start int) (int, bool, bool) {
	if start >= len(source) || source[start] != '#' {
		return start, false, false
	}
	hashEnd := start
	for hashEnd < len(source) && source[hashEnd] == '#' {
		hashEnd++
	}
	quoteEnd := hashEnd
	for quoteEnd < len(source) && quoteEnd-hashEnd < 3 && source[quoteEnd] == '"' {
		quoteEnd++
	}
	quoteCount := quoteEnd - hashEnd
	if quoteCount != 1 && quoteCount != 3 {
		return start, false, false
	}
	closing := strings.Repeat(`"`, quoteCount) + strings.Repeat("#", hashEnd-start)
	end := strings.Index(source[quoteEnd:], closing)
	if end < 0 {
		return len(source), true, false
	}
	return quoteEnd + end + len(closing), true, true
}

func skipPHPLiteral(source string, start int) (int, bool, bool) {
	if start+3 > len(source) || source[start:start+3] != "<<<" {
		return start, false, false
	}
	i := start + 3
	for i < len(source) && (source[i] == ' ' || source[i] == '\t') {
		i++
	}
	quote := byte(0)
	if i < len(source) && (source[i] == '\'' || source[i] == '"') {
		quote = source[i]
		i++
	}
	labelStart := i
	if i >= len(source) || !(source[i] == '_' || source[i] >= 'a' && source[i] <= 'z' || source[i] >= 'A' && source[i] <= 'Z') {
		return start, false, false
	}
	i++
	for i < len(source) && (source[i] == '_' || source[i] >= 'a' && source[i] <= 'z' || source[i] >= 'A' && source[i] <= 'Z' || source[i] >= '0' && source[i] <= '9') {
		i++
	}
	label := source[labelStart:i]
	if quote != 0 {
		if i >= len(source) || source[i] != quote {
			return start, false, false
		}
		i++
	}
	for i < len(source) && (source[i] == ' ' || source[i] == '\t' || source[i] == '\r') {
		i++
	}
	if i >= len(source) || source[i] != '\n' {
		return start, false, false
	}
	i++
	for i <= len(source) {
		lineEnd := strings.IndexByte(source[i:], '\n')
		if lineEnd < 0 {
			lineEnd = len(source) - i
		}
		line := source[i : i+lineEnd]
		candidate := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(candidate, label) {
			next := candidate[len(label):]
			if next == "" || next[0] == ';' || next[0] == ',' || next[0] == ')' || next[0] == ']' || next[0] == ' ' || next[0] == '\t' || next[0] == '\r' {
				indent := len(line) - len(candidate)
				return i + indent + len(label), true, true
			}
		}
		if i+lineEnd >= len(source) {
			break
		}
		i += lineEnd + 1
	}
	return len(source), true, false
}

func isPreprocessorLine(source string, index int) bool {
	lineStart := strings.LastIndex(source[:index], "\n") + 1
	for _, c := range source[lineStart:index] {
		if c != ' ' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}

func skipPreprocessorLines(source string, start int) int {
	for start < len(source) {
		lineEnd := strings.IndexByte(source[start:], '\n')
		if lineEnd < 0 {
			return len(source)
		}
		line := strings.TrimRight(source[start:start+lineEnd], " \t\r")
		start += lineEnd + 1
		if !strings.HasSuffix(line, "\\") {
			return start
		}
	}
	return start
}

func braceLanguageStructureError(tokens []braceLanguageToken) error {
	type delimiter struct {
		text string
		line int
	}
	var stack []delimiter
	pairs := map[string]string{")": "(", "]": "[", "}": "{"}
	for _, tok := range tokens {
		if strings.HasPrefix(tok.text, "<unterminated-") {
			return fmt.Errorf("unterminated source literal or comment on line %d", tok.line)
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
