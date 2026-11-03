package slop

func swiftRegexCanStart(tokens []braceLanguageToken) bool {
	if len(tokens) == 0 {
		return true
	}
	last := tokens[len(tokens)-1].text
	switch last {
	case "(", "{", "[", ";", ",", ":", "?", "=", "==", "!", "return", "yield", "case", "throw", "try", "await", "in", "where", "as", "is", "if", "guard", "let", "var":
		return true
	}
	for _, operator := range []string{"+", "-", "*", "/", "%", "&&", "||", "??", "&", "|", "^", "~=", "->", "=>", "<", ">", "<=", ">=", "==", "!=", "...", "..<"} {
		if last == operator {
			return true
		}
	}
	return false
}

func (r SlopRule) checkSwiftSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{name: "Swift", controls: wordSet("if", "for", "while", "switch", "guard"), directBlocks: wordSet("else", "do", "repeat"), optionalParen: true, boolLiterals: wordSet("true", "false"), tripleStrings: true, swiftRawStrings: true, preprocessor: true, nestedBlockComments: true, swiftRegexLiterals: true, depthBlocks: wordSet("repeat"), swiftInterpolation: true})
}
