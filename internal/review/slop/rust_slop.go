package slop

func (r SlopRule) checkRustSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{name: "Rust", controls: wordSet("if", "for", "while", "match", "loop"), directBlocks: wordSet("else"), optionalParen: true, rustLetPatterns: true, boolLiterals: wordSet("true", "false"), rustRawStrings: true, nestedBlockComments: true})
}
