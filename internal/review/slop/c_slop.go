package slop

func (r SlopRule) checkCSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{name: "C", controls: wordSet("if", "for", "while", "switch"), directBlocks: wordSet("else", "do"), depthBlocks: wordSet("do"), allowUnbracedBodies: true, boolLiterals: wordSet("true", "false"), preprocessor: true})
}
