package slop

func (r SlopRule) checkCppSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{name: "C++", controls: wordSet("if", "for", "while", "switch", "catch"), directBlocks: wordSet("else", "try", "do"), depthBlocks: wordSet("try", "do"), allowUnbracedBodies: true, cppIfModifiers: true, boolLiterals: wordSet("true", "false"), cppRawStrings: true, preprocessor: true})
}
