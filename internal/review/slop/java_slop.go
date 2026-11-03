package slop

func (r SlopRule) checkJavaSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{name: "Java", controls: wordSet("if", "for", "while", "switch", "catch"), directBlocks: wordSet("else", "try", "finally", "do"), depthBlocks: wordSet("try", "do"), allowUnbracedBodies: true, javaTryResources: true, boolLiterals: wordSet("true", "false"), tripleStrings: true})
}
