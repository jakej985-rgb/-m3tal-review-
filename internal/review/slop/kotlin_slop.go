package slop

func (r SlopRule) checkKotlinSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{name: "Kotlin", controls: wordSet("if", "for", "while", "when", "catch"), directBlocks: wordSet("else", "try", "finally", "do"), depthBlocks: wordSet("try", "do"), allowUnbracedBodies: true, nestedBlockComments: true, optionalParen: true, boolLiterals: wordSet("true", "false"), tripleStrings: true, kotlinInterpolation: true})
}
