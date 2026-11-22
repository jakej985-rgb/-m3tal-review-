package slop

func (r SlopRule) checkDartSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{
		name:                "Dart",
		controls:            wordSet("if", "for", "while", "switch", "catch"),
		directBlocks:        wordSet("else", "try", "finally", "do"),
		depthBlocks:         wordSet("do"),
		allowUnbracedBodies: true,
		boolLiterals:        wordSet("true", "false"),
		tripleStrings:       true,
		nestedBlockComments: true,
	})
}
