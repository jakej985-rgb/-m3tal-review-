package slop

func (r SlopRule) checkCSharpSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{name: "C#", controls: wordSet("if", "for", "foreach", "while", "switch", "catch"), directBlocks: wordSet("else", "try", "finally", "do"), depthBlocks: wordSet("try", "do"), allowUnbracedBodies: true, boolLiterals: wordSet("true", "false"), csharpVerbatimStrings: true, csharpRawStrings: true, csharpInterpolation: true, preprocessor: true})
}
