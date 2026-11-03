package slop

func (r SlopRule) checkPHPSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfig{name: "PHP", controls: wordSet("if", "for", "foreach", "while", "switch", "catch"), directBlocks: wordSet("else", "try", "finally", "do"), boolLiterals: wordSet("true", "false"), phpComments: true, phpAltSyntax: true, phpHeredoc: true, depthBlocks: wordSet("try", "do"), phpInterpolation: true, strictBoolOperators: true})
}
