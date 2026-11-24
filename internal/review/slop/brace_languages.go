package slop

import "github.com/jakej985-rgb/m3tal-review/internal/review/language"

// braceLanguageConfigs centralizes the scanner configuration for every
// brace-delimited language. Language dispatch lives in slop_rule.go; adding a
// language means adding one entry here rather than another near-empty file.
var braceLanguageConfigs = map[language.CodeLanguage]braceLanguageConfig{
	language.LanguageC: {
		name:                "C",
		controls:            wordSet("if", "for", "while", "switch"),
		directBlocks:        wordSet("else", "do"),
		depthBlocks:         wordSet("do"),
		allowUnbracedBodies: true,
		boolLiterals:        wordSet("true", "false"),
		preprocessor:        true,
	},
	language.LanguageCpp: {
		name:                "C++",
		controls:            wordSet("if", "for", "while", "switch", "catch"),
		directBlocks:        wordSet("else", "try", "do"),
		depthBlocks:         wordSet("try", "do"),
		allowUnbracedBodies: true,
		cppIfModifiers:      true,
		boolLiterals:        wordSet("true", "false"),
		cppRawStrings:       true,
		preprocessor:        true,
	},
	language.LanguageCSharp: {
		name:                  "C#",
		controls:              wordSet("if", "for", "foreach", "while", "switch", "catch"),
		directBlocks:          wordSet("else", "try", "finally", "do"),
		depthBlocks:           wordSet("try", "do"),
		allowUnbracedBodies:   true,
		boolLiterals:          wordSet("true", "false"),
		csharpVerbatimStrings: true,
		csharpRawStrings:      true,
		csharpInterpolation:   true,
		preprocessor:          true,
	},
	language.LanguageJava: {
		name:                "Java",
		controls:            wordSet("if", "for", "while", "switch", "catch"),
		directBlocks:        wordSet("else", "try", "finally", "do"),
		depthBlocks:         wordSet("try", "do"),
		allowUnbracedBodies: true,
		javaTryResources:    true,
		boolLiterals:        wordSet("true", "false"),
		tripleStrings:       true,
	},
	language.LanguageKotlin: {
		name:                "Kotlin",
		controls:            wordSet("if", "for", "while", "when", "catch"),
		directBlocks:        wordSet("else", "try", "finally", "do"),
		depthBlocks:         wordSet("try", "do"),
		allowUnbracedBodies: true,
		nestedBlockComments: true,
		optionalParen:       true,
		boolLiterals:        wordSet("true", "false"),
		tripleStrings:       true,
		kotlinInterpolation: true,
	},
	language.LanguagePHP: {
		name:                "PHP",
		controls:            wordSet("if", "for", "foreach", "while", "switch", "catch"),
		directBlocks:        wordSet("else", "try", "finally", "do"),
		boolLiterals:        wordSet("true", "false"),
		phpComments:         true,
		phpAltSyntax:        true,
		phpHeredoc:          true,
		depthBlocks:         wordSet("try", "do"),
		phpInterpolation:    true,
		strictBoolOperators: true,
	},
	language.LanguageRust: {
		name:                "Rust",
		controls:            wordSet("if", "for", "while", "match", "loop"),
		directBlocks:        wordSet("else"),
		optionalParen:       true,
		rustLetPatterns:     true,
		boolLiterals:        wordSet("true", "false"),
		rustRawStrings:      true,
		nestedBlockComments: true,
	},
	language.LanguageSwift: {
		name:                "Swift",
		controls:            wordSet("if", "for", "while", "switch", "guard"),
		directBlocks:        wordSet("else", "do", "repeat"),
		optionalParen:       true,
		boolLiterals:        wordSet("true", "false"),
		tripleStrings:       true,
		swiftRawStrings:     true,
		preprocessor:        true,
		nestedBlockComments: true,
		swiftRegexLiterals:  true,
		depthBlocks:         wordSet("repeat"),
		swiftInterpolation:  true,
	},
	language.LanguageDart: {
		name:                "Dart",
		controls:            wordSet("if", "for", "while", "switch", "catch"),
		directBlocks:        wordSet("else", "try", "finally", "do"),
		depthBlocks:         wordSet("do"),
		allowUnbracedBodies: true,
		boolLiterals:        wordSet("true", "false"),
		tripleStrings:       true,
		nestedBlockComments: true,
	},
}

func (r SlopRule) checkCSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguageC])
}

func (r SlopRule) checkCppSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguageCpp])
}

func (r SlopRule) checkCSharpSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguageCSharp])
}

func (r SlopRule) checkJavaSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguageJava])
}

func (r SlopRule) checkKotlinSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguageKotlin])
}

func (r SlopRule) checkPHPSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguagePHP])
}

func (r SlopRule) checkRustSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguageRust])
}

func (r SlopRule) checkSwiftSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguageSwift])
}

func (r SlopRule) checkDartSyntax(file string, added []int) []Finding {
	return braceAnalyzer(r, file, added, braceLanguageConfigs[language.LanguageDart])
}

// checkTypeScriptSyntax uses the shared JavaScript-compatible syntax scanner
// for TypeScript and TSX control-flow structures.
func (r SlopRule) checkTypeScriptSyntax(file string, added []int) []Finding {
	source, err := r.readSourceForAnalysis(file)
	if err != nil {
		return r.analysisReadError(file, err)
	}
	return analyzeBraceSlop(file, "TypeScript", string(source), addedLineMap(added))
}

func (r SlopRule) checkTypeScriptRegex(fd FileDiff) []Finding {
	return r.checkAddedLineRegex(fd)
}

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
