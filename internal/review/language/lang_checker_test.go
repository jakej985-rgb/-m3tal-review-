package language

import (
	"testing"
)

func TestCodeCheckerDetectsSupportedLanguages(t *testing.T) {
	checker := CodeChecker{}
	cases := map[string]CodeLanguage{
		"main.go":           LanguageGo,
		"app.jsx":           LanguageJavaScript,
		"app.tsx":           LanguageTypeScript,
		"script.py":         LanguagePython,
		"Main.java":         LanguageJava,
		"Main.kt":           LanguageKotlin,
		"main.c":            LanguageC,
		"main.cpp":          LanguageCpp,
		"main.cxx":          LanguageCpp,
		"main.c++":          LanguageCpp,
		"main.C":            LanguageCpp,
		"main.H":            LanguageCpp,
		"main.hh":           LanguageCpp,
		"main.hxx":          LanguageCpp,
		"Main.cs":           LanguageCSharp,
		"main.rs":           LanguageRust,
		"main.swift":        LanguageSwift,
		"index.php":         LanguagePHP,
		"README.md":         LanguageUnknown,
		"UPPERCASE.JS":      LanguageJavaScript,
		"Component.TSX":     LanguageTypeScript,
		"package-lock.json": LanguageUnknown,
	}
	for file, want := range cases {
		if got := checker.Language(file); got != want {
			t.Errorf("Language(%q) = %q, want %q", file, got, want)
		}
	}
}
