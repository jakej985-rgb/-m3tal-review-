package language

import (
	"path"
	"strings"
)

type CodeLanguage string

const (
	LanguageGo         CodeLanguage = "go"
	LanguageJavaScript CodeLanguage = "javascript"
	LanguageTypeScript CodeLanguage = "typescript"
	LanguagePython     CodeLanguage = "python"
	LanguageJava       CodeLanguage = "java"
	LanguageKotlin     CodeLanguage = "kotlin"
	LanguageC          CodeLanguage = "c"
	LanguageCpp        CodeLanguage = "cpp"
	LanguageCSharp     CodeLanguage = "csharp"
	LanguageRust       CodeLanguage = "rust"
	LanguageSwift      CodeLanguage = "swift"
	LanguagePHP        CodeLanguage = "php"
	LanguageShell      CodeLanguage = "shell"
	LanguageUnknown    CodeLanguage = "unknown"
)

// CodeChecker identifies the language from the file extension so review rules
// can select language-specific behavior.
type CodeChecker struct{}

func (CodeChecker) Language(file string) CodeLanguage {
	ext := path.Ext(file)
	if ext == ".C" || ext == ".H" || ext == ".c++" || ext == ".C++" || ext == ".cc" || ext == ".CC" {
		return LanguageCpp
	}
	switch strings.ToLower(ext) {
	case ".go":
		return LanguageGo
	case ".js", ".jsx", ".mjs", ".cjs":
		return LanguageJavaScript
	case ".ts", ".tsx", ".mts", ".cts":
		return LanguageTypeScript
	case ".py":
		return LanguagePython
	case ".java":
		return LanguageJava
	case ".kt", ".kts":
		return LanguageKotlin
	case ".c":
		return LanguageC
	case ".h", ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h++":
		return LanguageCpp
	case ".cs", ".csx":
		return LanguageCSharp
	case ".rs":
		return LanguageRust
	case ".swift":
		return LanguageSwift
	case ".php", ".phtml":
		return LanguagePHP
	case ".sh", ".bash", ".zsh":
		return LanguageShell
	default:
		return LanguageUnknown
	}
}

// IsLikelySourceFile reports common source-code extensions that do not yet
// have a dedicated analyzer. Audits use this to avoid reporting a complete
// pass when a source file was skipped by every language-aware rule.
func IsLikelySourceFile(file string) bool {
	ext := strings.ToLower(path.Ext(file))
	switch ext {
	case ".rb", ".rake", ".scala", ".sc", ".dart", ".vue", ".svelte",
		".sql", ".lua", ".r", ".m", ".mm", ".pl", ".pm", ".ex", ".exs",
		".erl", ".hrl", ".clj", ".cljs", ".cljc", ".groovy", ".gradle",
		".fish", ".elm", ".hs", ".lhs",
		".jl", ".nim", ".nix", ".proto", ".graphql", ".gql",
		".tf", ".hcl", ".sol", ".v", ".sv", ".asm", ".s":
		return true
	default:
		return false
	}
}
