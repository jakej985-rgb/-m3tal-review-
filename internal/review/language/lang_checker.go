package language

import (
	"bytes"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

type Confidence string

const (
	ConfidenceHigh   Confidence = "High"
	ConfidenceMedium Confidence = "Medium"
	ConfidenceLow    Confidence = "Low"
)

type DetectionResult struct {
	Language   CodeLanguage `json:"language"`
	Confidence Confidence   `json:"confidence"`
	Reason     string       `json:"reason"`
}

var (
	defaultOverridesMu sync.RWMutex
	defaultOverrides   map[string]string
)

// SetDefaultOverrides configures global default language overrides.
func SetDefaultOverrides(overrides map[string]string) {
	defaultOverridesMu.Lock()
	defer defaultOverridesMu.Unlock()
	if len(overrides) == 0 {
		defaultOverrides = nil
		return
	}
	defaultOverrides = make(map[string]string, len(overrides))
	for k, v := range overrides {
		defaultOverrides[k] = v
	}
}

// GetDefaultOverrides returns a copy of the active global default language overrides.
func GetDefaultOverrides() map[string]string {
	defaultOverridesMu.RLock()
	defer defaultOverridesMu.RUnlock()
	if len(defaultOverrides) == 0 {
		return nil
	}
	res := make(map[string]string, len(defaultOverrides))
	for k, v := range defaultOverrides {
		res[k] = v
	}
	return res
}

// NormalizeLanguage canonicalizes string representations of programming languages.
func NormalizeLanguage(name string) CodeLanguage {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "go", "golang":
		return LanguageGo
	case "javascript", "js", "jsx", "mjs", "cjs":
		return LanguageJavaScript
	case "typescript", "ts", "tsx", "mts", "cts":
		return LanguageTypeScript
	case "python", "py":
		return LanguagePython
	case "java":
		return LanguageJava
	case "kotlin", "kt", "kts":
		return LanguageKotlin
	case "c":
		return LanguageC
	case "cpp", "c++", "cc", "cxx", "hh", "hpp", "hxx":
		return LanguageCpp
	case "csharp", "c#", "cs":
		return LanguageCSharp
	case "rust", "rs":
		return LanguageRust
	case "swift":
		return LanguageSwift
	case "php":
		return LanguagePHP
	case "shell", "sh", "bash", "zsh":
		return LanguageShell
	case "", "unknown":
		return LanguageUnknown
	default:
		return CodeLanguage(strings.ToLower(strings.TrimSpace(name)))
	}
}

// CodeChecker identifies the language from file path, overrides, and content.
type CodeChecker struct {
	Overrides map[string]string
}

// NewChecker creates a CodeChecker with specified language overrides.
func NewChecker(overrides map[string]string) *CodeChecker {
	return &CodeChecker{Overrides: overrides}
}

// Language reports the detected language for backwards compatibility.
func (c CodeChecker) Language(file string) CodeLanguage {
	return c.Detect(file, nil).Language
}

// Detect identifies the language with confidence metric and reason.
func (c CodeChecker) Detect(file string, content []byte) DetectionResult {
	normFile := filepath.ToSlash(file)

	// 1. Check explicit overrides (instance overrides take precedence over global)
	overrides := c.Overrides
	if overrides == nil {
		defaultOverridesMu.RLock()
		overrides = defaultOverrides
		defaultOverridesMu.RUnlock()
	}

	if len(overrides) > 0 {
		if targetLang, pattern, matched := matchOverride(normFile, overrides); matched {
			return DetectionResult{
				Language:   NormalizeLanguage(targetLang),
				Confidence: ConfidenceHigh,
				Reason:     "override: " + pattern,
			}
		}
	}

	// 2. Check Shebang if content is available
	if len(content) > 0 && bytes.HasPrefix(content, []byte("#!")) {
		if res, ok := detectShebang(content); ok {
			return res
		}
	}

	// 3. Check file extension
	ext := path.Ext(normFile)
	if ext == ".C" || ext == ".H" || ext == ".c++" || ext == ".C++" || ext == ".cc" || ext == ".CC" {
		return DetectionResult{
			Language:   LanguageCpp,
			Confidence: ConfidenceHigh,
			Reason:     "extension: " + ext,
		}
	}

	lowerExt := strings.ToLower(ext)
	switch lowerExt {
	case ".go":
		return DetectionResult{Language: LanguageGo, Confidence: ConfidenceHigh, Reason: "extension: .go"}
	case ".js", ".jsx", ".mjs", ".cjs":
		return DetectionResult{Language: LanguageJavaScript, Confidence: ConfidenceHigh, Reason: "extension: " + lowerExt}
	case ".ts", ".tsx", ".mts", ".cts":
		if lowerExt == ".ts" && len(content) > 0 {
			trimmed := bytes.TrimSpace(content)
			if bytes.HasPrefix(trimmed, []byte("<?xml")) || bytes.HasPrefix(trimmed, []byte("<TS")) {
				return DetectionResult{
					Language:   LanguageUnknown,
					Confidence: ConfidenceHigh,
					Reason:     "content-sniffing: xml translation file",
				}
			}
		}
		return DetectionResult{Language: LanguageTypeScript, Confidence: ConfidenceHigh, Reason: "extension: " + lowerExt}
	case ".py":
		return DetectionResult{Language: LanguagePython, Confidence: ConfidenceHigh, Reason: "extension: .py"}
	case ".java":
		return DetectionResult{Language: LanguageJava, Confidence: ConfidenceHigh, Reason: "extension: .java"}
	case ".kt", ".kts":
		return DetectionResult{Language: LanguageKotlin, Confidence: ConfidenceHigh, Reason: "extension: " + lowerExt}
	case ".c":
		return DetectionResult{Language: LanguageC, Confidence: ConfidenceHigh, Reason: "extension: .c"}
	case ".h":
		// Ambiguous header extension: C vs C++
		if len(content) > 0 {
			if isLikelyCppContent(content) {
				return DetectionResult{
					Language:   LanguageCpp,
					Confidence: ConfidenceHigh,
					Reason:     "content-sniffing: cpp header constructs",
				}
			}
			if isLikelyCContent(content) {
				return DetectionResult{
					Language:   LanguageC,
					Confidence: ConfidenceMedium,
					Reason:     "content-sniffing: c header constructs",
				}
			}
		}
		return DetectionResult{
			Language:   LanguageCpp,
			Confidence: ConfidenceLow,
			Reason:     "ambiguous extension: .h",
		}
	case ".cc", ".cpp", ".cxx", ".c++", ".hh", ".hpp", ".hxx", ".h++":
		return DetectionResult{Language: LanguageCpp, Confidence: ConfidenceHigh, Reason: "extension: " + lowerExt}
	case ".cs", ".csx":
		return DetectionResult{Language: LanguageCSharp, Confidence: ConfidenceHigh, Reason: "extension: " + lowerExt}
	case ".rs":
		return DetectionResult{Language: LanguageRust, Confidence: ConfidenceHigh, Reason: "extension: .rs"}
	case ".swift":
		return DetectionResult{Language: LanguageSwift, Confidence: ConfidenceHigh, Reason: "extension: .swift"}
	case ".php", ".phtml":
		return DetectionResult{Language: LanguagePHP, Confidence: ConfidenceHigh, Reason: "extension: " + lowerExt}
	case ".sh", ".bash", ".zsh":
		return DetectionResult{Language: LanguageShell, Confidence: ConfidenceHigh, Reason: "extension: " + lowerExt}
	case ".inc":
		if len(content) > 0 && bytes.Contains(content, []byte("<?php")) {
			return DetectionResult{
				Language:   LanguagePHP,
				Confidence: ConfidenceHigh,
				Reason:     "content-sniffing: php opening tag",
			}
		}
		return DetectionResult{
			Language:   LanguageUnknown,
			Confidence: ConfidenceLow,
			Reason:     "ambiguous extension: .inc",
		}
	}

	// 4. Content sniffing for extensionless or unknown extensions
	if len(content) > 0 {
		if res, ok := sniffContent(content); ok {
			return res
		}
	}

	// 5. Fallback
	if IsLikelySourceFile(normFile) {
		return DetectionResult{
			Language:   LanguageUnknown,
			Confidence: ConfidenceLow,
			Reason:     "likely source file without dedicated analyzer",
		}
	}

	return DetectionResult{
		Language:   LanguageUnknown,
		Confidence: ConfidenceLow,
		Reason:     "unknown extension",
	}
}

// Detect is a convenience function using global default configuration.
func Detect(file string, content []byte) DetectionResult {
	return (CodeChecker{}).Detect(file, content)
}

// DetectWithOverrides detects language with specific explicit overrides.
func DetectWithOverrides(file string, content []byte, overrides map[string]string) DetectionResult {
	return (CodeChecker{Overrides: overrides}).Detect(file, content)
}

var (
	cppKeywordsPattern = regexp.MustCompile(`\b(?:class\s+\w+|template\s*<|namespace\s+\w+|public:|private:|protected:|std::|constexpr|nullptr|typename|using\s+namespace)\b`)
	cConstructsPattern = regexp.MustCompile(`\b(?:typedef\s+struct|extern\s+(?:int|char|void|unsigned|const)|\bstdio\.h\b|\bstdlib\.h\b)\b`)
	goPackagePattern   = regexp.MustCompile(`(?m)^\s*package\s+[a-zA-Z_]\w*`)
	pyConstructPattern = regexp.MustCompile(`(?m)^\s*(?:def\s+\w+\s*\(|class\s+\w+|import\s+\w+|from\s+\w+\s+import)`)
)

func isLikelyCppContent(content []byte) bool {
	if bytes.Contains(content, []byte("#include <iostream>")) ||
		bytes.Contains(content, []byte("#include <vector>")) ||
		bytes.Contains(content, []byte("#include <string>")) ||
		bytes.Contains(content, []byte("#include <memory>")) {
		return true
	}
	return cppKeywordsPattern.Match(content)
}

func isLikelyCContent(content []byte) bool {
	return cConstructsPattern.Match(content)
}

func detectShebang(content []byte) (DetectionResult, bool) {
	firstLineEnd := bytes.IndexByte(content, '\n')
	if firstLineEnd == -1 {
		firstLineEnd = len(content)
	}
	firstLine := string(content[:firstLineEnd])

	switch {
	case strings.Contains(firstLine, "python"):
		return DetectionResult{Language: LanguagePython, Confidence: ConfidenceHigh, Reason: "shebang: python"}, true
	case strings.Contains(firstLine, "bash") || strings.Contains(firstLine, "sh") || strings.Contains(firstLine, "zsh"):
		return DetectionResult{Language: LanguageShell, Confidence: ConfidenceHigh, Reason: "shebang: shell"}, true
	case strings.Contains(firstLine, "node"):
		return DetectionResult{Language: LanguageJavaScript, Confidence: ConfidenceHigh, Reason: "shebang: node"}, true
	case strings.Contains(firstLine, "php"):
		return DetectionResult{Language: LanguagePHP, Confidence: ConfidenceHigh, Reason: "shebang: php"}, true
	case strings.Contains(firstLine, "perl"):
		return DetectionResult{Language: LanguageUnknown, Confidence: ConfidenceLow, Reason: "shebang: perl"}, true
	case strings.Contains(firstLine, "ruby"):
		return DetectionResult{Language: LanguageUnknown, Confidence: ConfidenceLow, Reason: "shebang: ruby"}, true
	default:
		return DetectionResult{}, false
	}
}

func sniffContent(content []byte) (DetectionResult, bool) {
	if bytes.Contains(content, []byte("<?php")) {
		return DetectionResult{
			Language:   LanguagePHP,
			Confidence: ConfidenceHigh,
			Reason:     "content-sniffing: php opening tag",
		}, true
	}
	if goPackagePattern.Match(content) {
		return DetectionResult{
			Language:   LanguageGo,
			Confidence: ConfidenceHigh,
			Reason:     "content-sniffing: go package declaration",
		}, true
	}
	if pyConstructPattern.Match(content) {
		return DetectionResult{
			Language:   LanguagePython,
			Confidence: ConfidenceMedium,
			Reason:     "content-sniffing: python constructs",
		}, true
	}
	return DetectionResult{}, false
}

func matchOverride(normFile string, overrides map[string]string) (string, string, bool) {
	// Exact full relative path match
	if target, ok := overrides[normFile]; ok {
		return target, normFile, true
	}

	// Exact basename match
	base := path.Base(normFile)
	if target, ok := overrides[base]; ok {
		return target, base, true
	}

	// Glob pattern match
	for pattern, target := range overrides {
		if strings.Contains(pattern, "*") || strings.Contains(pattern, "?") || strings.Contains(pattern, "[") {
			if !strings.Contains(pattern, "/") {
				if matched, _ := path.Match(pattern, base); matched {
					return target, pattern, true
				}
			} else {
				if matchGlob(pattern, normFile) {
					return target, pattern, true
				}
			}
		}
	}

	return "", "", false
}

func matchGlob(pattern, file string) bool {
	patternParts := strings.Split(pattern, "/")
	fileParts := strings.Split(file, "/")
	return matchMemoHelper(patternParts, fileParts, 0, 0)
}

func matchMemoHelper(pParts, fParts []string, pi, fi int) bool {
	if pi == len(pParts) {
		return fi == len(fParts)
	}
	if pParts[pi] == "**" {
		for next := fi; next <= len(fParts); next++ {
			if matchMemoHelper(pParts, fParts, pi+1, next) {
				return true
			}
		}
		return false
	}
	if fi == len(fParts) {
		return false
	}
	matched, err := path.Match(pParts[pi], fParts[fi])
	return err == nil && matched && matchMemoHelper(pParts, fParts, pi+1, fi+1)
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
