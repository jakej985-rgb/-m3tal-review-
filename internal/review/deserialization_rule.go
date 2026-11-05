package review

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// DeserializationRule flags deserializers that can execute arbitrary code or
// instantiate unsafe objects when fed untrusted input.
type DeserializationRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (DeserializationRule) Name() string {
	return "unsafe-deserialization"
}

var unsafeDeserializationPatterns = []struct {
	language language.CodeLanguage
	pattern  *regexp.Regexp
	message  string
}{
	{
		language: language.LanguagePython,
		pattern:  regexp.MustCompile(`\b(?:pickle|cPickle|dill|shelve|marshal)\.(?:load|loads)\s*\(`),
		message:  "Unsafe deserialization can execute arbitrary code; use JSON or a restricted format",
	},
	{
		language: language.LanguagePython,
		pattern:  regexp.MustCompile(`\byaml\.unsafe_load\s*\(|\byaml\.load\s*\(`),
		message:  "yaml.load without a verified SafeLoader can construct arbitrary Python objects",
	},
	{
		language: language.LanguagePython,
		pattern:  regexp.MustCompile(`\bjsonpickle\.(?:decode|loads)\s*\(`),
		message:  "jsonpickle can instantiate arbitrary Python objects; avoid decoding untrusted data",
	},
	{
		language: language.LanguagePHP,
		pattern:  regexp.MustCompile(`\bunserialize\s*\(`),
		message:  "unserialize on untrusted data can instantiate arbitrary objects; use json_decode",
	},
	{
		language: language.LanguageJavaScript,
		pattern:  regexp.MustCompile(`\brequire\s*\(\s*['"](?:node-serialize|funcster|serialize-javascript)['"]`),
		message:  "Insecure serialization library can execute arbitrary code; use JSON",
	},
}

func (r DeserializationRule) Check(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		fileLanguage := (language.CodeChecker{}).Language(block.file)
		code := string(maskNonCode(block.file, block.text))
		for _, unsafePattern := range unsafeDeserializationPatterns {
			if unsafePattern.language != fileLanguage {
				continue
			}
			for _, match := range unsafePattern.pattern.FindAllStringIndex(code, -1) {
				if unsafePattern.message == unsafeYamlMessage && safeYAMLLoaderNearby(code, match[1]) {
					continue
				}
				if !matchTouchesAdded(block, code, match[0], match[1]) {
					continue
				}
				line := lineAtOffset(block.firstLine, code, match[0])
				key := block.file + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        "unsafe-deserialization",
					Severity:    "high",
					File:        block.file,
					Line:        line,
					Message:     unsafePattern.message,
					Remediation: "Use a safe data format (JSON, protobuf) or restrict the deserializer's allowed types.",
				})
			}
		}
	}
	return findings
}

const unsafeYamlMessage = "yaml.load without a verified SafeLoader can construct arbitrary Python objects"

// safeYAMLLoaderNearby reports whether the yaml.load call at offset end
// explicitly selects a safe loader within the call's argument window.
func safeYAMLLoaderNearby(code string, callEnd int) bool {
	window := code[callEnd:]
	if len(window) > 400 {
		window = window[:400]
	}
	return strings.Contains(window, "SafeLoader") || strings.Contains(window, "CSafeLoader")
}
