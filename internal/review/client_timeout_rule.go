package review

import (
	"regexp"
	"strings"
)

// ClientTimeoutRule flags http.Client composite literals that do not set a
// Timeout field. It extracts the balanced-brace literal body so Timeout
// fields are seen regardless of nesting depth (transport configs, TLS
// configs, and func literals inside the literal).
type ClientTimeoutRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (ClientTimeoutRule) Name() string { return "client-timeouts" }

// Matches the start of an http.Client composite literal. The prefix
// alternatives exclude function signatures like `func f() *http.Client {`,
// where the brace opens the function body rather than a literal.
var httpClientLiteralRe = regexp.MustCompile(`(?:=|:=|return\b|\(|,|\[|:)\s*&?\*?http\.Client\s*\{`)
var timeoutFieldRe = regexp.MustCompile(`\bTimeout\s*:`)

func (r ClientTimeoutRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") || strings.HasSuffix(block.file, "_test.go") {
			continue
		}
		code := string(maskNonCode(block.file, block.text))
		for _, m := range httpClientLiteralRe.FindAllStringIndex(code, -1) {
			open := strings.IndexByte(code[m[0]:m[1]], '{')
			if open < 0 {
				continue
			}
			body := braceBody(code, m[0]+open)
			if body == "" || timeoutFieldRe.MatchString(body) {
				continue
			}
			line := lineAtOffset(block.firstLine, code, m[0])
			if !block.addedLines[line] {
				continue
			}
			findings = append(findings, Finding{
				Rule:        "client-timeouts",
				Severity:    "low",
				File:        block.file,
				Line:        line,
				Message:     "HTTP client literal; verify Timeout is configured",
				Remediation: "Set Timeout on http.Client to avoid hanging on unresponsive servers.",
			})
		}
	}
	return findings
}

// braceBody returns the text inside the balanced braces starting at the '{'
// at offset, or "" if unbalanced within the bound.
func braceBody(code string, openOffset int) string {
	depth := 0
	for i := openOffset; i < len(code) && i < openOffset+8000; i++ {
		switch code[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return code[openOffset+1 : i]
			}
		}
	}
	return ""
}
