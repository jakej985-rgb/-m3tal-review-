package review

import (
	"path"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

type DebugRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (DebugRule) Name() string {
	return "debug-leftover"
}

var debugPatterns = []struct {
	pattern *regexp.Regexp
	message string
}{
	{
		pattern: regexp.MustCompile(`\bfmt\.Print(?:ln|f)?\s*\(`),
		message: "Debug print statement detected",
	},
	{
		pattern: regexp.MustCompile(`\bconsole\.log\s*\(`),
		message: "Console log statement detected",
	},
	{
		pattern: regexp.MustCompile(`\bdebugger\s*;?`),
		message: "Debugger statement detected",
	},
}

func (r DebugRule) Check(diff string) []Finding {
	var findings []Finding
	for _, fileDiff := range ParseDiff(diff) {
		if (language.CodeChecker{}).Language(fileDiff.Path) == language.LanguageUnknown && !language.IsLikelySourceFile(fileDiff.Path) {
			continue
		}
		// Performance optimization: Generate diff source blocks directly from fileDiff
		// instead of re-parsing the entire diff and scanning for fileDiff.Path.
		blocks := fileDiffSourceBlocks(fileDiff)
		if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
			blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
		}
		for _, block := range blocks {
			findings = append(findings, debugFindingsForBlock(block)...)
		}
	}

	return findings
}

func debugFindingsForBlock(block diffSourceBlock) []Finding {
	code := string(maskNonCode(block.file, block.text))
	var findings []Finding
	for _, debugPattern := range debugPatterns {
		// CLI packages commonly use fmt.Print for their intended user interface.
		if debugPattern.message == "Debug print statement detected" && isCLIOutputFile(block.file) {
			continue
		}
		// Processes that speak a line-delimited protocol over stdin/stdout
		// (JSON-RPC plugins, agents) use fmt.Print* as the protocol channel,
		// not as debug output; real logging goes to stderr.
		if debugPattern.message == "Debug print statement detected" && isStdioProtocolFile(block.file, block.text) {
			continue
		}
		// Dev tooling (CI helper scripts, build/test tooling) legitimately logs
		// to stdout/stderr; debug leftovers there are not shipped-code defects.
		if debugPattern.message != "Debugger statement detected" && isToolingFile(block.file) {
			continue
		}
		for _, match := range debugPattern.pattern.FindAllStringIndex(code, -1) {
			if !matchTouchesAdded(block, code, match[0], match[1]) {
				continue
			}
			findings = append(findings, Finding{
				Rule:        "debug-leftover",
				Severity:    "medium",
				File:        block.file,
				Line:        lineAtOffset(block.firstLine, code, match[0]),
				Message:     debugPattern.message,
				Remediation: "Remove debug output before merging, or replace it with the project's approved logging.",
			})
			break
		}
	}
	return findings
}

func isCLIOutputFile(file string) bool {
	clean := "/" + strings.TrimPrefix(path.Clean(file), "/") + "/"
	return strings.Contains(clean, "/internal/cli/") || strings.Contains(clean, "/cmd/")
}

// isStdioProtocolFile reports whether the file implements a request/response
// protocol on stdin/stdout: it scans os.Stdin for framed input and serializes
// responses (json.Marshal/Encoder) to stdout. fmt.Print* there is the wire
// protocol, not leftover debugging.
func isStdioProtocolFile(file string, text string) bool {
	if !strings.HasSuffix(file, ".go") {
		return false
	}
	return strings.Contains(text, "bufio.NewScanner(os.Stdin)") &&
		(strings.Contains(text, "json.Marshal") || strings.Contains(text, "json.NewEncoder(os.Stdout)"))
}

// isToolingFile reports whether the path is development/CI tooling rather
// than shipped application code.
func isToolingFile(file string) bool {
	clean := "/" + strings.TrimPrefix(path.Clean(file), "/") + "/"
	for _, dir := range []string{"/.github/", "/scripts/", "/tools/", "/test/", "/tests/", "/testing/", "/examples/", "/benchmarks/"} {
		if strings.Contains(clean, dir) {
			return true
		}
	}
	return false
}
