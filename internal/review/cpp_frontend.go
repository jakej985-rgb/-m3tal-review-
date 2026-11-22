package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// CPPUnboundedBufferRule detects calls to unbounded string and buffer manipulation
// functions (such as strcpy, strcat, sprintf, vsprintf, gets) in C and C++ source code,
// which cause stack/heap buffer overflows and memory corruption.
type CPPUnboundedBufferRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (CPPUnboundedBufferRule) Name() string {
	return "cpp-unbounded-buffer"
}

func (r CPPUnboundedBufferRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	unsafeCFunctionRe = regexp.MustCompile(
		`\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(`,
	)
)

func (r CPPUnboundedBufferRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !isCPPFile(filePath) || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func isCPPFile(path string) bool {
	ext := strings.ToLower(path)
	return strings.HasSuffix(ext, ".c") ||
		strings.HasSuffix(ext, ".cpp") ||
		strings.HasSuffix(ext, ".cc") ||
		strings.HasSuffix(ext, ".cxx") ||
		strings.HasSuffix(ext, ".h") ||
		strings.HasSuffix(ext, ".hpp") ||
		strings.HasSuffix(ext, ".hxx")
}

func (r CPPUnboundedBufferRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		m := unsafeCFunctionRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}

		findingLine := block.firstLine + i
		if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
			continue
		}

		fnName := m[1]
		key := fmt.Sprintf("%s:%d:cpp-unbounded-buffer:%s", block.file, findingLine, fnName)
		if seen[key] {
			continue
		}
		seen[key] = true

		safeAlt := "strncpy"
		switch fnName {
		case "strcat":
			safeAlt = "strncat"
		case "sprintf":
			safeAlt = "snprintf"
		case "vsprintf":
			safeAlt = "vsnprintf"
		case "gets":
			safeAlt = "fgets"
		}

		findings = append(findings, Finding{
			File:        block.file,
			Line:        findingLine,
			Rule:        "cpp-unbounded-buffer",
			Severity:    "high",
			Category:    "security",
			Confidence:  "high",
			Message:     fmt.Sprintf("Unbounded buffer copy hazard: function %q does not enforce destination buffer bounds, risking memory corruption.", fnName),
			Remediation: fmt.Sprintf("Replace %s with bounds-enforcing alternative %s(...) or use C++ std::string / std::span.", fnName, safeAlt),
		})
	}

	return findings
}
