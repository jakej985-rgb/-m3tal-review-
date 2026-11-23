package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

var (
	filepathJoinRe = regexp.MustCompile(`\b([a-zA-Z0-9_]+)\s*(?::=|=)\s*filepath\.Join\s*\([^)\n]+,\s*([a-zA-Z0-9_]+)\s*\)`)
	fileReadRe     = regexp.MustCompile(`\b(?:os\.(?:ReadFile|Open|OpenFile|ReadDir)|ioutil\.ReadFile)\s*\(\s*([a-zA-Z0-9_]+)\s*\)`)
)

// FilepathContainmentRule detects filepath.Join calls with untrusted key/path parameters
// passed to file reads without containment validation (such as filepath.IsLocal or strings.HasPrefix).
type FilepathContainmentRule struct {
	ruleRuntime
}

func (r *FilepathContainmentRule) Name() string { return "filepath-containment-bypass" }

func (r *FilepathContainmentRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r *FilepathContainmentRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if IsTestOrFixtureFile(block.file) {
			continue
		}
		if (language.CodeChecker{}).Language(block.file) != language.LanguageGo {
			continue
		}

		code := string(maskNonCode(block.file, block.text))
		lines := strings.Split(code, "\n")
		rawLines := strings.Split(block.text, "\n")

		// Group lines into functions
		type funcSpan struct {
			start int
			end   int
		}
		var funcSpans []funcSpan
		curStart := -1
		braceDepth := 0
		for idx, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "func ") && curStart == -1 {
				curStart = idx
				braceDepth = 0
			}
			if curStart != -1 {
				for _, ch := range line {
					if ch == '{' {
						braceDepth++
					} else if ch == '}' {
						braceDepth--
						if braceDepth <= 0 {
							funcSpans = append(funcSpans, funcSpan{start: curStart, end: idx})
							curStart = -1
							break
						}
					}
				}
			}
		}
		if curStart != -1 {
			funcSpans = append(funcSpans, funcSpan{start: curStart, end: len(lines) - 1})
		}

		for _, fn := range funcSpans {
			fnLines := lines[fn.start : fn.end+1]

			type joinInfo struct {
				pathVar string
				keyVar  string
				lineIdx int
			}
			var joins []joinInfo

			for idx, line := range fnLines {
				if m := filepathJoinRe.FindStringSubmatch(line); len(m) > 2 {
					pathVar := m[1]
					keyVar := m[2]
					if keyVar != "" && keyVar != "." && keyVar != "dir" && keyVar != "base" {
						joins = append(joins, joinInfo{pathVar: pathVar, keyVar: keyVar, lineIdx: fn.start + idx})
					}
				}
			}

			if len(joins) == 0 {
				continue
			}

			for idx, line := range fnLines {
				absLine := fn.start + idx
				m := fileReadRe.FindStringSubmatch(line)
				if len(m) < 2 {
					continue
				}
				readArg := m[1]

				// Match with join
				for _, j := range joins {
					if j.pathVar != readArg || j.lineIdx >= absLine {
						continue
					}

					// Verify containment checks BEFORE this read in this same function
					keyPattern := regexp.QuoteMeta(j.keyVar)
					pathPattern := regexp.QuoteMeta(j.pathVar)

					isLocalRe := regexp.MustCompile(`\bfilepath\.IsLocal\s*\(\s*` + keyPattern + `\s*\)`)
					hasPrefixRe := regexp.MustCompile(`\bstrings\.HasPrefix\s*\([^,]+,\s*` + pathPattern + `\b|\bstrings\.HasPrefix\s*\([^)]*` + pathPattern + `[^,]*,`)
					relRe := regexp.MustCompile(`\bfilepath\.Rel\s*\([^,]+,\s*` + pathPattern + `\s*\)`)

					isProtected := false
					for k := fn.start; k < absLine; k++ {
						checkLine := lines[k]
						if isLocalRe.MatchString(checkLine) || hasPrefixRe.MatchString(checkLine) || relRe.MatchString(checkLine) {
							isProtected = true
							break
						}
					}

					if !isProtected {
						touchesAdded := block.addedLines[block.firstLine+j.lineIdx] || block.addedLines[block.firstLine+absLine]
						if !touchesAdded {
							continue
						}
						key := fmt.Sprintf("%s:%d:filepath-containment-bypass", block.file, block.firstLine+j.lineIdx)
						if seen[key] {
							continue
						}
						seen[key] = true

						snippet := ""
						if j.lineIdx < len(rawLines) {
							snippet = fmt.Sprintf("[%s:%d] (go)\n> %s\n", block.file, block.firstLine+j.lineIdx, strings.TrimSpace(rawLines[j.lineIdx]))
						}

						findings = append(findings, Finding{
							Rule:        "filepath-containment-bypass",
							Severity:    "high",
							Category:    "security",
							File:        block.file,
							Line:        block.firstLine + j.lineIdx,
							Message:     "filepath.Join with key/path parameter read without containment validation (vulnerable to traversal /dev/null bypass)",
							Remediation: "Validate path containment using filepath.IsLocal (Go 1.20+) or strings.HasPrefix(cleaned, baseDir) before reading; filepath.Join does not prevent directory traversal.",
							Confidence:  "High",
							Snippet:     snippet,
							Explanation: &model.FindingExplanation{
								RuleRationale:   "filepath.Join cleans paths but does not prevent escaping the base directory when relative segments (../) or absolute paths are provided. Input must be validated using filepath.IsLocal or prefix matching before opening or reading.",
								EvidenceSummary: fmt.Sprintf("Path %s joined from parameter %s and read on line %d without containment validation.", j.pathVar, j.keyVar, block.firstLine+absLine),
								EvidenceKind:    "security-defect",
							},
						})
					}
				}
			}
		}
	}
	return findings
}
