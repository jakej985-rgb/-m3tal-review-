package review

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

var (
	filepathJoinCallRe = regexp.MustCompile(`\b(?:([a-zA-Z0-9_]+)\s*(?::=|=)\s*)?(?:filepath\.Clean\s*\(\s*)?filepath\.Join\s*\(([^;\n]+)\)`)
	filepathCleanRe    = regexp.MustCompile(`\b([a-zA-Z0-9_]+)\s*(?::=|=)\s*filepath\.Clean\s*\(\s*([a-zA-Z0-9_]+)\s*\)`)
	fileReadCallRe     = regexp.MustCompile(`\b(?:os\.(?:ReadFile|Open|OpenFile|ReadDir)|ioutil\.ReadFile)\s*\(\s*(?:filepath\.Clean\s*\(\s*)?([a-zA-Z0-9_]+)\s*\)?\s*\)`)
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

func isStringLiteral(s string) bool {
	s = strings.TrimSpace(s)
	return (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
		(strings.HasPrefix(s, "`") && strings.HasSuffix(s, "`"))
}

func extractStringConstants(rawText string) map[string]bool {
	consts := make(map[string]bool)

	// Single const: const Name [type] = "..."
	singleRe := regexp.MustCompile(`\bconst\s+([a-zA-Z0-9_]+)(?:\s+[a-zA-Z0-9_]+)?\s*=\s*(?:"[^"\n]*"|` + "`[^`]*`" + `)`)
	for _, m := range singleRe.FindAllStringSubmatch(rawText, -1) {
		if len(m) > 1 {
			consts[m[1]] = true
		}
	}

	// Const blocks: const ( ... )
	blockRe := regexp.MustCompile(`(?s)\bconst\s*\((.*?)\)`)
	itemRe := regexp.MustCompile(`\b([a-zA-Z0-9_]+)(?:\s+[a-zA-Z0-9_]+)?\s*=\s*(?:"[^"\n]*"|` + "`[^`]*`" + `)`)
	for _, b := range blockRe.FindAllStringSubmatch(rawText, -1) {
		if len(b) > 1 {
			for _, m := range itemRe.FindAllStringSubmatch(b[1], -1) {
				if len(m) > 1 {
					consts[m[1]] = true
				}
			}
		}
	}
	return consts
}

type funcSpan struct {
	start int
	end   int
}

func extractFuncSpans(lines []string) []funcSpan {
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
	return funcSpans
}

func extractPackageConstants(rawLines []string, funcSpans []funcSpan) map[string]bool {
	inFunc := make(map[int]bool)
	for _, fn := range funcSpans {
		for i := fn.start; i <= fn.end; i++ {
			inFunc[i] = true
		}
	}
	var pkgLines []string
	for i, l := range rawLines {
		if !inFunc[i] {
			pkgLines = append(pkgLines, l)
		}
	}
	return extractStringConstants(strings.Join(pkgLines, "\n"))
}

func extractFuncParams(rawLines []string, fnStart, fnEnd int) map[string]bool {
	params := make(map[string]bool)

	header := ""
	for i := fnStart; i <= fnEnd && i < len(rawLines); i++ {
		header += " " + rawLines[i]
		if strings.Contains(rawLines[i], "{") {
			break
		}
	}

	var parenGroups []string
	pDepth := 0
	pStart := -1
	for idx, ch := range header {
		if ch == '(' {
			if pDepth == 0 {
				pStart = idx + 1
			}
			pDepth++
		} else if ch == ')' {
			pDepth--
			if pDepth == 0 && pStart != -1 {
				parenGroups = append(parenGroups, header[pStart:idx])
				pStart = -1
			}
		}
	}

	identRe := regexp.MustCompile(`^[a-zA-Z_]\w*$`)
	for _, group := range parenGroups {
		for _, decl := range strings.Split(group, ",") {
			decl = strings.TrimSpace(decl)
			fields := strings.Fields(decl)
			if len(fields) >= 2 {
				for _, f := range fields[:len(fields)-1] {
					f = strings.Trim(f, " \t,")
					if identRe.MatchString(f) {
						params[f] = true
					}
				}
			}
		}
	}
	return params
}

func (r *FilepathContainmentRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	blocks := sourceBlocks(diff, r.repositoryRoot, r.workingTree)
	filePackageConstants := make(map[string]map[string]bool)

	for _, block := range blocks {
		if IsTestOrFixtureFile(block.file) {
			continue
		}
		if (language.CodeChecker{}).Language(block.file) != language.LanguageGo {
			continue
		}
		code := string(maskNonCode(block.file, block.text))
		lines := strings.Split(code, "\n")
		rawLines := strings.Split(block.text, "\n")
		spans := extractFuncSpans(lines)
		pkgConsts := extractPackageConstants(rawLines, spans)
		if filePackageConstants[block.file] == nil {
			filePackageConstants[block.file] = make(map[string]bool)
		}
		for k, v := range pkgConsts {
			if v {
				filePackageConstants[block.file][k] = true
			}
		}
	}

	for _, block := range blocks {
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

		funcSpans := extractFuncSpans(lines)
		packageConstants := filePackageConstants[block.file]

		for _, fn := range funcSpans {
			fnLines := lines[fn.start : fn.end+1]
			fnRawLines := rawLines[fn.start : fn.end+1]
			fnLocalConstants := extractStringConstants(strings.Join(fnRawLines, "\n"))
			params := extractFuncParams(rawLines, fn.start, fn.end)

			type joinInfo struct {
				pathVars    []string // all aliases, including cleaned
				dynamicKeys []string
				lineIdx     int
			}
			var joins []joinInfo

			type scopedVar struct {
				name      string
				depth     int
				isIfInit  bool
				stmtDepth int
			}
			var scopedVars []scopedVar
			curDepth := 0

			assignRe := regexp.MustCompile(`\b([a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s*:=`)
			varDeclRe := regexp.MustCompile(`\bvar\s+([a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)`)

			type lineEvent struct {
				pos      int
				kind     int // 1: '{', 2: '}', 3: decl, 4: join call
				idents   []string
				joinCall []string
			}

			// Pass 1: detect joins with untrusted/non-literal segments tracking lexical scope
			for idx, line := range fnLines {
				var events []lineEvent

				for i, ch := range line {
					if ch == '{' {
						events = append(events, lineEvent{pos: i, kind: 1})
					} else if ch == '}' {
						events = append(events, lineEvent{pos: i, kind: 2})
					}
				}

				for _, loc := range assignRe.FindAllStringSubmatchIndex(line, -1) {
					pos := loc[0]
					matched := line[loc[2]:loc[3]]
					var ids []string
					for _, part := range strings.Split(matched, ",") {
						part = strings.TrimSpace(part)
						if part != "" && part != "_" {
							ids = append(ids, part)
						}
					}
					if len(ids) > 0 {
						events = append(events, lineEvent{pos: pos, kind: 3, idents: ids})
					}
				}

				for _, loc := range varDeclRe.FindAllStringSubmatchIndex(line, -1) {
					pos := loc[0]
					matched := line[loc[2]:loc[3]]
					var ids []string
					for _, part := range strings.Split(matched, ",") {
						part = strings.TrimSpace(part)
						if part != "" && part != "_" {
							ids = append(ids, part)
						}
					}
					if len(ids) > 0 {
						events = append(events, lineEvent{pos: pos, kind: 3, idents: ids})
					}
				}

				for _, loc := range filepathJoinCallRe.FindAllStringSubmatchIndex(line, -1) {
					pos := loc[0]
					var submatches []string
					for k := 0; k < len(loc); k += 2 {
						if loc[k] >= 0 && loc[k+1] >= 0 {
							submatches = append(submatches, line[loc[k]:loc[k+1]])
						} else {
							submatches = append(submatches, "")
						}
					}
					events = append(events, lineEvent{pos: pos, kind: 4, joinCall: submatches})
				}

				sort.SliceStable(events, func(a, b int) bool {
					if events[a].pos != events[b].pos {
						return events[a].pos < events[b].pos
					}
					return events[a].kind < events[b].kind
				})

				isElseFollows := func(lineIdx, charPos int) bool {
					rest := line[charPos+1:]
					if regexp.MustCompile(`\belse\b`).MatchString(rest) {
						return true
					}
					for k := lineIdx + 1; k < len(fnLines); k++ {
						trimmed := strings.TrimSpace(fnLines[k])
						if trimmed == "" {
							continue
						}
						return regexp.MustCompile(`^else(?:\s|\{|$|\b)`).MatchString(trimmed)
					}
					return false
				}

				for _, ev := range events {
					switch ev.kind {
					case 1:
						curDepth++
					case 2:
						curDepth--
						elseFollows := isElseFollows(idx, ev.pos)
						var remaining []scopedVar
						for _, sv := range scopedVars {
							if sv.isIfInit {
								if curDepth > sv.stmtDepth || (curDepth == sv.stmtDepth && elseFollows) {
									remaining = append(remaining, sv)
								}
							} else {
								if sv.depth <= curDepth {
									remaining = append(remaining, sv)
								}
							}
						}
						scopedVars = remaining
					case 3:
						declDepth := curDepth
						prefix := line[:ev.pos]
						isIf := regexp.MustCompile(`\bif\b[^{]*$`).MatchString(prefix)
						isForSwitch := regexp.MustCompile(`\b(?:for|switch)\b[^{]*$`).MatchString(prefix)
						if isIf {
							for _, id := range ev.idents {
								scopedVars = append(scopedVars, scopedVar{name: id, depth: curDepth + 1, isIfInit: true, stmtDepth: curDepth})
							}
						} else {
							if isForSwitch {
								declDepth = curDepth + 1
							}
							for _, id := range ev.idents {
								scopedVars = append(scopedVars, scopedVar{name: id, depth: declDepth})
							}
						}
					case 4:
						m := ev.joinCall
						if len(m) > 2 {
							assignedVar := m[1]
							argsStr := m[2]
							args := splitCallArgs(argsStr)
							if len(args) < 2 {
								continue
							}

							isShadowed := func(seg string) bool {
								if params[seg] {
									return true
								}
								for _, sv := range scopedVars {
									if sv.name == seg {
										if sv.isIfInit {
											if curDepth > sv.stmtDepth {
												return true
											}
										} else {
											return true
										}
									}
								}
								return false
							}

							var dynamicKeys []string
							for _, seg := range args[1:] {
								seg = strings.TrimSpace(seg)
								isConstant := seg == "" || isStringLiteral(seg) || seg == "." || seg == `""` ||
									fnLocalConstants[seg] || (packageConstants[seg] && !isShadowed(seg))
								if isConstant {
									continue
								}
								dynamicKeys = append(dynamicKeys, seg)
							}

							if len(dynamicKeys) > 0 && assignedVar != "" {
								joins = append(joins, joinInfo{
									pathVars:    []string{assignedVar},
									dynamicKeys: dynamicKeys,
									lineIdx:     fn.start + idx,
								})
							}
						}
					}
				}
			}

			if len(joins) == 0 {
				continue
			}

			// Pass 2: track aliases via filepath.Clean(p)
			for _, line := range fnLines {
				if m := filepathCleanRe.FindStringSubmatch(line); len(m) > 2 {
					cleanVar := m[1]
					origVar := m[2]
					for i := range joins {
						hasOrig := false
						for _, pv := range joins[i].pathVars {
							if pv == origVar {
								hasOrig = true
								break
							}
						}
						if hasOrig {
							joins[i].pathVars = append(joins[i].pathVars, cleanVar)
						}
					}
				}
			}

			// Pass 3: match file reads
			for idx, line := range fnLines {
				absLine := fn.start + idx
				m := fileReadCallRe.FindStringSubmatch(line)
				if len(m) < 2 {
					continue
				}
				readArg := m[1]

				for _, j := range joins {
					isMatchingPath := false
					for _, pv := range j.pathVars {
						if pv == readArg {
							isMatchingPath = true
							break
						}
					}
					if !isMatchingPath || j.lineIdx >= absLine {
						continue
					}

					// Verify containment checks BEFORE this read in this same function
					var pathPatterns []string
					for _, pv := range j.pathVars {
						pathPatterns = append(pathPatterns, regexp.QuoteMeta(pv))
					}
					pathUnion := strings.Join(pathPatterns, "|")

					hasPrefixRe := regexp.MustCompile(`\bstrings\.HasPrefix\s*\([^,]+,\s*(?:` + pathUnion + `)\b|\bstrings\.HasPrefix\s*\([^)]*(?:` + pathUnion + `)[^,]*,`)
					relRe := regexp.MustCompile(`\bfilepath\.Rel\s*\([^,]+,\s*(?:` + pathUnion + `)\s*\)`)

					finalPathProtected := false
					for k := fn.start; k < absLine; k++ {
						checkLine := lines[k]
						if hasPrefixRe.MatchString(checkLine) || relRe.MatchString(checkLine) {
							finalPathProtected = true
							break
						}
					}

					allKeysProtected := false
					if !finalPathProtected {
						allKeysProtected = true
						for _, dynamicKey := range j.dynamicKeys {
							keyPattern := regexp.QuoteMeta(dynamicKey)
							parts := strings.Split(dynamicKey, ".")
							shortKey := parts[len(parts)-1]
							if shortKey != "" && shortKey != dynamicKey {
								keyPattern += "|" + regexp.QuoteMeta(shortKey)
							}
							isLocalRe := regexp.MustCompile(`\bfilepath\.IsLocal\s*\(\s*(?:` + keyPattern + `)\s*\)`)

							keyChecked := false
							for k := fn.start; k < absLine; k++ {
								if isLocalRe.MatchString(lines[k]) {
									keyChecked = true
									break
								}
							}
							if !keyChecked {
								allKeysProtected = false
								break
							}
						}
					}

					isProtected := finalPathProtected || allKeysProtected

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
								EvidenceSummary: fmt.Sprintf("Path %v joined from parameter %v and read on line %d without containment validation.", j.pathVars, j.dynamicKeys, block.firstLine+absLine),
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

func splitCallArgs(s string) []string {
	var args []string
	parenDepth := 0
	inQuote := false
	var quoteChar rune
	start := 0

	for i, ch := range s {
		if inQuote {
			if ch == quoteChar {
				inQuote = false
			}
			continue
		}
		if ch == '"' || ch == '`' || ch == '\'' {
			inQuote = true
			quoteChar = ch
			continue
		}
		if ch == '(' || ch == '[' || ch == '{' {
			parenDepth++
			continue
		}
		if ch == ')' || ch == ']' || ch == '}' {
			parenDepth--
			continue
		}
		if ch == ',' && parenDepth == 0 {
			args = append(args, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if start < len(s) {
		args = append(args, strings.TrimSpace(s[start:]))
	}
	return args
}
