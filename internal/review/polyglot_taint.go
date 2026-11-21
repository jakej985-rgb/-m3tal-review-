package review

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

var (
	// Python patterns
	pyFuncDefRe = regexp.MustCompile(`(?m)^\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\):`)
	pyRouteDecoratorRe = regexp.MustCompile(`@(?:app|router|bp|blueprint|api_router)\.(?:get|post|put|delete|patch|route)\b`)
	pyFlaskSourceRe = regexp.MustCompile(`\brequest\.(?:args|form|values|json|get_json|data|files|headers|cookies)\b`)
	pyFastAPISourceRe = regexp.MustCompile(`\b(?:request\.query_params|Query\s*\(|Body\s*\(|request\.body\s*\()`)
	pyAssignRe = regexp.MustCompile(`(?m)^\s*([A-Za-z_]\w*)\s*=\s*([^\n#]{1,300})`)
	pyGuardCallRe = regexp.MustCompile(`\b(?:int|float|shlex\.quote|html\.escape|re\.escape|sanitize\w*|validate\w*|clean\w*|escape\w*)\s*\(`)
	pySQLSinkRe = regexp.MustCompile(`\b(?:cursor|conn|connection|db|session|engine)\.(?:execute|executemany)\s*\(`)
	pyShellSinkRe = regexp.MustCompile(`\b(?:os\.(?:system|popen)|subprocess\.(?:run|Popen|call|check_output|check_call))\s*\(`)

	// TypeScript / JavaScript patterns
	tsFuncDefRe = regexp.MustCompile(`(?m)(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$]\w*)\s*\(([^)]*)\)|(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$]\w*)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*=>`)
	tsExpressSourceRe = regexp.MustCompile(`\b(?:req|request)\.(?:query|body|params|headers|cookies)\b`)
	tsNextSourceRe = regexp.MustCompile(`\b(?:request\.nextUrl\.searchParams|searchParams\.get|request\.json\s*\(\))`)
	tsAssignRe = regexp.MustCompile(`(?m)(?:const|let|var)\s+([$\w]+)\s*=\s*([^\n;]{1,300})`)
	tsDestructureRe = regexp.MustCompile(`(?m)(?:const|let|var)\s*\{([^}]+)\}\s*=\s*([^\n;]{1,300})`)
	tsGuardCallRe = regexp.MustCompile(`\b(?:encodeURIComponent|parseInt|parseFloat|Number|DOMPurify\.sanitize|sanitize\w*|validate\w*|escape\w*)\s*\(`)
	tsSQLSinkRe = regexp.MustCompile(`\b(?:db|pool|client|prisma|knex|sequelize)\.(?:query|raw|\$queryRaw|\$executeRaw)\s*\(`)
	tsShellSinkRe = regexp.MustCompile(`(?:child_process\.)?\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(`)
)

type polyglotFunc struct {
	name      string
	params    []string
	file      string
	blockIdx  int
	startLine int
	endLine   int
	isRoute   bool
}

func isPythonFile(path string) bool {
	lower := strings.ToLower(path)
	return strings.HasSuffix(lower, ".py") && !isTestFile(path)
}

func isTypeScriptFile(path string) bool {
	lower := strings.ToLower(path)
	return (strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".tsx") ||
		strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".jsx") ||
		strings.HasSuffix(lower, ".mjs") || strings.HasSuffix(lower, ".cjs")) && !isTestFile(path)
}

// splitPyParams parses parameter names from a Python parameter list string.
func splitPyParams(paramStr string) []string {
	var params []string
	parts := strings.Split(paramStr, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "self" || p == "cls" || p == "*" || p == "/" || strings.HasPrefix(p, "**") {
			continue
		}
		// Drop type annotations and defaults: `user_id: int = 1` -> `user_id`
		if idx := strings.IndexAny(p, ":="); idx >= 0 {
			p = strings.TrimSpace(p[:idx])
		}
		if p != "" {
			params = append(params, p)
		}
	}
	return params
}

// splitTSParams parses parameter names from a TypeScript/JavaScript parameter list string.
func splitTSParams(paramStr string) []string {
	var params []string
	parts := strings.Split(paramStr, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// Strip TS type annotations or defaults: `id: string = ""` -> `id`
		if idx := strings.IndexAny(p, ":="); idx >= 0 {
			p = strings.TrimSpace(p[:idx])
		}
		p = strings.TrimPrefix(p, "...")
		p = strings.TrimSpace(p)
		if p != "" && !strings.Contains(p, "{") && !strings.Contains(p, "[") {
			params = append(params, p)
		}
	}
	return params
}

// checkPythonCrossFile performs cross-file and intra-file taint tracing for Python
// applications using FastAPI or Flask into SQL or shell command execution sinks.
func checkPythonCrossFile(blocks []diffSourceBlock) []Finding {
	if len(blocks) == 0 {
		return nil
	}

	funcs := make([]polyglotFunc, 0)
	sigs := make(map[string]polyglotFunc)

	for bIdx, block := range blocks {
		lines := strings.Split(block.text, "\n")
		for i, line := range lines {
			m := pyFuncDefRe.FindStringSubmatch(line)
			if len(m) >= 3 {
				fnName := m[1]
				params := splitPyParams(m[2])
				isRoute := false
				// Check preceding lines for decorators
				for j := i - 1; j >= 0 && j >= i-3; j-- {
					if pyRouteDecoratorRe.MatchString(lines[j]) {
						isRoute = true
						break
					}
				}
				fn := polyglotFunc{
					name:      fnName,
					params:    params,
					file:      block.file,
					blockIdx:  bIdx,
					startLine: block.firstLine + i,
					isRoute:   isRoute,
				}
				funcs = append(funcs, fn)
				sigs[fnName] = fn
			}
		}
	}

	// 1. Initial seeds per function
	funcSeeds := make([]map[string]bool, len(funcs))
	for i, fn := range funcs {
		seeds := make(map[string]bool)
		block := blocks[fn.blockIdx]
		lines := strings.Split(block.text, "\n")
		// Route handler parameters are automatically seeded as untrusted inputs
		if fn.isRoute {
			for _, p := range fn.params {
				if p != "db" && p != "session" && p != "request" {
					seeds[p] = true
				}
			}
		}
		// Check for local Flask/FastAPI source reads
		for _, line := range lines {
			if pyFlaskSourceRe.MatchString(line) || pyFastAPISourceRe.MatchString(line) {
				assignMatches := pyAssignRe.FindStringSubmatch(line)
				if len(assignMatches) >= 3 {
					lhs := assignMatches[1]
					rhs := assignMatches[2]
					if !pyGuardCallRe.MatchString(rhs) {
						seeds[lhs] = true
					}
				}
			}
		}
		funcSeeds[i] = seeds
	}

	// 2. Fixpoint iteration over call edges across functions and files
	paramTaint := make(map[string]map[string]bool)
	for pass := 0; pass < 4; pass++ {
		changed := false
		for i, fn := range funcs {
			block := blocks[fn.blockIdx]
			lines := strings.Split(block.text, "\n")
			localTaint := make(map[string]bool)
			for s := range funcSeeds[i] {
				localTaint[s] = true
			}
			for p := range paramTaint[fn.name] {
				localTaint[p] = true
			}

			// Propagate assignments inside function
			for _, line := range lines {
				assignMatches := pyAssignRe.FindStringSubmatch(line)
				if len(assignMatches) >= 3 {
					lhs := assignMatches[1]
					rhs := assignMatches[2]
					if !pyGuardCallRe.MatchString(rhs) {
						for t := range localTaint {
							if strings.Contains(rhs, t) {
								if !localTaint[lhs] {
									localTaint[lhs] = true
								}
								break
							}
						}
					}
				}

				// Check function calls: fnCall(arg1, arg2)
				for calleeName, calleeFn := range sigs {
					if calleeName == fn.name {
						continue
					}
					callPattern := calleeName + `\s*\(([^)]*)\)`
					re := regexp.MustCompile(callPattern)
					m := re.FindStringSubmatch(line)
					if len(m) >= 2 {
						args := strings.Split(m[1], ",")
						for argIdx, arg := range args {
							arg = strings.TrimSpace(arg)
							for t := range localTaint {
								if strings.Contains(arg, t) {
									// Taint corresponding callee param
									if argIdx < len(calleeFn.params) {
										calleeParam := calleeFn.params[argIdx]
										if paramTaint[calleeName] == nil {
											paramTaint[calleeName] = make(map[string]bool)
										}
										if !paramTaint[calleeName][calleeParam] {
											paramTaint[calleeName][calleeParam] = true
											changed = true
										}
									}
									break
								}
							}
						}
					}
				}
			}
		}
		if !changed {
			break
		}
	}

	// 3. Scan for sinks with converged taint
	var findings []Finding
	seen := make(map[string]bool)

	for i, fn := range funcs {
		block := blocks[fn.blockIdx]
		lines := strings.Split(block.text, "\n")
		localTaint := make(map[string]bool)
		for s := range funcSeeds[i] {
			localTaint[s] = true
		}
		for p := range paramTaint[fn.name] {
			localTaint[p] = true
		}

		for lineIdx, line := range lines {
			lineNum := block.firstLine + lineIdx

			// Local assignment propagation
			assignMatches := pyAssignRe.FindStringSubmatch(line)
			if len(assignMatches) >= 3 {
				lhs := assignMatches[1]
				rhs := assignMatches[2]
				if !pyGuardCallRe.MatchString(rhs) {
					for t := range localTaint {
						if strings.Contains(rhs, t) {
							localTaint[lhs] = true
							break
						}
					}
				}
			}

			// Only report on added or modified lines in diff
			if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
				continue
			}

			// Check SQL sinks
			if pySQLSinkRe.MatchString(line) {
				for t := range localTaint {
					if strings.Contains(line, t) {
						key := fmt.Sprintf("%s:%d:sql", block.file, lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "request-taint",
								Severity:    "high",
								Category:    "security",
								Confidence:  "High",
								File:        block.file,
								Line:        lineNum,
								Message:     fmt.Sprintf("Tainted request data flows into SQL sink; untrusted variable %q passed to database execute", t),
								Remediation: "Use parameterized queries (e.g. cursor.execute('SELECT ... WHERE id = %s', (id,))) instead of formatting untrusted input.",
								Explanation: &model.FindingExplanation{
									RuleRationale:   "Untrusted user input interpolated into database queries enables SQL injection.",
									EvidenceSummary: fmt.Sprintf("Variable %q carrying request taint reaches database query execution.", t),
									EvidenceKind:    "taint-flow",
								},
							})
						}
						break
					}
				}
			}

			// Check Shell sinks
			if pyShellSinkRe.MatchString(line) {
				for t := range localTaint {
					if strings.Contains(line, t) {
						key := fmt.Sprintf("%s:%d:shell", block.file, lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "request-taint",
								Severity:    "high",
								Category:    "security",
								Confidence:  "High",
								File:        block.file,
								Line:        lineNum,
								Message:     fmt.Sprintf("Tainted request data flows into shell command sink; untrusted variable %q passed to execution call", t),
								Remediation: "Avoid shell command execution with untrusted input; pass argument lists to subprocess.run(shell=False).",
								Explanation: &model.FindingExplanation{
									RuleRationale:   "Untrusted input passed to shell commands enables remote arbitrary command execution.",
									EvidenceSummary: fmt.Sprintf("Variable %q carrying request taint reaches shell execution.", t),
									EvidenceKind:    "taint-flow",
								},
							})
						}
						break
					}
				}
			}
		}
	}

	return findings
}

// checkTypeScriptCrossFile performs cross-file and intra-file taint tracing for
// TypeScript and JavaScript applications using Express or Next.js.
func checkTypeScriptCrossFile(blocks []diffSourceBlock) []Finding {
	if len(blocks) == 0 {
		return nil
	}

	funcs := make([]polyglotFunc, 0)
	sigs := make(map[string]polyglotFunc)

	for bIdx, block := range blocks {
		lines := strings.Split(block.text, "\n")
		for i, line := range lines {
			m := tsFuncDefRe.FindStringSubmatch(line)
			if len(m) >= 5 {
				fnName := m[1]
				paramStr := m[2]
				if fnName == "" {
					fnName = m[3]
					paramStr = m[4]
				}
				if fnName != "" {
					params := splitTSParams(paramStr)
					fn := polyglotFunc{
						name:      fnName,
						params:    params,
						file:      block.file,
						blockIdx:  bIdx,
						startLine: block.firstLine + i,
					}
					funcs = append(funcs, fn)
					sigs[fnName] = fn
				}
			}
		}
	}

	// 1. Initial seeds per function
	funcSeeds := make([]map[string]bool, len(funcs))
	for i, fn := range funcs {
		seeds := make(map[string]bool)
		block := blocks[fn.blockIdx]
		lines := strings.Split(block.text, "\n")

		for _, line := range lines {
			if tsExpressSourceRe.MatchString(line) || tsNextSourceRe.MatchString(line) {
				// Destructuring: const { id, name } = req.query;
				if dest := tsDestructureRe.FindStringSubmatch(line); len(dest) >= 3 {
					rhs := dest[2]
					if !tsGuardCallRe.MatchString(rhs) {
						for _, id := range strings.Split(dest[1], ",") {
							id = strings.TrimSpace(id)
							if id != "" {
								seeds[id] = true
							}
						}
					}
				}
				// Plain assignment: const id = req.query.id;
				if assign := tsAssignRe.FindStringSubmatch(line); len(assign) >= 3 {
					lhs := assign[1]
					rhs := assign[2]
					if !tsGuardCallRe.MatchString(rhs) {
						seeds[lhs] = true
					}
				}
			}
		}
		funcSeeds[i] = seeds
	}

	// 2. Fixpoint iteration over call edges across functions and files
	paramTaint := make(map[string]map[string]bool)
	for pass := 0; pass < 4; pass++ {
		changed := false
		for i, fn := range funcs {
			block := blocks[fn.blockIdx]
			lines := strings.Split(block.text, "\n")
			localTaint := make(map[string]bool)
			for s := range funcSeeds[i] {
				localTaint[s] = true
			}
			for p := range paramTaint[fn.name] {
				localTaint[p] = true
			}

			// Propagate assignments
			for _, line := range lines {
				if assign := tsAssignRe.FindStringSubmatch(line); len(assign) >= 3 {
					lhs := assign[1]
					rhs := assign[2]
					if !tsGuardCallRe.MatchString(rhs) {
						for t := range localTaint {
							if strings.Contains(rhs, t) {
								if !localTaint[lhs] {
									localTaint[lhs] = true
								}
								break
							}
						}
					}
				}

				// Check call edges: calleeFn(arg1, arg2)
				for calleeName, calleeFn := range sigs {
					if calleeName == fn.name {
						continue
					}
					callPattern := calleeName + `\s*\(([^)]*)\)`
					re := regexp.MustCompile(callPattern)
					m := re.FindStringSubmatch(line)
					if len(m) >= 2 {
						args := strings.Split(m[1], ",")
						for argIdx, arg := range args {
							arg = strings.TrimSpace(arg)
							for t := range localTaint {
								if strings.Contains(arg, t) {
									if argIdx < len(calleeFn.params) {
										calleeParam := calleeFn.params[argIdx]
										if paramTaint[calleeName] == nil {
											paramTaint[calleeName] = make(map[string]bool)
										}
										if !paramTaint[calleeName][calleeParam] {
											paramTaint[calleeName][calleeParam] = true
											changed = true
										}
									}
									break
								}
							}
						}
					}
				}
			}
		}
		if !changed {
			break
		}
	}

	// 3. Scan for sinks with converged taint
	var findings []Finding
	seen := make(map[string]bool)

	for i, fn := range funcs {
		block := blocks[fn.blockIdx]
		lines := strings.Split(block.text, "\n")
		localTaint := make(map[string]bool)
		for s := range funcSeeds[i] {
			localTaint[s] = true
		}
		for p := range paramTaint[fn.name] {
			localTaint[p] = true
		}

		for lineIdx, line := range lines {
			lineNum := block.firstLine + lineIdx

			// Local assignment propagation
			if assign := tsAssignRe.FindStringSubmatch(line); len(assign) >= 3 {
				lhs := assign[1]
				rhs := assign[2]
				if !tsGuardCallRe.MatchString(rhs) {
					for t := range localTaint {
						if strings.Contains(rhs, t) {
							localTaint[lhs] = true
							break
						}
					}
				}
			}

			if !block.addedLines[lineNum] && len(block.addedLines) > 0 {
				continue
			}

			// Check SQL sinks: db.query(sql)
			if tsSQLSinkRe.MatchString(line) {
				for t := range localTaint {
					if strings.Contains(line, t) {
						key := fmt.Sprintf("%s:%d:sql", block.file, lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "request-taint",
								Severity:    "high",
								Category:    "security",
								Confidence:  "High",
								File:        block.file,
								Line:        lineNum,
								Message:     fmt.Sprintf("Tainted request data flows into SQL query sink; untrusted variable %q passed to database execute", t),
								Remediation: "Use parameterized queries or ORM query builders (e.g. db.query('SELECT ... WHERE id = $1', [id])).",
								Explanation: &model.FindingExplanation{
									RuleRationale:   "Untrusted request inputs interpolated into database queries enable SQL injection.",
									EvidenceSummary: fmt.Sprintf("Variable %q carrying request taint reaches database query execution.", t),
									EvidenceKind:    "taint-flow",
								},
							})
						}
						break
					}
				}
			}

			// Check Shell sinks: child_process.exec(cmd)
			if tsShellSinkRe.MatchString(line) {
				for t := range localTaint {
					if strings.Contains(line, t) {
						key := fmt.Sprintf("%s:%d:shell", block.file, lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "request-taint",
								Severity:    "high",
								Category:    "security",
								Confidence:  "High",
								File:        block.file,
								Line:        lineNum,
								Message:     fmt.Sprintf("Tainted request data flows into shell execution sink; untrusted variable %q passed to exec call", t),
								Remediation: "Avoid shell command execution with untrusted input; use execFile or spawn without shell expansion.",
								Explanation: &model.FindingExplanation{
									RuleRationale:   "Untrusted request data passed to command execution enables remote code execution.",
									EvidenceSummary: fmt.Sprintf("Variable %q carrying request taint reaches shell command sink.", t),
									EvidenceKind:    "taint-flow",
								},
							})
						}
						break
					}
				}
			}
		}
	}

	sort.Slice(findings, func(a, b int) bool {
		if findings[a].File != findings[b].File {
			return findings[a].File < findings[b].File
		}
		return findings[a].Line < findings[b].Line
	})

	return findings
}
