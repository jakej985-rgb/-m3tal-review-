package review

import (
	"path/filepath"
	"regexp"
	"strings"
)

// CredentialFilePermRule flags credential material written to disk with
// permissions that leave it readable by other local users: Go os.WriteFile /
// os.Create / os.OpenFile calls with permissive modes, and Python open() /
// Path.write_* calls in credential-named functions that rely on the default
// umask instead of an explicit 0o600.
type CredentialFilePermRule struct {
	ruleRuntime
}

func (CredentialFilePermRule) Name() string { return "credential-file-permissions" }

var (
	// credContextRe marks function names or call arguments that handle
	// credential material.
	credContextRe = regexp.MustCompile(`(?i)(token|secret|credential|oauth|auth|passwd|password|private[_-]?key|api[_-]?key|\.pem|\bcert\b)`)

	goFuncRe = regexp.MustCompile(`(?m)^func\s+(?:\([^)]*\)\s*)?(\w+)`)
	// goWriteRe matches file-writing calls; the arg span is extracted with
	// balanced parens afterwards.
	goWriteRe = regexp.MustCompile(`(?:os|ioutil)\.(?:WriteFile|Create|OpenFile|MkdirAll)\s*\(`)
	// Permissive explicit permission literals (before umask).
	goBadPermRe  = regexp.MustCompile(`\b0?(?:644|664|646|640|666|660|646|755|775|777|766)\b`)
	goSafePermRe = regexp.MustCompile(`\b0?600\b|os\.ModePerm`)
	// os.Create takes no permission argument and applies the process umask
	// to a permissive default. (MkdirAll/OpenFile/WriteFile take explicit
	// perms handled by goBadPermRe/goSafePermRe.)
	goImplicitPermRe = regexp.MustCompile(`os\.Create\s*\(`)

	pyFuncRe = regexp.MustCompile(`(?m)^[ \t]*(?:async\s+)?def\s+(\w+)`)
	// pyOpenWriteRe matches open() calls whose argument span contains a
	// write-ish mode, plus Path.write_text/write_bytes calls.
	pyOpenWriteRe = regexp.MustCompile(`\bopen\s*\(|\.write_(?:text|bytes)\s*\(`)
	pyWriteModeRe = regexp.MustCompile(`["'](?:w|a|x|w\+|a\+|x\+|wb|ab|xb|w\+b|wt)[bt+]*["']|mode\s*=\s*["'](?:w|a|x)[bt+]*["']`)
	pySafePermRe  = regexp.MustCompile(`0o?600|0o?400|chmod|umask`)
)

// balancedCallEnd returns the index just past the ')' matching the '(' at
// openIdx, or -1 if unbalanced within the block.
func balancedCallEnd(text string, openIdx int) int {
	depth := 0
	for i := openIdx; i < len(text) && i < openIdx+4096; i++ {
		switch text[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// namedFuncRanges returns function ranges with names. Ranges run to the next
// declaration or EOF; indentation is not tracked, so a method's range may
// extend into following siblings — acceptable for a heuristic scoped by
// credential-name context.
func namedFuncRanges(text string, re *regexp.Regexp) []namedFunc {
	var out []namedFunc
	locs := re.FindAllStringSubmatchIndex(text, -1)
	for i, m := range locs {
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		out = append(out, namedFunc{name: text[m[2]:m[3]], start: m[0], end: end})
	}
	return out
}

type namedFunc struct {
	name       string
	start, end int
}

func (r CredentialFilePermRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		// Test files legitimately write credential-shaped fixtures with
		// permissive temp perms; production credential stores are the risk.
		if isTestSourceFile(block.file) {
			continue
		}
		ext := strings.ToLower(filepath.Ext(block.file))
		switch ext {
		case ".go":
			findings = append(findings, r.checkGo(block)...)
		case ".py":
			findings = append(findings, r.checkPython(block)...)
		}
	}
	return findings
}

func (r CredentialFilePermRule) checkGo(block diffSourceBlock) []Finding {
	var findings []Finding
	for _, fn := range namedFuncRanges(block.text, goFuncRe) {
		body := block.text[fn.start:fn.end]
		credFn := credContextRe.MatchString(fn.name)
		for _, m := range goWriteRe.FindAllStringIndex(body, -1) {
			callStart := fn.start + m[0]
			// The regex ends with the '(' so m[1]-1 is the paren offset.
			absParen := fn.start + m[1] - 1
			callEnd := balancedCallEnd(block.text, absParen)
			if callEnd < 0 {
				continue
			}
			args := block.text[absParen : callEnd-1]
			if goSafePermRe.MatchString(args) {
				continue
			}
			permBad := goBadPermRe.MatchString(args)
			implicit := goImplicitPermRe.MatchString(body[m[0]:m[1]])
			credArgs := credContextRe.MatchString(args)
			if !(credFn || credArgs) || (!permBad && !implicit) {
				continue
			}
			if !matchTouchesAdded(block, block.text, callStart, callEnd) {
				continue
			}
			severity := "low"
			if permBad {
				severity = "medium"
			}
			findings = append(findings, Finding{
				Rule:        "credential-file-permissions",
				Severity:    severity,
				File:        block.file,
				Line:        lineAtOffset(block.firstLine, block.text, callStart),
				Message:     "Credential-named file write uses permissive or implicit permissions",
				Remediation: "Write credential files with 0600 (os.WriteFile(..., 0o600)) and avoid os.Create/os.MkdirAll for secrets.",
			})
		}
	}
	return findings
}

func (r CredentialFilePermRule) checkPython(block diffSourceBlock) []Finding {
	var findings []Finding
	for _, fn := range namedFuncRanges(block.text, pyFuncRe) {
		body := block.text[fn.start:fn.end]
		if !credContextRe.MatchString(fn.name) {
			continue
		}
		if pySafePermRe.MatchString(body) {
			continue
		}
		for _, m := range pyOpenWriteRe.FindAllStringIndex(body, -1) {
			absStart := fn.start + m[0]
			callEnd := balancedCallEnd(block.text, absStart+m[1]-m[0]-1)
			span := body[m[0]:m[1]]
			if strings.HasPrefix(strings.TrimSpace(span), ".") {
				// Path.write_text/write_bytes — no mode arg; flag directly.
				if !matchTouchesAdded(block, block.text, absStart, absStart+m[1]-m[0]) {
					continue
				}
				findings = append(findings, Finding{
					Rule:        "credential-file-permissions",
					Severity:    "low",
					File:        block.file,
					Line:        lineAtOffset(block.firstLine, block.text, absStart),
					Message:     "Credential-named file write relies on default permissions",
					Remediation: "Write credential files with mode 0o600 and chmod them after creation.",
				})
				continue
			}
			if callEnd < 0 {
				continue
			}
			args := block.text[absStart+m[1]-m[0]-1 : callEnd]
			if !pyWriteModeRe.MatchString(args) {
				continue
			}
			if !matchTouchesAdded(block, block.text, absStart, callEnd) {
				continue
			}
			findings = append(findings, Finding{
				Rule:        "credential-file-permissions",
				Severity:    "low",
				File:        block.file,
				Line:        lineAtOffset(block.firstLine, block.text, absStart),
				Message:     "Credential-named file write relies on default permissions (umask-dependent)",
				Remediation: "Write credential files with os.open(..., 0o600) or chmod to 0o600 after creation.",
			})
		}
	}
	return findings
}
