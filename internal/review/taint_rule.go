package review

import (
	"fmt"
	"regexp"
	"strings"
)

// TaintRule performs lightweight intra-file taint analysis for Go HTTP
// handlers: values that originate from request input (chi.URLParam, query,
// form values, path values, JSON-decoded bodies) are tracked through simple
// assignments, and uses that reach filesystem, serving, or exec sinks are
// reported. It complements the regex TraversalRule, which only sees sources
// and sinks on the same line.
type TaintRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (TaintRule) Name() string { return "request-taint" }

var (
	goTaintSourceAssignRe = regexp.MustCompile(`(?m)([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*[:+]?=\s*[^\n=]{0,160}?(?:chi\.URLParam|\.URL\.Query\(\)\.Get|\.FormValue|\.PostFormValue|\.PathValue|\.MultipartForm)`)
	goTaintBodyDecodeRe   = regexp.MustCompile(`json\.NewDecoder\([^)]*\.Body[^)]*\)\.Decode\s*\(\s*&?([A-Za-z_]\w*)`)
	goTaintSinkRe         = regexp.MustCompile(`\b(?:os\.(?:RemoveAll|Remove|Rename|MkdirAll|WriteFile|Create|OpenFile|ReadFile|ReadDir|Stat|Lstat)|ioutil\.(?:ReadFile|WriteFile|ReadDir|TempFile)|http\.(?:ServeFile|ServeContent)|exec\.Command(?:Context)?|plugin\.Open)\s*\(`)
	goTaintDirectSourceRe = regexp.MustCompile(`chi\.URLParam|\.URL\.Query\(\)\.Get|\.FormValue|\.PostFormValue|\.PathValue`)
	goTaintAssignRe       = regexp.MustCompile(`(?m)^([^\n=;]{1,120}?)\s*(:=|=)\s*([^\n]{0,240})$`)
	goTaintIdentRe        = regexp.MustCompile(`[A-Za-z_]\w*`)
	goKeywords            = map[string]bool{
		"if": true, "for": true, "while": true, "return": true, "var": true,
		"const": true, "func": true, "else": true, "switch": true, "case": true,
		"go": true, "defer": true, "range": true, "type": true, "struct": true,
		"import": true, "package": true, "map": true, "chan": true, "select": true,
	}
)

// taintPropagationPasses bounds the def-use fixpoint so pathological files
// cannot loop the analyzer.
const taintPropagationPasses = 4

// sinkArgSpan returns the text of the argument list starting at the '(' that
// follows offset, tracking parenthesis depth (bounded).
func sinkArgSpan(code string, offset int) string {
	open := strings.IndexByte(code[offset:], '(')
	if open < 0 {
		return ""
	}
	start := offset + open + 1
	depth := 1
	for i := start; i < len(code) && i < start+4000; i++ {
		switch code[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return code[start:i]
			}
		}
	}
	return code[start:]
}

func validAssignLHS(lhs string) bool {
	lhs = strings.TrimSpace(lhs)
	if lhs == "" {
		return false
	}
	last := lhs[len(lhs)-1]
	return last == '_' || last == ']' || last == ')' ||
		(last >= 'a' && last <= 'z') || (last >= 'A' && last <= 'Z') || (last >= '0' && last <= '9')
}

func (r TaintRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") || strings.HasSuffix(block.file, "_test.go") {
			continue
		}
		findings = append(findings, r.checkGoBlock(block)...)
	}
	return findings
}

func (r TaintRule) checkGoBlock(block diffSourceBlock) []Finding {
	code := string(maskNonCode(block.file, block.text))
	lines := strings.Split(code, "\n")

	// Seed tainted identifiers from request sources.
	tainted := make(map[string]bool)
	for _, m := range goTaintSourceAssignRe.FindAllStringSubmatch(code, -1) {
		for _, id := range goTaintIdentRe.FindAllString(m[1], -1) {
			if !goKeywords[id] {
				tainted[id] = true
			}
		}
	}
	for _, m := range goTaintBodyDecodeRe.FindAllStringSubmatch(code, -1) {
		tainted[m[1]] = true
	}
	if len(tainted) == 0 {
		return nil
	}

	// Propagate taint through simple assignments: `x := f(tainted)` or
	// `a, b := g(tainted, ...)` taints the LHS identifiers.
	for pass := 0; pass < taintPropagationPasses; pass++ {
		changed := false
		for _, line := range lines {
			m := goTaintAssignRe.FindStringSubmatch(line)
			if m == nil || !validAssignLHS(m[1]) {
				continue
			}
			lhs, rhs := m[1], m[3]
			// Reject comparisons (==, <=, >=, !=): the operator group can match
			// the first '=' of '==', leaving a rhs that starts with '='.
			if strings.HasPrefix(strings.TrimSpace(rhs), "=") {
				continue
			}
			if !containsTaintedIdent(rhs, tainted) {
				continue
			}
			for _, id := range goTaintIdentRe.FindAllString(lhs, -1) {
				if !goKeywords[id] && !tainted[id] {
					tainted[id] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	// Report sinks whose path/exec arguments reference tainted data or request
	// sources. For write-style sinks only the path argument is checked:
	// request-controlled *content* written to a fixed path is normal API
	// behavior, not a vulnerability.
	var findings []Finding
	for _, m := range goTaintSinkRe.FindAllStringIndex(code, -1) {
		callName := sinkCallName(code, m[0])
		args := sinkArgSpan(code, m[1]-1)
		if args == "" {
			continue
		}
		scope := taintRelevantArgs(callName, args)
		if scope == "" {
			continue
		}
		direct := goTaintDirectSourceRe.MatchString(scope)
		indirect := containsTaintedIdent(scope, tainted)
		if !direct && !indirect {
			continue
		}
		line := lineAtOffset(block.firstLine, code, m[0])
		if !block.addedLines[line] {
			continue
		}
		kind := "filesystem/serving"
		if strings.Contains(callName, "exec.Command") {
			kind = "command execution"
		}
		via := "request-derived value"
		if indirect && !direct {
			via = "variable assigned from request input"
		}
		findings = append(findings, Finding{
			Category:    "security",
			Rule:        "request-taint",
			Severity:    "high",
			File:        block.file,
			Line:        line,
			Message:     fmt.Sprintf("%s sink reached by %s (%s)", kind, via, sinkCallName(code, m[0])),
			Remediation: "Validate and constrain request-derived values before filesystem, serving, or exec sinks; prefer filepath.Base/allowlists and reject path separators.",
		})
	}
	return findings
}

// splitTopLevelArgs splits a call argument list on commas at paren depth 0.
// Input comes from masked source, so commas inside string literals are already
// blanked and cannot confuse the split.
func splitTopLevelArgs(args string) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, args[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, args[start:])
	return out
}

// taintRelevantArgs returns the portion of sink arguments that carries path or
// command risk: the first argument for single-path filesystem calls, the first
// two for Rename, everything after (w, r) for http.ServeFile/ServeContent, and
// all arguments for exec/plugin calls.
func taintRelevantArgs(callName, args string) string {
	parts := splitTopLevelArgs(args)
	base := callName
	if idx := strings.LastIndex(base, "."); idx >= 0 {
		base = base[idx+1:]
	}
	switch {
	case strings.Contains(callName, "ServeFile") || strings.Contains(callName, "ServeContent"):
		if len(parts) > 2 {
			return strings.Join(parts[2:], ",")
		}
		return ""
	case base == "Rename":
		if len(parts) > 2 {
			return strings.Join(parts[:2], ",")
		}
		return strings.Join(parts, ",")
	case strings.HasPrefix(callName, "exec.") || strings.Contains(callName, "plugin.Open"):
		return args
	default:
		// Single-path sinks: RemoveAll, Remove, MkdirAll, WriteFile, Create,
		// OpenFile, ReadFile, ReadDir, Stat, Lstat, TempFile.
		if len(parts) > 0 {
			return parts[0]
		}
		return ""
	}
}

func containsTaintedIdent(text string, tainted map[string]bool) bool {
	for _, id := range goTaintIdentRe.FindAllString(text, -1) {
		if tainted[id] {
			return true
		}
	}
	return false
}

func sinkCallName(code string, offset int) string {
	end := strings.IndexByte(code[offset:], '(')
	if end < 0 || end > 60 {
		return "sink"
	}
	return strings.TrimSpace(code[offset : offset+end])
}

// ScopeDefaultRule flags permission/scope normalization that silently falls
// back to wildcard/full access ("*", ScopeFull) when input is empty or
// invalid — a common authorization-escalation bug.
type ScopeDefaultRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (ScopeDefaultRule) Name() string { return "wildcard-default-scope" }

var (
	scopeFuncRe = regexp.MustCompile(`(?m)^func\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{]*\{`)
	scopeNameRe = regexp.MustCompile(`(?i)permission|scope|normalize|allow|grant|acl|policy`)
	scopeWildRe = regexp.MustCompile(`(?i)return\s+(?:\[\]string\s*\{\s*["']?\*|ScopeFull|FullAccess|\[\]string\{[^}]*ScopeFull)`)
	scopeCtxRe  = regexp.MustCompile(`(?i)len\([^)]*\)\s*==\s*0|default:|invalid|unknown`)
	scopeNextFn = regexp.MustCompile(`(?m)^func\s`)
)

func (r ScopeDefaultRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") {
			continue
		}
		findings = append(findings, scopeFindingsForBlock(block)...)
	}
	return findings
}

func scopeFindingsForBlock(block diffSourceBlock) []Finding {
	// Use raw text: func signatures and "*" literals must remain visible.
	code := block.text
	var findings []Finding
	for _, m := range scopeFuncRe.FindAllStringSubmatchIndex(code, -1) {
		name := code[m[2]:m[3]]
		if !scopeNameRe.MatchString(name) {
			continue
		}
		// Function body: from match end to the next top-level "func " or EOF.
		bodyStart := m[1]
		bodyEnd := len(code)
		if next := scopeNextFn.FindStringIndex(code[bodyStart:]); next != nil {
			bodyEnd = bodyStart + next[0]
		}
		body := code[bodyStart:bodyEnd]
		if len(body) > 8000 {
			body = body[:8000]
		}
		// scopeWildRe needs the "*" literal, which maskNonCode blanks; match the
		// raw block text at the same offsets (masks preserve length).
		rawBody := block.text[bodyStart:bodyEnd]
		if len(rawBody) > 8000 {
			rawBody = rawBody[:8000]
		}
		if !scopeWildRe.MatchString(rawBody) || !scopeCtxRe.MatchString(rawBody) {
			continue
		}
		line := lineAtOffset(block.firstLine, code, m[0])
		if !block.addedLines[line] {
			continue
		}
		findings = append(findings, Finding{
			Category:    "security",
			Rule:        "wildcard-default-scope",
			Severity:    "high",
			File:        block.file,
			Line:        line,
			Message:     fmt.Sprintf("Permission/scope function %s falls back to wildcard or full access on empty/invalid input", name),
			Remediation: "Reject invalid or empty permission scopes instead of defaulting to \"*\"/full access; normalize to the least-privilege set.",
		})
	}
	return findings
}

// PluginTrustRule flags code that auto-executes plugins discovered relative to
// the working directory or from repository-controlled manifests, and env
// blocks that inject credential variables into plugin subprocesses.
type PluginTrustRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (PluginTrustRule) Name() string { return "plugin-trust" }

var (
	pluginCwdPathRe   = regexp.MustCompile(`["']\.{1,2}/(?:plugins?|\.)["']|["']plugins["']`)
	pluginAutoStartRe = regexp.MustCompile(`(?i)auto.?start|DiscoverAnd\w*Start|LoadAndStart`)
	pluginExecRe      = regexp.MustCompile(`\bexec\.Command(?:Context)?\s*\(`)
	pluginEnvCredRe   = regexp.MustCompile(`os\.Environ\(\)[^;]{0,400}["'][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Za-z0-9_]*=?["']\s*\+`)
)

func (r PluginTrustRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") {
			continue
		}
		code := string(maskNonCode(block.file, block.text))
		isPluginFile := strings.Contains(strings.ToLower(block.file), "plugin")
		hasAutoStart := pluginAutoStartRe.MatchString(code)
		// Literal-bearing patterns run on raw text (maskNonCode blanks strings).
		hasEnvCred := pluginEnvCredRe.MatchString(block.text)
		if !hasAutoStart && !hasEnvCred && !(isPluginFile && pluginCwdPathRe.MatchString(block.text)) {
			continue
		}
		findings = append(findings, pluginFindingsForBlock(block, code, isPluginFile)...)
	}
	return findings
}

func pluginFindingsForBlock(block diffSourceBlock, code string, isPluginFile bool) []Finding {
	var findings []Finding
	seen := make(map[int]bool)
	emit := func(offset int, severity, message, remediation string) {
		line := lineAtOffset(block.firstLine, code, offset)
		if seen[line] || !block.addedLines[line] {
			return
		}
		seen[line] = true
		findings = append(findings, Finding{
			Category:    "security",
			Rule:        "plugin-trust",
			Severity:    severity,
			File:        block.file,
			Line:        line,
			Message:     message,
			Remediation: remediation,
		})
	}
	// Auto-start files: flag executable launches of discovered plugin commands.
	if pluginAutoStartRe.MatchString(code) {
		for _, m := range pluginExecRe.FindAllStringIndex(code, -1) {
			emit(m[0], "high", "Plugin/subprocess auto-start executes a command discovered at runtime", "Require explicit user consent or an allowlist before executing discovered plugin commands; do not auto-start code found on disk.")
		}
	}
	// Credential variables injected into subprocess environments (raw text:
	// the env var names are string literals that masking would blank).
	for _, m := range pluginEnvCredRe.FindAllStringIndex(block.text, -1) {
		emit(m[0], "medium", "Credential-bearing environment variables passed to plugin subprocess", "Pass only the minimum required credentials to plugins; prefer scoped, revocable tokens over primary API keys.")
	}
	// CWD-relative plugin search paths in plugin host code. A bare "plugins"
	// literal is only suspicious outside path-join calls: filepath.Join(home,
	// ".config", "m3tal", "plugins") is anchored, not working-directory-relative.
	if isPluginFile {
		for _, m := range pluginCwdPathRe.FindAllStringIndex(block.text, -1) {
			lit := block.text[m[0]:m[1]]
			if lit == `"plugins"` || lit == `'plugins'` {
				prefix := block.text[:m[0]]
				if j := strings.LastIndex(prefix, "Join("); j >= 0 && j > strings.LastIndex(prefix, ")") {
					continue
				}
			}
			emit(m[0], "medium", "Plugin discovery searches a working-directory-relative path", "Resolve plugin directories against the user config/home directory or an explicit trusted path, not the process CWD.")
		}
	}
	return findings
}

// PrivilegedExecRule flags execution of system package managers / privilege
// wrappers (sudo, dpkg, apt, systemctl, ...) inside HTTP-serving Go code,
// where request-influenced arguments can become root-level operations.
type PrivilegedExecRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (PrivilegedExecRule) Name() string { return "privileged-pkg-exec" }

var (
	privilegedBinRe = regexp.MustCompile(`\bexec\.Command(?:Context)?\s*\(\s*"(sudo|doas|dpkg|dpkg-deb|apt-get|apt|apk|yum|dnf|zypper|snap|flatpak|brew|systemctl|service|rpm)"`)
	httpHandlerFile = regexp.MustCompile(`net/http|http\.ResponseWriter|http\.Request|chi\.|gin\.|echo\.|fiber\.`)
	quotedStringRe  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)
)

func (r PrivilegedExecRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") || strings.HasSuffix(block.file, "_test.go") {
			continue
		}
		code := string(maskNonCode(block.file, block.text))
		if !httpHandlerFile.MatchString(code) {
			continue
		}
		for _, m := range privilegedBinRe.FindAllStringIndex(block.text, -1) {
			if offsetInComment(block.file, block.text, m[0]) {
				continue
			}
			line := lineAtOffset(block.firstLine, code, m[0])
			if !block.addedLines[line] {
				continue
			}
			// Strip string literals from the call arguments; any remaining
			// identifier means non-literal (potentially request-derived) input.
			// The match starts at "exec", so the first '(' after it opens the
			// argument list.
			args := sinkArgSpan(code, m[0])
			rest := quotedStringRe.ReplaceAllString(args, "")
			severity := "medium"
			msg := "Privileged package/system command executed from HTTP handler code"
			if goTaintIdentRe.MatchString(rest) {
				severity = "high"
				msg = "Privileged command arguments include non-literal values reachable from request handlers"
			}
			findings = append(findings, Finding{
				Category:    "security",
				Rule:        "privileged-pkg-exec",
				Severity:    severity,
				File:        block.file,
				Line:        line,
				Message:     msg,
				Remediation: "Avoid executing package managers or privilege wrappers from request handlers; constrain inputs with strict allowlists and prefer fixed argument vectors.",
			})
		}
	}
	return findings
}

// ProcessKillRule flags process termination APIs whose target PID may be
// request-controlled, which can kill critical system processes.
type ProcessKillRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (ProcessKillRule) Name() string { return "process-kill-abuse" }

var (
	killCallRe   = regexp.MustCompile(`\.Kill\s*\(|syscall\.Kill\s*\(|\.Signal\s*\(|Terminate\s*\(`)
	killPidVarRe = regexp.MustCompile(`(?m)([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*:=\s*[^\n]{0,160}?(?:chi\.URLParam|\.URL\.Query\(\)|PostFormValue|FormValue)`)
)

func (r ProcessKillRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") || strings.HasSuffix(block.file, "_test.go") {
			continue
		}
		code := string(maskNonCode(block.file, block.text))
		// Identifiers assigned from request input that look PID/process-ish.
		pidVars := make(map[string]bool)
		for _, m := range killPidVarRe.FindAllStringSubmatch(code, -1) {
			for _, id := range goTaintIdentRe.FindAllString(m[1], -1) {
				lower := strings.ToLower(id)
				if strings.Contains(lower, "pid") || strings.Contains(lower, "process") {
					pidVars[id] = true
				}
			}
		}
		seen := make(map[int]bool)
		for _, m := range killCallRe.FindAllStringIndex(code, -1) {
			args := sinkArgSpan(code, m[1]-1)
			requestDerived := false
			for v := range pidVars {
				if regexp.MustCompile(`\b` + regexp.QuoteMeta(v) + `\b`).MatchString(args) {
					requestDerived = true
					break
				}
			}
			// Method-style kills (proc.Kill()) take no args; when the file
			// derives a request-controlled PID, flag the call site anyway.
			if !requestDerived && len(pidVars) > 0 && strings.TrimSpace(args) == "" {
				requestDerived = true
			}
			if !requestDerived {
				continue
			}
			line := lineAtOffset(block.firstLine, code, m[0])
			if seen[line] || !block.addedLines[line] {
				continue
			}
			seen[line] = true
			findings = append(findings, Finding{
				Category:    "security",
				Rule:        "process-kill-abuse",
				Severity:    "medium",
				File:        block.file,
				Line:        line,
				Message:     "Process termination may target a request-controlled PID; arbitrary processes (including system services) can be killed",
				Remediation: "Allowlist killable processes/PIDs, refuse PID 1 and protected system processes, and require explicit authorization scope.",
			})
		}
	}
	return findings
}

// CredentialQueryRule flags server-side extraction of credentials from URL
// query parameters, which leak via logs, history, and referrers.
type CredentialQueryRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (CredentialQueryRule) Name() string { return "credential-in-query" }

var credentialQueryRe = regexp.MustCompile(`(?i)(?:URL\.Query\(\)\.Get|PostFormValue|FormValue)\s*\(\s*["'][^"']*(?:token|api_?key|secret|password|passwd|access_?key|auth)[^"']*["']|req\.query\.(?:token|api_?key|apiKey|secret|password|passwd|access_?key|auth\w*)|request\.args\.get\s*\(\s*["'][^"']*(?:token|secret|password|key)[^"']*["']`)

func (r CredentialQueryRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		for _, m := range credentialQueryRe.FindAllStringIndex(block.text, -1) {
			if offsetInComment(block.file, block.text, m[0]) {
				continue
			}
			line := lineAtOffset(block.firstLine, block.text, m[0])
			if !block.addedLines[line] {
				continue
			}
			findings = append(findings, Finding{
				Category:    "security",
				Rule:        "credential-in-query",
				Severity:    "low",
				File:        block.file,
				Line:        line,
				Message:     "Credential read from URL query parameter; query strings leak via logs, browser history, and referrers",
				Remediation: "Accept credentials via Authorization headers or request bodies instead of query parameters.",
			})
		}
	}
	return findings
}
