package review

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// JavaScript/TypeScript taint: an intra-file approximation of the Go
// request-taint engine. Taint seeds are request-context identifiers
// (req/request/ctx used as values or member bases) and process.argv;
// taint propagates through const/let/var, destructuring, and plain
// assignments; sinks are command execution (child_process-style calls,
// eval/new Function), filesystem calls, and response file-serving APIs.
// Taint resets at function/handler boundaries so sibling handlers cannot
// contaminate each other. There is no cross-file or call-edge propagation
// — confidence is capped at medium.

var (
	// jsReqIdentRe matches request-context identifiers used as values or
	// member bases. A preceding '.' excludes property access on unrelated
	// objects (foo.req, http.request, res.request).
	jsReqIdentRe = regexp.MustCompile(`\b(?:req|request|ctx)\b`)
	jsArgvRe     = regexp.MustCompile(`\bprocess\.argv\b`)
	// jsFuncBoundaryRes match lines that open a new function/handler scope;
	// taint does not cross these boundaries.
	jsFuncBoundaryRes = []*regexp.Regexp{
		regexp.MustCompile(`^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function[\s(*]`),
		regexp.MustCompile(`^\s*(?:const|let|var)\s+[$\w]+\s*=\s*(?:async\s+)?(?:function\b|\(|[$\w]+\s*=>)`),
		regexp.MustCompile(`^\s*(?:async\s+)?(?:\([^()]*\)|[$\w]+)\s*=>`),
		// Inline handlers: app.get('/x', (req, res) => { ...
		regexp.MustCompile(`\.(?:get|post|put|delete|patch|use|all|route|on|handle)\s*\(.*=>`),
		regexp.MustCompile(`^\s*(?:async\s+)?[$\w]+\s*\([^()]*\)\s*\{`), // method shorthand
	}
	// No lookahead in RE2: `==`, `===`, `=>`, `>=` are filtered by checking
	// the RHS prefix in code (see checkJSFile).
	jsAssignRe      = regexp.MustCompile(`(?:\b(?:const|let|var)\s+|^|[;{}]\s*)([$\w]+)\s*=\s*([^\n;]{0,300})`)
	jsDestructureRe = regexp.MustCompile(`\b(?:const|let|var)\s*[\[{]([^\]}\n]{1,200})[\]}]\s*=\s*([^\n;]{0,300})`)
	jsIdentRe       = regexp.MustCompile(`[$\w]+`)
	jsGuardCallRe   = regexp.MustCompile(`\b(?:encodeURIComponent|path\.basename|parseInt|parseFloat|Number|sanitize\w*|validate\w*|verify\w*|DOMPurify\.sanitize)\s*\(`)
	// jsExecSinkRe matches command-execution calls. The [^\w$.] prefix
	// excludes member calls like regex.exec(...).
	jsExecSinkRe = regexp.MustCompile(`(?:^|[^\w$.])(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(`)
	jsEvalSinkRe = regexp.MustCompile(`\beval\s*\(|new\s+Function\s*\(`)
	jsFsSinkRe   = regexp.MustCompile(`\b(?:fs|fsPromises|fsp|nodeFs)\.(?:readFile|writeFile|appendFile|createReadStream|createWriteStream|unlink|rename|rm|mkdir|copyFile|open)(?:Sync)?\s*\(`)
	// Bare fs function names (readFileSync etc.) only count when the file
	// imports fs — otherwise they are too ambiguous.
	jsBareFsRe    = regexp.MustCompile(`(?:^|[^\w$.])(?:readFile|writeFile|appendFile|createReadStream|createWriteStream|unlink|rename|rm|copyFile)(?:Sync)?\s*\(`)
	jsServeSinkRe = regexp.MustCompile(`\b(?:res|response|reply)\.(?:sendFile|download|sendfile)\s*\(|\bsendFile\s*\(`)
	jsFsImportRe  = regexp.MustCompile(`(?:require\s*\(\s*['"](?:node:)?fs['"]|from\s+['"](?:node:)?fs['"]|from\s+['"](?:node:)?fs/promises['"])`)
	jsKeywords    = map[string]bool{
		"if": true, "for": true, "while": true, "switch": true, "catch": true,
		"return": true, "else": true, "do": true, "try": true, "finally": true,
		"function": true, "new": true, "typeof": true, "case": true,
	}
)

// jsTaintFile reports whether a path is JS/TS source (not test/spec).
func jsTaintFile(file string) bool {
	lower := strings.ToLower(file)
	isJS := strings.HasSuffix(lower, ".js") || strings.HasSuffix(lower, ".jsx") ||
		strings.HasSuffix(lower, ".ts") || strings.HasSuffix(lower, ".tsx") ||
		strings.HasSuffix(lower, ".mjs") || strings.HasSuffix(lower, ".cjs")
	if !isJS || isTestSourceFile(file) {
		return false
	}
	return !strings.Contains(lower, "__tests__") &&
		!strings.Contains(lower, ".test.") &&
		!strings.Contains(lower, ".spec.")
}

// reqIdentUsed reports whether line contains a request-context identifier
// that is not a property access on another object.
func reqIdentUsed(line string) bool {
	for _, m := range jsReqIdentRe.FindAllStringIndex(line, -1) {
		if m[0] > 0 && line[m[0]-1] == '.' {
			continue
		}
		return true
	}
	return false
}

func taintReqIdents(line string, tainted map[string]bool) {
	for _, m := range jsReqIdentRe.FindAllStringIndex(line, -1) {
		if m[0] > 0 && line[m[0]-1] == '.' {
			continue
		}
		tainted[line[m[0]:m[1]]] = true
	}
}

// jsBoundaryAt reports whether the line opens a new function/handler scope.
func jsBoundaryAt(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "<!--") {
		return false
	}
	for i, re := range jsFuncBoundaryRes {
		if !re.MatchString(line) {
			continue
		}
		if i == len(jsFuncBoundaryRes)-1 {
			// Method shorthand also matches `if (x) {` etc.; exclude keywords.
			name := strings.TrimSpace(strings.SplitN(strings.TrimSpace(line), "(", 2)[0])
			name = strings.TrimPrefix(name, "async ")
			name = strings.TrimSpace(name)
			if jsKeywords[name] {
				return false
			}
		}
		return true
	}
	return false
}

// stripJSGuardCalls blanks entire sanitizer/validator call spans (through
// the closing paren) so arguments inside them are not treated as live taint.
func stripJSGuardCalls(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	pos := 0
	for _, m := range jsGuardCallRe.FindAllStringIndex(text, -1) {
		if m[0] < pos {
			// Nested guard already blanked by the enclosing call.
			continue
		}
		b.WriteString(text[pos:m[0]])
		// m[1]-1 is the '('; blank through its matching ')'.
		end := balancedCallEnd(text, m[1]-1)
		if end < 0 {
			end = m[1]
		}
		b.WriteString(strings.Repeat(" ", end-m[0]))
		pos = end
	}
	b.WriteString(text[pos:])
	return b.String()
}

// checkJSFile runs intra-file taint over one JS/TS block. Sink hits roll up
// into a single finding with per-line evidence.
func checkJSFile(block diffSourceBlock) []Finding {
	code := restoreJSTemplateInterpolations(block.text, string(maskNonCode(block.file, block.text)))
	lines := strings.Split(code, "\n")
	lineStarts := make([]int, len(lines))
	for i, off := 0, 0; i < len(lines); i++ {
		lineStarts[i] = off
		off += len(lines[i]) + 1
	}
	hasFSImport := jsFsImportRe.MatchString(block.text)

	tainted := make(map[string]bool)
	type hit struct {
		line     int
		kind     string
		callName string
		sev      string
	}
	var hits []hit
	seen := make(map[string]bool)

	for i, line := range lines {
		lineNum := block.firstLine + i
		if jsBoundaryAt(line) {
			tainted = make(map[string]bool)
		}

		// Seeds: request-context identifiers taint wherever they appear as
		// values or member bases; process.argv taints `process`.
		taintReqIdents(line, tainted)
		if jsArgvRe.MatchString(line) {
			tainted["process"] = true
		}

		// Propagation through destructuring and plain assignments.
		for _, m := range jsDestructureRe.FindAllStringSubmatch(line, -1) {
			rhs := stripJSGuardCalls(m[2])
			if reqIdentUsed(rhs) || containsJSTainted(rhs, tainted) {
				for _, id := range jsIdentRe.FindAllString(m[1], -1) {
					if !jsKeywords[id] {
						tainted[id] = true
					}
				}
			}
		}
		for _, m := range jsAssignRe.FindAllStringSubmatch(line, -1) {
			lhs, rhs := m[1], stripJSGuardCalls(m[2])
			// Skip comparison/arrow matches: `x == y`, `x === y`, `x => y`.
			trimmedRHS := strings.TrimSpace(rhs)
			if strings.HasPrefix(trimmedRHS, "=") || strings.HasPrefix(trimmedRHS, ">") {
				continue
			}
			if reqIdentUsed(rhs) || containsJSTainted(rhs, tainted) {
				for _, id := range jsIdentRe.FindAllString(lhs, -1) {
					if !jsKeywords[id] {
						tainted[id] = true
					}
				}
			}
		}

		// Sinks: the call's own (balanced, possibly multiline) argument span
		// must reference request-derived data. Unrelated request use
		// elsewhere on the line does not count.
		add := func(kind, base string, start, end int) {
			key := block.file + ":" + fmt.Sprint(lineNum)
			if seen[key] || !block.addedLines[lineNum] {
				return
			}
			// The sink regexes end at '('; locate it in the full code.
			paren := lineStarts[i] + strings.LastIndex(line[:end], "(")
			callEnd := balancedCallEnd(code, paren)
			if callEnd < 0 {
				return
			}
			args := code[paren+1 : callEnd-1]
			live := stripJSGuardCalls(args)
			if !reqIdentUsed(live) && !jsArgvRe.MatchString(live) && !containsJSTainted(live, tainted) {
				return
			}
			s := base
			if jsGuardCallRe.MatchString(args) {
				s = "medium"
			}
			name := strings.Trim(strings.TrimSpace(line[start:end]), " \t(,;.!?:")
			seen[key] = true
			hits = append(hits, hit{line: lineNum, kind: kind, callName: name, sev: s})
		}
		for _, m := range jsExecSinkRe.FindAllStringIndex(line, -1) {
			add("command execution", "high", m[0], m[1])
		}
		for _, m := range jsEvalSinkRe.FindAllStringIndex(line, -1) {
			add("code evaluation", "high", m[0], m[1])
		}
		for _, m := range jsFsSinkRe.FindAllStringIndex(line, -1) {
			add("filesystem", "medium", m[0], m[1])
		}
		if hasFSImport {
			for _, m := range jsBareFsRe.FindAllStringIndex(line, -1) {
				add("filesystem", "medium", m[0], m[1])
			}
		}
		for _, m := range jsServeSinkRe.FindAllStringIndex(line, -1) {
			add("file serving", "medium", m[0], m[1])
		}
	}

	if len(hits) == 0 {
		return nil
	}
	sort.Slice(hits, func(a, b int) bool { return hits[a].line < hits[b].line })
	sevRank := map[string]int{"low": 0, "medium": 1, "high": 2}
	best := hits[0]
	for _, h := range hits[1:] {
		if sevRank[h.sev] > sevRank[best.sev] {
			best = h
		}
	}
	var ev []FindingEvidence
	var calls []string
	seenCall := make(map[string]bool)
	for _, h := range hits {
		ev = append(ev, FindingEvidence{Rule: "request-taint", Severity: h.sev, Confidence: "medium", Line: h.line, Message: fmt.Sprintf("%s sink (%s)", h.kind, h.callName)})
		if h.callName != "" && !seenCall[h.callName] {
			seenCall[h.callName] = true
			calls = append(calls, h.callName)
		}
	}
	callList := strings.Join(calls, ", ")
	if callList == "" {
		callList = best.kind
	}
	return []Finding{{
		Category:    "security",
		Rule:        "request-taint",
		Severity:    best.sev,
		Confidence:  "medium",
		File:        block.file,
		Line:        hits[0].line,
		Signature:   "js:" + block.file,
		Message:     fmt.Sprintf("%s sink(s) reached by request-derived values in JS/TS source (%s, %d site%s) — intra-file analysis, verify call chain", best.kind, callList, len(hits), map[bool]string{true: "", false: "s"}[len(hits) == 1]),
		Remediation: "Validate and constrain request-derived values before exec/filesystem/serving sinks; prefer allowlists and path containment checks.",
		Evidence:    ev,
	}}
}

// restoreJSTemplateInterpolations re-exposes live `${...}` expressions inside
// template literals that maskNonCode blanked. Offsets are preserved, and
// static template text stays masked.
func restoreJSTemplateInterpolations(src, masked string) string {
	if len(src) != len(masked) || !strings.Contains(src, "${") {
		return masked
	}
	out := []byte(masked)
	inTemplate, inComment := false, false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inComment {
			if c == '\n' {
				inComment = false
			}
			continue
		}
		if !inTemplate {
			// Only enter templates from live code (not other strings/comments).
			if masked[i] == ' ' && c != ' ' {
				if c == '`' && (i == 0 || masked[i-1] != ' ' || src[i-1] == ' ' || src[i-1] == '(' || src[i-1] == '=') {
					inTemplate = true
				}
				continue
			}
			if c == '/' && i+1 < len(src) && src[i+1] == '/' {
				inComment = true
			}
			continue
		}
		switch {
		case c == '\\':
			i++
		case c == '`':
			inTemplate = false
		case c == '$' && i+1 < len(src) && src[i+1] == '{':
			depth := 0
			j := i + 1
			for ; j < len(src); j++ {
				if src[j] == '{' {
					depth++
				} else if src[j] == '}' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			if j >= len(src) {
				return string(out)
			}
			copy(out[i+2:j], src[i+2:j])
			i = j
		}
	}
	return string(out)
}

func containsJSTainted(text string, tainted map[string]bool) bool {
	for _, id := range jsIdentRe.FindAllString(text, -1) {
		if tainted[id] {
			return true
		}
	}
	return false
}
