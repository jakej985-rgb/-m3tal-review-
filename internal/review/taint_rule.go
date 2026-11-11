package review

import (
	"fmt"
	"path"
	"regexp"
	"sort"
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
	goTaintSinkRe         = regexp.MustCompile(`\b(?:os\.(?:RemoveAll|Remove|Rename|MkdirAll|WriteFile|Create|OpenFile|ReadFile|ReadDir|Stat|Lstat)|ioutil\.(?:ReadFile|WriteFile|ReadDir|TempFile)|http\.(?:ServeFile|ServeContent)|exec\.Command(?:Context)?|plugin\.Open|http\.NewRequest(?:WithContext)?|\.Do)\s*\(`)
	goTaintDirectSourceRe = regexp.MustCompile(`chi\.URLParam|\.URL\.Query\(\)\.Get|\.FormValue|\.PostFormValue|\.PathValue`)
	// Manifest-declared names (plugin.yaml spec/plugin fields) are attacker-
	// controlled when a repo ships manifests; seed them as taint sources in
	// files that parse manifests.
	// .Manifest.Dir is excluded: it is assigned by plugin discovery
	// (yaml:"-"), not parsed from the manifest, so it is not attacker input.
	goManifestSourceRe   = regexp.MustCompile(`\.Manifest\.(?:Metadata|Spec|Config)\b|\.Spec\.(?:Name|Plugin|Command|Path)|\bsec\.Plugin\b|manifest\.\w*(?:Name|Plugin)`)
	goManifestFileGateRe = regexp.MustCompile(`yaml\.Unmarshal|plugin\.yaml|\.Manifest\b|Manifest\s+\*?\w+|type\s+Manifest\b`)
	goTaintAssignRe      = regexp.MustCompile(`(?m)^([^\n=;]{1,120}?)\s*(:=|=)\s*([^\n]{0,240})$`)
	goTaintIdentRe       = regexp.MustCompile(`[A-Za-z_]\w*`)
	// RPC plugin sources: JSON-RPC over stdin decodes request frames
	// (`json.Unmarshal(line, &req)`) and action params
	// (`json.Unmarshal(req.Params, &params)`). Only applied to packages that
	// actually scan os.Stdin, so ordinary config/HTTP unmarshals of file or
	// response bodies are not treated as request input.
	goRPCUnmarshalRe = regexp.MustCompile(`json\.Unmarshal\s*\(\s*(?:line\b|req\.Params\b|input\b|msg\b|message\b)[^,\n]{0,160}?,\s*&([A-Za-z_]\w*)`)
	// Struct fields whose names end in Path/File/Dir/Root carry filesystem
	// locations (config paths, share/export paths, stack roots). When such a
	// field flows into a call, the callee parameter is treated as risky.
	goSelectorPathRe = regexp.MustCompile(`\.[A-Za-z_]\w*(?:Path|File|Dir|Filename|Root)\b`)
	// Outbound-request sinks: user-influenced URLs reaching HTTP clients.
	goHTTPRequestSinkRe = regexp.MustCompile(`http\.NewRequest(?:WithContext)?\s*\(|\.Do\s*\(`)
	goFuncHeaderRe      = regexp.MustCompile(`^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(([^)]*)\)`)
	goCallSiteRe        = regexp.MustCompile(`[A-Za-z_]\w*\s*\(`)
	goKeywords          = map[string]bool{
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
	// Group Go files by package directory so taint can propagate through
	// intra-package helper calls (handler -> SaveStack -> atomicWriteFile).
	blocksByDir := make(map[string][]diffSourceBlock)
	var dirs []string
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") || strings.HasSuffix(block.file, "_test.go") {
			continue
		}
		dir := path.Dir(block.file)
		if _, ok := blocksByDir[dir]; !ok {
			dirs = append(dirs, dir)
		}
		blocksByDir[dir] = append(blocksByDir[dir], block)
	}
	for _, dir := range dirs {
		findings = append(findings, r.checkPackage(blocksByDir[dir])...)
	}
	return findings
}

// goFuncDeclRe matches top-level Go function/method declarations (column 0).
// Anonymous funcs are always indented, so they stay inside their enclosing
// declaration's segment.
var goFuncDeclRe = regexp.MustCompile(`(?m)^func\s`)

// goGuardCallRe matches calls that sanitize or validate a value: path/base
// helpers, escaping functions, numeric parsers, and sanitize/validate/verify/
// clean/escape/allowlist-style wrappers. Tainted data passing through these is
// treated as guarded.
var goGuardCallRe = regexp.MustCompile(`\b(?:filepath\.Base|filepath\.Rel|html\.EscapeString|template\.HTMLEscape|strconv\.Atoi|strconv\.ParseInt|strconv\.ParseUint|strconv\.ParseFloat|url\.QueryEscape|url\.PathEscape|sanitize[A-Za-z_]\w*|validate[A-Za-z_]\w*|verify[A-Za-z_]\w*|clean[A-Za-z_]\w*|escape[A-Za-z_]\w*|allowlist\w*|whitelist\w*)\s*\(`)

// goFuncSegment is a top-level function's byte range within a file's code.
type goFuncSegment struct {
	start, end int
}

// goFuncSegments splits masked Go source into per-declaration regions so
// taint cannot bleed between functions that reuse identifier names (e.g. two
// handlers both declaring debPath).
func goFuncSegments(code string) []goFuncSegment {
	matches := goFuncDeclRe.FindAllStringIndex(code, -1)
	if len(matches) == 0 {
		return nil
	}
	segs := make([]goFuncSegment, 0, len(matches))
	for i, m := range matches {
		end := len(code)
		if i+1 < len(matches) {
			end = matches[i+1][0]
		}
		segs = append(segs, goFuncSegment{start: m[0], end: end})
	}
	return segs
}

// callArgsAt returns the argument text of the call whose '(' is at offset.
func callArgsAt(code string, offset int) string {
	open := strings.IndexByte(code[offset:], '(')
	if open < 0 {
		return ""
	}
	return sinkArgSpan(code, offset+open)
}

// stripGuardCalls removes sanitizer/validator call expressions (name through
// closing paren) so tainted idents inside them do not propagate.
func stripGuardCalls(text string) string {
	for {
		m := goGuardCallRe.FindStringIndex(text)
		if m == nil {
			return text
		}
		// Find the call's closing paren starting from the '(' the regex ended at.
		open := strings.IndexByte(text[m[0]:], '(')
		argStart := m[0] + open + 1
		depth := 1
		end := -1
		for i := argStart; i < len(text) && i < argStart+4000; i++ {
			switch text[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = i + 1
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return text
		}
		text = text[:m[0]] + " " + text[end:]
	}
}

// splitGoStatements splits masked code on newlines and ';' (string literals
// are already blanked by masking), returning each statement and its offset.
func splitGoStatements(code string) ([]string, []int) {
	var stmts []string
	var starts []int
	start := 0
	for i := 0; i <= len(code); i++ {
		if i == len(code) || code[i] == '\n' || code[i] == ';' {
			stmts = append(stmts, code[start:i])
			starts = append(starts, start)
			start = i + 1
		}
	}
	return stmts, starts
}

// stmtIndexAt returns the index of the statement containing offset.
func stmtIndexAt(starts []int, offset int) int {
	idx := -1
	for i, s := range starts {
		if s > offset {
			break
		}
		idx = i
	}
	return idx
}

// goValidatorCallRe matches validation-style calls that gate their argument
// (as opposed to transformers whose return value is the clean data).
var goValidatorCallRe = regexp.MustCompile(`\b(?:sanitize[A-Za-z_]\w*|validate[A-Za-z_]\w*|verify[A-Za-z_]\w*|allowlist\w*|whitelist\w*)\s*\(`)

// validatedIdents returns identifiers passed as whole arguments to
// validator calls within a line.
func validatedIdents(segment string) map[string]bool {
	return guardedIdentsFor(goValidatorCallRe, segment)
}

// guardedIdents returns identifiers passed as whole arguments to sanitizer or
// validator calls within a code segment.
func guardedIdents(segment string) map[string]bool {
	return guardedIdentsFor(goGuardCallRe, segment)
}

func guardedIdentsFor(re *regexp.Regexp, segment string) map[string]bool {
	out := make(map[string]bool)
	for _, m := range re.FindAllStringIndex(segment, -1) {
		args := callArgsAt(segment, m[1]-1)
		for _, arg := range splitTopLevelArgs(args) {
			arg = strings.TrimSpace(arg)
			ids := goTaintIdentRe.FindAllString(arg, -1)
			// Only single-identifier arguments count: composite expressions
			// like req.Package sanitize one field, not the whole struct.
			if len(ids) == 1 && !goKeywords[ids[0]] {
				out[ids[0]] = true
			}
		}
	}
	return out
}

// taintFunc is a top-level Go function participating in package taint
// analysis, with its ordered parameter names for call-edge propagation.
type taintFunc struct {
	name     string
	params   []string
	variadic bool
	blockIdx int
	seg      goFuncSegment
}

// goTypeNames are identifiers that appear as parameter types, not names.
var goTypeNames = map[string]bool{
	"string": true, "int": true, "int8": true, "int16": true, "int32": true,
	"int64": true, "uint": true, "uint8": true, "uint16": true, "uint32": true,
	"uint64": true, "uintptr": true, "byte": true, "rune": true, "bool": true,
	"float32": true, "float64": true, "complex64": true, "complex128": true,
	"error": true, "any": true, "comparable": true,
}

// parseFuncHeader extracts the function name and ordered parameter names
// from the start of a masked function declaration. Only the first identifier
// of each parameter declaration is kept (later idents are types, including
// selector types like context.Context whose parts would confuse naive parses).
func parseFuncHeader(segStart string) (name string, params []string, variadic bool) {
	m := goFuncHeaderRe.FindStringSubmatch(segStart)
	if m == nil {
		return "", nil, false
	}
	name = m[1]
	for _, part := range splitTopLevelArgs(m[2]) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "...") {
			variadic = true
		}
		ids := goTaintIdentRe.FindAllString(part, -1)
		if len(ids) == 0 {
			continue
		}
		// Single-identifier declarations that are types (func F(string)) are
		// unnamed parameters; multi-ident declarations start with the name.
		if len(ids) == 1 && (goKeywords[ids[0]] || goTypeNames[ids[0]]) {
			continue
		}
		params = append(params, ids[0])
	}
	return name, params, variadic
}

// collectTaintSeeds returns the identifiers tainted by request input,
// manifest-declared fields, or (in JSON-RPC plugin packages) decoded RPC
// frames and params.
func collectTaintSeeds(segText string, rpcPkg bool) map[string]bool {
	tainted := make(map[string]bool)
	for _, m := range goTaintSourceAssignRe.FindAllStringSubmatch(segText, -1) {
		for _, id := range goTaintIdentRe.FindAllString(m[1], -1) {
			if !goKeywords[id] {
				tainted[id] = true
			}
		}
	}
	for _, m := range goTaintBodyDecodeRe.FindAllStringSubmatch(segText, -1) {
		tainted[m[1]] = true
	}
	// Manifest-declared identifiers only count as sources in files that
	// actually parse manifests (plugin hosts, config loaders).
	manifestGate := goManifestFileGateRe.MatchString(segText)
	if manifestGate {
		for _, m := range goTaintAssignRe.FindAllStringSubmatch(segText, -1) {
			if !validAssignLHS(m[1]) || strings.HasPrefix(strings.TrimSpace(m[3]), "=") {
				continue
			}
			cleanRHS := stripGuardCalls(m[3])
			if !goManifestSourceRe.MatchString(cleanRHS) {
				continue
			}
			if containsTaintedIdent(cleanRHS, tainted) {
				continue // already tainted via request sources
			}
			for _, id := range goTaintIdentRe.FindAllString(m[1], -1) {
				if !goKeywords[id] {
					tainted[id] = true
				}
			}
		}
	}
	if rpcPkg {
		for _, m := range goRPCUnmarshalRe.FindAllStringSubmatch(segText, -1) {
			tainted[m[1]] = true
		}
	}
	return tainted
}

// propagateTaint runs the sequential flow pass over a function segment,
// evolving the tainted set in source order (see checkPackage for the rules).
// It returns per-statement taint snapshots so sinks can be checked against
// the state at their own position: a validator placed after a sink must not
// clean the earlier, unvalidated use.
func propagateTaint(segText string, tainted map[string]bool) (snapshots []map[string]bool, stmtStarts []int) {
	lines, stmtStarts := splitGoStatements(segText)
	snapshots = make([]map[string]bool, len(lines))
	for i, line := range lines {
		snap := make(map[string]bool, len(tainted))
		for id := range tainted {
			snap[id] = true
		}
		snapshots[i] = snap
		// Only validator-style calls clean their argument in place;
		// transformers (filepath.Base, escapers, parsers) return a new value
		// and leave the original identifier tainted.
		for id := range validatedIdents(line) {
			delete(tainted, id)
		}
		m := goTaintAssignRe.FindStringSubmatch(line)
		if m == nil || !validAssignLHS(m[1]) {
			continue
		}
		lhs, rhsRaw := m[1], m[3]
		// Reject comparisons (==, <=, >=, !=): the operator group can match
		// the first '=' of '==', leaving a rhs that starts with '='.
		if strings.HasPrefix(strings.TrimSpace(rhsRaw), "=") {
			continue
		}
		rhs := strings.TrimSpace(stripGuardCalls(rhsRaw))
		lhsIds := goTaintIdentRe.FindAllString(lhs, -1)
		if rhs == "" && strings.TrimSpace(rhsRaw) != "" {
			// RHS was entirely guard call(s): sanitized output.
			for _, id := range lhsIds {
				if !goKeywords[id] {
					delete(tainted, id)
				}
			}
			continue
		}
		if !containsTaintedIdent(rhs, tainted) {
			continue
		}
		for _, id := range lhsIds {
			if !goKeywords[id] {
				tainted[id] = true
			}
		}
	}
	return snapshots, stmtStarts
}

// riskyArg reports whether a call argument carries untrusted or
// filesystem-location data: tainted identifiers, direct request sources,
// manifest fields, or struct fields named like paths.
func riskyArg(text string, tainted map[string]bool, manifestGate bool) bool {
	if containsTaintedIdent(text, tainted) {
		return true
	}
	if goTaintDirectSourceRe.MatchString(text) {
		return true
	}
	if manifestGate && goManifestSourceRe.MatchString(text) {
		return true
	}
	return goSelectorPathRe.MatchString(text)
}

// callParamEdge records that a call passed risky data into callee parameters.
type callParamEdge struct {
	callee string
	params map[string]bool
}

// callParamEdges finds calls to functions in the same package whose arguments
// are risky, and returns the callee parameter names that should be tainted.
// Uses the post-propagation tainted set (a bounded over-approximation: taint
// is not tracked per program point for call edges).
func callParamEdges(segText string, sigs map[string]taintFunc, tainted map[string]bool, manifestGate bool) []callParamEdge {
	var edges []callParamEdge
	for _, m := range goCallSiteRe.FindAllStringIndex(segText, -1) {
		name := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(segText[m[0]:m[1]]), "("))
		fn, ok := sigs[name]
		if !ok || len(fn.params) == 0 {
			continue
		}
		args := callArgsAt(segText, m[0])
		if args == "" {
			continue
		}
		taintedParams := make(map[string]bool)
		for i, arg := range splitTopLevelArgs(args) {
			idx := i
			if fn.variadic && i >= len(fn.params)-1 {
				idx = len(fn.params) - 1
			}
			if idx >= len(fn.params) {
				break
			}
			arg = strings.TrimSuffix(strings.TrimSpace(arg), "...")
			// Apply the same sanitizer treatment as propagateTaint: values
			// wrapped in guard calls (filepath.Base, validators) are clean.
			arg = strings.TrimSpace(stripGuardCalls(arg))
			if arg != "" && riskyArg(arg, tainted, manifestGate) {
				taintedParams[fn.params[idx]] = true
			}
		}
		if len(taintedParams) > 0 {
			edges = append(edges, callParamEdge{callee: name, params: taintedParams})
		}
	}
	return edges
}

// initialTaint combines a function's local seeds with taint arriving through
// its parameters from intra-package callers.
func initialTaint(seeds map[string]bool, fn taintFunc, paramTaint map[string]map[string]bool) map[string]bool {
	out := make(map[string]bool, len(seeds)+4)
	for k := range seeds {
		out[k] = true
	}
	if pt := paramTaint[fn.name]; pt != nil {
		for _, p := range fn.params {
			if pt[p] {
				out[p] = true
			}
		}
	}
	return out
}

// checkPackage runs flow-sensitive taint analysis across all Go files in one
// package directory: request/RPC inputs are seeded per function, propagated
// through assignments, and carried across intra-package call edges until a
// bounded fixpoint is reached.
func (r TaintRule) checkPackage(blocks []diffSourceBlock) []Finding {
	codes := make([]string, len(blocks))
	funcs := make([]taintFunc, 0)
	sigs := make(map[string]taintFunc)
	rpcPkg := false
	// Names declared more than once (methods on different receivers) cannot
	// be resolved to a single declaration; skip call-edge propagation for them.
	ambiguous := make(map[string]bool)
	for i, block := range blocks {
		codes[i] = string(maskNonCode(block.file, block.text))
		if strings.Contains(block.text, "bufio.NewScanner(os.Stdin)") {
			rpcPkg = true
		}
		for _, seg := range goFuncSegments(codes[i]) {
			name, params, variadic := parseFuncHeader(codes[i][seg.start:])
			if name == "" {
				continue
			}
			fn := taintFunc{name: name, params: params, variadic: variadic, blockIdx: i, seg: seg}
			funcs = append(funcs, fn)
			if _, dup := sigs[name]; dup {
				ambiguous[name] = true
			}
			sigs[name] = fn
		}
	}
	for name := range ambiguous {
		delete(sigs, name)
	}
	if len(funcs) == 0 {
		return nil
	}

	seeds := make([]map[string]bool, len(funcs))
	for i, fn := range funcs {
		seeds[i] = collectTaintSeeds(codes[fn.blockIdx][fn.seg.start:fn.seg.end], rpcPkg)
	}

	// Fixpoint over call edges: tainted arguments taint callee parameters.
	paramTaint := make(map[string]map[string]bool)
	for pass := 0; pass < taintPropagationPasses+1; pass++ {
		changed := false
		for i, fn := range funcs {
			segText := codes[fn.blockIdx][fn.seg.start:fn.seg.end]
			tainted := initialTaint(seeds[i], fn, paramTaint)
			propagateTaint(segText, tainted)
			for _, e := range callParamEdges(segText, sigs, tainted, goManifestFileGateRe.MatchString(segText)) {
				set := paramTaint[e.callee]
				if set == nil {
					set = make(map[string]bool)
					paramTaint[e.callee] = set
				}
				for p := range e.params {
					if !set[p] {
						set[p] = true
						changed = true
					}
				}
			}
		}
		if !changed {
			break
		}
	}

	// Report sinks with converged taint. Hits are collected per function and
	// rolled up into a single finding: shared helpers (atomicWriteFile,
	// runCmd) can contain many sink calls, and per-line findings inflate the
	// count without adding information. Individual sink locations are kept
	// in Evidence.
	var findings []Finding
	seen := make(map[string]bool)
	for i, fn := range funcs {
		block := blocks[fn.blockIdx]
		code := codes[fn.blockIdx]
		segText := code[fn.seg.start:fn.seg.end]
		tainted := initialTaint(seeds[i], fn, paramTaint)
		snapshots, stmtStarts := propagateTaint(segText, tainted)
		manifestGate := goManifestFileGateRe.MatchString(segText)
		funcHasGuards := goGuardCallRe.MatchString(segText)
		paramSet := paramTaint[fn.name]
		// Provenance: when the function has no local taint seeds, every
		// tainted identifier inside it derives from call-edge parameters
		// (local propagation only spreads existing taint). Such sinks are
		// "inferred" — the risk decision lives at the caller/path
		// construction, not inside the helper.
		fnInferred := len(seeds[i]) == 0 && len(paramSet) > 0
		type sinkHit struct {
			line       int
			callName   string
			kind       string
			via        string
			severity   string
			confidence string
			suffix     string
		}
		var hits []sinkHit
		for _, m := range goTaintSinkRe.FindAllStringIndex(segText, -1) {
			callName := sinkCallName(segText, m[0])
			args := sinkArgSpan(segText, m[1]-1)
			if args == "" {
				continue
			}
			scope := stripGuardCalls(taintRelevantArgs(callName, args))
			if scope == "" {
				continue
			}
			direct := goTaintDirectSourceRe.MatchString(scope) ||
				(manifestGate && goManifestSourceRe.MatchString(scope))
			// Sinks are checked against the taint state at their own
			// statement: a validator placed after the sink must not clean
			// the earlier, unvalidated use.
			stateAtSink := tainted
			if stmtIdx := stmtIndexAt(stmtStarts, m[0]); stmtIdx >= 0 && stmtIdx < len(snapshots) {
				stateAtSink = snapshots[stmtIdx]
			}
			scopeTainted := false
			for _, id := range goTaintIdentRe.FindAllString(scope, -1) {
				if stateAtSink[id] {
					scopeTainted = true
					break
				}
			}
			inferredOnly := fnInferred && scopeTainted && !direct
			fieldPath := !direct && !scopeTainted && goSelectorPathRe.MatchString(scope)
			if !direct && !scopeTainted && !fieldPath {
				continue
			}
			line := lineAtOffset(block.firstLine, code, fn.seg.start+m[0])
			key := block.file + ":" + fmt.Sprint(line)
			if !block.addedLines[line] || seen[key] {
				continue
			}
			seen[key] = true
			kind := "filesystem/serving"
			if strings.Contains(callName, "exec.Command") {
				kind = "command execution"
			} else if goHTTPRequestSinkRe.MatchString(callName + "(") {
				kind = "outbound request"
			}
			via := "request-derived value"
			if rpcPkg && !direct {
				via = "plugin RPC input"
			} else if scopeTainted && !direct {
				via = "variable assigned from request input"
			} else if fieldPath {
				via = "struct field path"
			}
			severity := "high"
			confidence := "high"
			suffix := ""
			switch {
			case funcHasGuards:
				// The function applies validation somewhere; the sink may still
				// be reachable through an unguarded path, so keep the signal but
				// mark it for manual verification.
				severity = "medium"
				confidence = "medium"
				suffix = " (guarded function — verify coverage)"
			case fieldPath:
				severity = "medium"
				confidence = "medium"
				suffix = " (config/struct path — verify validation)"
			case inferredOnly && kind == "filesystem/serving":
				// Taint reached this helper only through a call edge: the
				// actual risk decision lives at the call site / path
				// construction, so report medium rather than inflating
				// every filesystem call inside shared helpers to high.
				// exec.Command and outbound requests stay high — a tainted
				// argument there is dangerous regardless of provenance.
				severity = "medium"
				confidence = "medium"
				suffix = " (inferred cross-function reachability — verify call chain)"
			case inferredOnly:
				confidence = "medium"
				suffix = " (inferred cross-function reachability — verify call chain)"
			}
			hits = append(hits, sinkHit{line: line, callName: callName, kind: kind, via: via, severity: severity, confidence: confidence, suffix: suffix})
		}
		if len(hits) == 0 {
			continue
		}
		// Roll up all sinks in this function into one finding.
		sort.Slice(hits, func(a, b int) bool { return hits[a].line < hits[b].line })
		sevRank := map[string]int{"low": 0, "medium": 1, "high": 2}
		best := hits[0]
		for _, h := range hits[1:] {
			if sevRank[h.severity] > sevRank[best.severity] ||
				(h.severity == best.severity && h.confidence == "high" && best.confidence != "high") {
				best = h
			}
		}
		var ev []FindingEvidence
		var calls []string
		seenCall := make(map[string]bool)
		for _, h := range hits {
			ev = append(ev, FindingEvidence{Rule: "request-taint", Severity: h.severity, Confidence: h.confidence, Line: h.line, Message: fmt.Sprintf("%s sink (%s)%s", h.kind, h.callName, h.suffix)})
			if !seenCall[h.callName] {
				seenCall[h.callName] = true
				calls = append(calls, h.callName)
			}
		}
		via := hits[0].via
		for _, h := range hits[1:] {
			if h.via != via {
				via = "mixed request-derived sources"
				break
			}
		}
		findings = append(findings, Finding{
			Category:    "security",
			Rule:        "request-taint",
			Severity:    best.severity,
			Confidence:  best.confidence,
			File:        block.file,
			Line:        hits[0].line,
			Signature:   fn.name,
			Message:     fmt.Sprintf("%s sink(s) reached by %s in %s (%s, %d site%s)%s", best.kind, via, fn.name, strings.Join(calls, ", "), len(hits), map[bool]string{true: "", false: "s"}[len(hits) == 1], best.suffix),
			Remediation: "Validate and constrain request-derived values before filesystem, serving, or exec sinks; prefer filepath.Base/allowlists and reject path separators.",
			Evidence:    ev,
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
	case strings.HasPrefix(callName, "exec.") || strings.Contains(callName, "plugin.Open") || strings.HasSuffix(callName, ".Do"):
		return args
	case strings.Contains(callName, "NewRequest"):
		// http.NewRequest(method, url, body): the URL is the risky argument.
		if len(parts) > 1 {
			return strings.Join(parts[1:], ",")
		}
		return ""
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
	// pluginEnvCredAssignRe catches credential env vars appended to a
	// subprocess Env field without requiring os.Environ() passthrough, e.g.
	// `cmd.Env = append(baseEnv(), "M3TAL_API_KEY="+key)`.
	pluginEnvCredAssignRe = regexp.MustCompile(`(?s)\b\w+\.Env\s*[:=][^;]{0,800}?["'][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Za-z0-9_]*=?["']`)
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
		hasEnvCred := pluginEnvCredRe.MatchString(block.text) || pluginEnvCredAssignRe.MatchString(block.text)
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
	emit := func(offset int, severity, confidence, message, remediation string) {
		line := lineAtOffset(block.firstLine, code, offset)
		if seen[line] || !block.addedLines[line] {
			return
		}
		seen[line] = true
		findings = append(findings, Finding{
			Category:    "security",
			Rule:        "plugin-trust",
			Severity:    severity,
			Confidence:  confidence,
			File:        block.file,
			Line:        line,
			Message:     message,
			Remediation: remediation,
		})
	}
	// Auto-start files: flag executable launches of discovered plugin commands.
	if pluginAutoStartRe.MatchString(code) {
		for _, m := range pluginExecRe.FindAllStringIndex(code, -1) {
			emit(m[0], "high", "medium", "Plugin/subprocess auto-start executes a command discovered at runtime", "Require explicit user consent or an allowlist before executing discovered plugin commands; do not auto-start code found on disk.")
		}
	}
	// Credential variables injected into subprocess environments (raw text:
	// the env var names are string literals that masking would blank).
	for _, re := range []*regexp.Regexp{pluginEnvCredRe, pluginEnvCredAssignRe} {
		for _, m := range re.FindAllStringIndex(block.text, -1) {
			emit(m[0], "medium", "medium", "Credential-bearing environment variables passed to plugin subprocess", "Pass only the minimum required credentials to plugins; prefer scoped, revocable tokens over primary API keys.")
		}
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
			emit(m[0], "medium", "high", "Plugin discovery searches a working-directory-relative path", "Resolve plugin directories against the user config/home directory or an explicit trusted path, not the process CWD.")
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

// ResolvedPathRule flags files that resolve symlinks (filepath.EvalSymlinks,
// os.Readlink) and also write files. Resolution changes the effective target:
// a containment check applied to the lexical path does not protect the
// resolved destination, so writes through resolved paths need re-validation.
type ResolvedPathRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (ResolvedPathRule) Name() string { return "resolved-path-write" }

var (
	resolvedPathRe = regexp.MustCompile(`filepath\.EvalSymlinks|os\.Readlink`)
	pathWriteRe    = regexp.MustCompile(`os\.(?:Rename|WriteFile|Create|OpenFile|MkdirAll)\s*\(|ioutil\.WriteFile\s*\(`)
)

func (r ResolvedPathRule) Check(diff string) []Finding {
	var findings []Finding
	for _, block := range sourceBlocks(diff, r.RepositoryRoot, r.WorkingTree) {
		if !strings.HasSuffix(block.file, ".go") || strings.HasSuffix(block.file, "_test.go") {
			continue
		}
		code := string(maskNonCode(block.file, block.text))
		resolve := resolvedPathRe.FindStringIndex(code)
		if resolve == nil || !pathWriteRe.MatchString(code) {
			continue
		}
		line := lineAtOffset(block.firstLine, code, resolve[0])
		if !block.addedLines[line] {
			continue
		}
		findings = append(findings, Finding{
			Category:    "security",
			Rule:        "resolved-path-write",
			Severity:    "medium",
			Confidence:  "medium",
			File:        block.file,
			Line:        line,
			Message:     "File resolves symlinks and performs file writes; containment checked before resolution may not cover the resolved target",
			Remediation: "Re-validate containment (e.g. filepath.Rel against the allowed root) on the resolved path before writing, or refuse to follow symlinks for managed files.",
		})
	}
	return findings
}
