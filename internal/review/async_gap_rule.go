package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// AsyncGapRule is a deterministic lifecycle static analyzer that detects
// BuildContext, setState(), or controller calls across async gaps (await) without
// verifying widget mountedness, preventing 'setState() called after dispose()'
// and deactivated ancestor lookup exceptions.
type AsyncGapRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (AsyncGapRule) Name() string {
	return "unmounted-async-gap"
}

func (r *AsyncGapRule) EnableWorkingTree() {
	r.WorkingTree = true
}

func (r AsyncGapRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// await statement
	awaitExprRe = regexp.MustCompile(`\bawait\s+`)

	// Single-line early exit guard (e.g. 'if (!mounted) return;', 'if (x || !context.mounted) return;', 'throw')
	mountedEarlyExitRe = regexp.MustCompile(
		`\bif\s*\([^)]*!(?:(?:this|context|[a-zA-Z0-9_]+)\.)?mounted[^)]*\)\s*(?:return\b|throw\b|rethrow\b)`,
	)

	// Opening of multi-line !mounted guard (e.g. 'if (!mounted) {')
	mountedIfNegativeBlockRe = regexp.MustCompile(
		`\bif\s*\([^)]*!(?:(?:this|context|[a-zA-Z0-9_]+)\.)?mounted[^)]*\)\s*\{`,
	)

	// Unconditional exit statement: return; return x; throw x; rethrow;
	unconditionalExitRe = regexp.MustCompile(`^\s*(?:return\b|throw\b|rethrow\b)`)

	// Guard reference and false comparison patterns
	mountedRefRe   = regexp.MustCompile(`\b(?:(?:this|context|[a-zA-Z0-9_]+)\.)?mounted\b`)
	mountedFalseRe = regexp.MustCompile(`\b(?:(?:this|context|[a-zA-Z0-9_]+)\.)?mounted\s*==\s*false\b|\b(?:(?:this|context|[a-zA-Z0-9_]+)\.)?mounted\s*!=\s*true\b`)

	// Ternary guard on mounted: mounted ? ... : ...
	mountedTernaryRe = regexp.MustCompile(`\b(?:(?:this|context|[a-zA-Z0-9_]+)\.)?mounted\s*\?`)

	// Calls requiring mounted context
	setStateRe   = regexp.MustCompile(`\bsetState\s*\(`)
	contextUseRe = regexp.MustCompile(
		`\b(?:Navigator\.(?:of|pop|push|maybePop|pushNamed|pushReplacement|popUntil|pushAndRemoveUntil|replace|removeRoute)|ScaffoldMessenger\.of|Scaffold\.of|Theme\.of|MediaQuery\.(?:of|sizeOf|orientationOf|paddingOf|viewInsetsOf|platformBrightnessOf|textScalerOf)|FocusScope\.of|DefaultTabController\.of|BlocProvider\.of(?:\s*<[^;\n()]+>)?|context\.(?:go|push|pop|read|watch|select)|ref\.(?:read|watch)|showDialog|showModalBottomSheet|showBottomSheet|showMenu|showDatePicker|showTimePicker|showSearch)\b`,
	)
	controllerRe = regexp.MustCompile(
		`(?i:\b\w*(?:controller|node|animation)\w*)\s*\.\s*(?:forward|reverse|reset|animateTo|jumpTo|jumpToPage|requestFocus)\s*\(`,
	)

	// Method declaration in Dart (handles nested generics like Future<List<T>>)
	methodDeclRe = regexp.MustCompile(
		`(?:^|\s)(?:@override\s+)?(?:void|Widget|Future(?:<[^;\n()]+>)?|[A-Z]\w*(?:<[^;\n()]+>)?|bool|int|String|double)\s+([a-zA-Z0-9_]+)\s*\(`,
	)

	// Event callback opening in Flutter UI (onPressed: () { ..., onTap: () => ...)
	eventCallbackRe = regexp.MustCompile(
		`\bon[A-Z]\w*\s*:\s*(?:\([^)]*\)|[a-zA-Z0-9_]+)?\s*(?:=>|\{)`,
	)

	deactivatedContextRe = regexp.MustCompile(
		`\b(?:Theme\.of|MediaQuery\.(?:of|sizeOf|orientationOf|paddingOf)|Navigator\.of|ScaffoldMessenger\.of|Provider\.of(?:\s*<[^;\n()]+>)?|context\.(?:read|watch|select)(?:\s*<[^;\n()]+>)?|context\.(?:go|push|pop))\s*\(`,
	)
	watchOutsideBuildRe = regexp.MustCompile(
		`\b(?:context|ref)\.watch\s*(?:<[^;\n()]+>)?\s*\(`,
	)
	topLevelDeclRe = regexp.MustCompile(
		`^(?:final|const|var|class|enum)\s+[a-zA-Z0-9_<>]+\s*=?`,
	)
)

func isSafePositiveMountedGuard(line string) (bool, map[string]bool) {
	openIdx := strings.Index(line, "if")
	if openIdx < 0 {
		return false, nil
	}
	parenStart := strings.Index(line[openIdx:], "(")
	if parenStart < 0 {
		return false, nil
	}
	parenStart += openIdx

	parenDepth := 0
	parenEnd := -1
	for idx := parenStart; idx < len(line); idx++ {
		if line[idx] == '(' {
			parenDepth++
		} else if line[idx] == ')' {
			parenDepth--
			if parenDepth == 0 {
				parenEnd = idx
				break
			}
		}
	}
	if parenEnd == -1 {
		return false, nil
	}
	cond := line[parenStart+1 : parenEnd]
	return impliesMounted(cond)
}

func stripEnclosingParens(expr string) string {
	expr = strings.TrimSpace(expr)
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		depth := 0
		enclosesAll := true
		for i := 0; i < len(expr)-1; i++ {
			if expr[i] == '(' {
				depth++
			} else if expr[i] == ')' {
				depth--
				if depth == 0 {
					enclosesAll = false
					break
				}
			}
		}
		if enclosesAll {
			expr = strings.TrimSpace(expr[1 : len(expr)-1])
		} else {
			break
		}
	}
	return expr
}

func impliesMounted(expr string) (bool, map[string]bool) {
	expr = stripEnclosingParens(expr)
	if expr == "" {
		return false, nil
	}

	// In Dart, conditional operator (? :) has lower precedence than ??, &&, ||.
	// Conservatively reject unsupported top-level conditional expressions before splitting at logical operators.
	if hasTopLevelTernary(expr) {
		return false, nil
	}

	// In Dart, null-coalescing (??) has lower precedence than && and ||.
	// Both alternatives must guarantee mountedness for the whole expression to imply mountedness.
	coalesceTerms := splitTopLevelOp(expr, "??")
	if len(coalesceTerms) > 1 {
		var commonReceivers map[string]bool
		for i, term := range coalesceTerms {
			safe, recs := impliesMounted(term)
			if !safe || len(recs) == 0 {
				return false, nil
			}
			if i == 0 {
				commonReceivers = make(map[string]bool, len(recs))
				for k, v := range recs {
					commonReceivers[k] = v
				}
			} else {
				for k := range commonReceivers {
					if !recs[k] {
						delete(commonReceivers, k)
					}
				}
				if len(commonReceivers) == 0 {
					return false, nil
				}
			}
		}
		return true, commonReceivers
	}

	// 1. Top-level disjunction (||): every term must guarantee mountedness.
	// Only receivers guaranteed across ALL branches are safely mounted.
	orTerms := splitTopLevelOp(expr, "||")
	if len(orTerms) > 1 {
		var commonReceivers map[string]bool
		for i, term := range orTerms {
			safe, recs := impliesMounted(term)
			if !safe || len(recs) == 0 {
				return false, nil
			}
			if i == 0 {
				commonReceivers = make(map[string]bool, len(recs))
				for k, v := range recs {
					commonReceivers[k] = v
				}
			} else {
				for k := range commonReceivers {
					if !recs[k] {
						delete(commonReceivers, k)
					}
				}
				if len(commonReceivers) == 0 {
					return false, nil
				}
			}
		}
		return true, commonReceivers
	}

	// 2. Top-level conjunction (&&): at least one term must guarantee mountedness.
	// Union the receivers guaranteed by any conjunct.
	andTerms := splitTopLevelOp(expr, "&&")
	if len(andTerms) > 1 {
		anySafe := false
		unionReceivers := make(map[string]bool)
		for _, term := range andTerms {
			safe, recs := impliesMounted(term)
			if safe {
				anySafe = true
				for k, v := range recs {
					if v {
						unionReceivers[k] = true
					}
				}
			}
		}
		if anySafe && len(unionReceivers) > 0 {
			return true, unionReceivers
		}
		return false, nil
	}

	// 3. Atomic positive condition
	atomic := strings.TrimSpace(expr)
	if strings.HasPrefix(atomic, "!") {
		return false, nil
	}
	if mountedFalseRe.MatchString(atomic) {
		return false, nil
	}
	m := atomicMountedRe.FindStringSubmatch(atomic)
	if len(m) > 0 {
		rec := m[1]
		if rec == "" || rec == "this" {
			// Bare mounted or this.mounted: State instance mounted check.
			// Guards setState() and State-level context.
			return true, map[string]bool{"this": true, "context": true}
		}
		// Qualified context guard like context.mounted or ctx.mounted
		return true, map[string]bool{rec: true}
	}
	return false, nil
}

func splitTopLevelOp(expr string, op string) []string {
	var parts []string
	parenDepth := 0
	lastIdx := 0
	opLen := len(op)
	inQuote := false
	var quoteChar byte

	for i := 0; i <= len(expr)-opLen; i++ {
		ch := expr[i]
		if inQuote {
			if ch == '\\' {
				i++
				continue
			}
			if ch == quoteChar {
				inQuote = false
			}
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = true
			quoteChar = ch
			continue
		}
		if ch == '(' || ch == '[' || ch == '{' {
			parenDepth++
		} else if ch == ')' || ch == ']' || ch == '}' {
			parenDepth--
		} else if parenDepth == 0 && expr[i:i+opLen] == op {
			if op == "??" && i+opLen < len(expr) && expr[i+opLen] == '=' {
				continue
			}
			parts = append(parts, expr[lastIdx:i])
			lastIdx = i + opLen
			i += opLen - 1
		}
	}
	if lastIdx < len(expr) {
		parts = append(parts, expr[lastIdx:])
	}
	return parts
}

var (
	atomicMountedRe   = regexp.MustCompile(`^(?:(this|context|[a-zA-Z0-9_]+)\.)?mounted(?:\s*==\s*true|\s*!=\s*false)?$`)
	staticNavigatorRe = regexp.MustCompile(`\bNavigator\.(?:pop|push|maybePop|pushNamed|pushReplacement|popUntil|pushAndRemoveUntil|replace|removeRoute)\s*\(\s*([a-zA-Z0-9_]+)`)
)

func isCallProtectedByReceivers(line string, activeReceivers map[string]bool) bool {
	if activeReceivers == nil {
		return false
	}
	hasStateMounted := activeReceivers["this"]

	if setStateRe.MatchString(line) {
		return hasStateMounted
	}
	if controllerRe.MatchString(line) {
		return hasStateMounted
	}

	if m := staticNavigatorRe.FindStringSubmatch(line); len(m) > 1 {
		arg := m[1]
		if (arg == "context" || arg == "this") && hasStateMounted {
			return true
		}
		return activeReceivers[arg]
	}

	if m := regexp.MustCompile(`\b([a-zA-Z0-9_]+)\.(?:go|push|pop|read|watch|select)\b`).FindStringSubmatch(line); len(m) > 1 {
		recv := m[1]
		if recv == "ref" {
			return hasStateMounted || activeReceivers["ref"] || activeReceivers["this"]
		}
		if (recv == "context" || recv == "this") && (hasStateMounted || activeReceivers["context"]) {
			return true
		}
		return activeReceivers[recv]
	}

	if m := regexp.MustCompile(`\b(?:of|Of)\s*\(\s*([a-zA-Z0-9_]+)`).FindStringSubmatch(line); len(m) > 1 {
		arg := m[1]
		if (arg == "context" || arg == "this") && hasStateMounted {
			return true
		}
		return activeReceivers[arg]
	}
	if m := regexp.MustCompile(`\bcontext\s*:\s*([a-zA-Z0-9_]+)`).FindStringSubmatch(line); len(m) > 1 {
		arg := m[1]
		if (arg == "context" || arg == "this") && hasStateMounted {
			return true
		}
		return activeReceivers[arg]
	}

	if contextUseRe.MatchString(line) {
		if hasStateMounted || activeReceivers["context"] {
			return true
		}
		return false
	}

	return hasStateMounted
}

func hasTopLevelTernary(expr string) bool {
	parenDepth := 0
	hasQuestion := false
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if ch == '(' {
			parenDepth++
			continue
		}
		if ch == ')' {
			parenDepth--
			continue
		}
		if parenDepth == 0 {
			if ch == '?' {
				// Ignore Dart null-aware ?. and null-coalescing ?? or ??=
				if i+1 < len(expr) && (expr[i+1] == '.' || expr[i+1] == '?') {
					continue
				}
				if i > 0 && expr[i-1] == '?' {
					continue
				}
				hasQuestion = true
			} else if ch == ':' && hasQuestion {
				return true
			}
		}
	}
	return false
}

var mountedExitExtractRe = regexp.MustCompile(`\bif\s*\([^)]*!(?:((?:this|context|[a-zA-Z0-9_]+))\.)?mounted[^)]*\)`)

func getUnconditionalEarlyExitReceivers(lines []string, j int) (bool, map[string]bool) {
	line := lines[j]
	isExit := false
	if mountedEarlyExitRe.MatchString(line) {
		isExit = true
	} else if mountedIfNegativeBlockRe.MatchString(line) {
		maxK := j + 4
		if maxK > len(lines) {
			maxK = len(lines)
		}
		for k := j + 1; k < maxK; k++ {
			trimmed := strings.TrimSpace(lines[k])
			if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
				continue
			}
			if unconditionalExitRe.MatchString(trimmed) {
				isExit = true
				break
			}
			if strings.HasPrefix(trimmed, "if") || strings.Contains(trimmed, "}") {
				break
			}
		}
	}
	if !isExit {
		return false, nil
	}
	m := mountedExitExtractRe.FindStringSubmatch(line)
	if len(m) > 1 {
		rec := m[1]
		if rec == "" || rec == "this" {
			return true, map[string]bool{"this": true, "context": true}
		}
		return true, map[string]bool{rec: true}
	}
	return true, map[string]bool{"this": true, "context": true}
}

func (r AsyncGapRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		// Only check Dart source files (.dart) and ignore tests
		if !strings.HasSuffix(strings.ToLower(filePath), ".dart") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		// If repository snapshot is available, load full file source so partial diff hunks have full enclosing method context
		if r.RepositoryRoot != "" {
			if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
				blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
			}
		}

		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

type guardScope struct {
	braceDepth int
	receivers  map[string]bool
}

func getActiveReceivers(cumulativeProvenReceivers map[string]bool, guardStack []guardScope) map[string]bool {
	activeReceivers := make(map[string]bool, len(cumulativeProvenReceivers))
	for k, v := range cumulativeProvenReceivers {
		if v {
			activeReceivers[k] = true
		}
	}
	for _, scope := range guardStack {
		for k, v := range scope.receivers {
			if v {
				activeReceivers[k] = true
			}
		}
	}
	return activeReceivers
}

func (r AsyncGapRule) checkConditionSinks(currLine string, currLineNum, awaitLineNum int, activeReceivers map[string]bool, block diffSourceBlock, seen map[string]bool) *Finding {
	openIdx := strings.Index(currLine, "if")
	if openIdx < 0 {
		return nil
	}
	parenStart := strings.Index(currLine[openIdx:], "(")
	if parenStart < 0 {
		return nil
	}
	parenStart += openIdx
	parenDepth := 0
	parenEnd := -1
	for idx := parenStart; idx < len(currLine); idx++ {
		if currLine[idx] == '(' {
			parenDepth++
		} else if currLine[idx] == ')' {
			parenDepth--
			if parenDepth == 0 {
				parenEnd = idx
				break
			}
		}
	}
	if parenEnd == -1 {
		return nil
	}
	cond := currLine[parenStart+1 : parenEnd]

	condReceivers := make(map[string]bool, len(activeReceivers))
	for k, v := range activeReceivers {
		condReceivers[k] = v
	}

	return r.checkExprSinks(cond, currLine, currLineNum, awaitLineNum, block, condReceivers, seen)
}

func (r AsyncGapRule) checkExprSinks(
	expr string,
	currLine string,
	currLineNum int,
	awaitLineNum int,
	block diffSourceBlock,
	condReceivers map[string]bool,
	seen map[string]bool,
) *Finding {
	expr = stripEnclosingParens(expr)
	if expr == "" {
		return nil
	}

	// In Dart, logical OR (||) has lower precedence than &&.
	// In a || b, if a evaluates to false, b runs without assuming a's facts.
	orTerms := splitTopLevelOp(expr, "||")
	if len(orTerms) > 1 {
		for _, orTerm := range orTerms {
			branchReceivers := make(map[string]bool, len(condReceivers))
			for k, v := range condReceivers {
				branchReceivers[k] = v
			}
			if f := r.checkExprSinks(orTerm, currLine, currLineNum, awaitLineNum, block, branchReceivers, seen); f != nil {
				return f
			}
		}
		return nil
	}

	// In Dart, logical AND (&&) has left-to-right short-circuit evaluation.
	// Facts established by earlier operands flow into subsequent operands.
	andTerms := splitTopLevelOp(expr, "&&")
	if len(andTerms) > 1 {
		for _, term := range andTerms {
			if f := r.checkExprSinks(term, currLine, currLineNum, awaitLineNum, block, condReceivers, seen); f != nil {
				return f
			}
			if safe, recs := impliesMounted(term); safe {
				for k, v := range recs {
					if v {
						condReceivers[k] = true
					}
				}
			}
		}
		return nil
	}

	// Leaf term: check for unguarded sink invocation
	term := expr
	matchedOp := ""
	if setStateRe.MatchString(term) {
		matchedOp = "setState()"
	} else if m := contextUseRe.FindString(term); m != "" {
		matchedOp = m
	} else if m := controllerRe.FindString(term); m != "" {
		matchedOp = strings.TrimSuffix(m, "(")
	}

	if matchedOp != "" && !isCallProtectedByReceivers(term, condReceivers) {
		if block.addedLines[currLineNum] || block.addedLines[awaitLineNum] {
			key := fmt.Sprintf("%s:%d:%s", block.file, currLineNum, matchedOp)
			if !seen[key] {
				seen[key] = true
				msg := fmt.Sprintf(
					"%s called across async gap (after await on line %d) without checking if (!mounted) or if (!context.mounted); throws if widget unmounts during async operation",
					matchedOp, awaitLineNum,
				)
				remediation := "Add 'if (!mounted) return;' (or 'if (!context.mounted) return;') immediately after the await statement."
				return &Finding{
					Rule:        "unmounted-async-gap",
					Severity:    "high",
					Category:    "quality",
					File:        block.file,
					Line:        currLineNum,
					Message:     msg,
					Remediation: remediation,
					Confidence:  "High",
					Snippet:     strings.TrimSpace(currLine),
					Explanation: &model.FindingExplanation{
						RuleRationale:   "Calling setState, BuildContext, or controllers after an asynchronous operation when the widget has been unmounted causes runtime exceptions.",
						EvidenceSummary: fmt.Sprintf("%s invoked across async boundary without mounted guard.", matchedOp),
						EvidenceKind:    "async-lifecycle",
					},
				}
			}
		}
	}

	if safe, recs := impliesMounted(term); safe {
		for k, v := range recs {
			if v {
				condReceivers[k] = true
			}
		}
	}
	return nil
}

var (
	controlFlowBlockRe = regexp.MustCompile(`\b(if|else|for|while|do|switch|try|catch|finally)\s*(?:\([^)]*\))?\s*$`)
	typeDeclBlockRe    = regexp.MustCompile(`\b(class|enum|mixin|extension)\b`)
	funcOrClosureRe    = regexp.MustCompile(`(?:\b(?:async|sync)\*?|\bfunction\b|\)\s*(?:async)?)\s*$`)
)

func isFuncOrClosureHeader(header string) bool {
	h := strings.TrimSpace(header)
	if controlFlowBlockRe.MatchString(h) || typeDeclBlockRe.MatchString(h) {
		return false
	}
	if methodDeclRe.MatchString(h) || eventCallbackRe.MatchString(h) || funcOrClosureRe.MatchString(h) {
		return true
	}
	if strings.Contains(h, "async") {
		return true
	}
	if strings.HasSuffix(h, ")") {
		return true
	}
	return false
}

type braceScopeEntry struct {
	depth  int
	isFunc bool
}

func (r AsyncGapRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	currentMethod := ""
	methodBaseDepth := 0
	currentBraceDepth := 0
	var fileBraceStack []braceScopeEntry

	for i, line := range lines {
		lineNum := block.firstLine + i

		// Track method declarations and depth
		if m := methodDeclRe.FindStringSubmatch(line); len(m) > 1 {
			currentMethod = m[1]
			methodBaseDepth = currentBraceDepth
		}

		awaitPos := -1
		if loc := awaitExprRe.FindStringIndex(line); loc != nil {
			awaitPos = loc[0]
		}

		processBraces := func(startChar, endChar int) {
			for cIdx := startChar; cIdx < endChar; cIdx++ {
				ch := line[cIdx]
				if ch == '{' {
					currentBraceDepth++
					header := ""
					before := strings.TrimSpace(line[:cIdx])
					if before != "" {
						header = before
					} else {
						for prev := i - 1; prev >= 0; prev-- {
							p := strings.TrimSpace(lines[prev])
							if p != "" {
								header = p
								break
							}
						}
					}
					isFunc := isFuncOrClosureHeader(header)
					fileBraceStack = append(fileBraceStack, braceScopeEntry{depth: currentBraceDepth, isFunc: isFunc})
				} else if ch == '}' {
					currentBraceDepth--
					if len(fileBraceStack) > 0 {
						fileBraceStack = fileBraceStack[:len(fileBraceStack)-1]
					}
					if currentMethod != "" && currentBraceDepth <= methodBaseDepth {
						currentMethod = ""
					}
				}
			}
		}

		if awaitPos >= 0 {
			processBraces(0, awaitPos)
		} else {
			processBraces(0, len(line))
			continue
		}

		// Enclosing function or closure depth
		enclosingFuncDepth := 0
		for idx := len(fileBraceStack) - 1; idx >= 0; idx-- {
			if fileBraceStack[idx].isFunc {
				enclosingFuncDepth = fileBraceStack[idx].depth
				break
			}
		}
		if enclosingFuncDepth == 0 {
			if currentMethod != "" {
				enclosingFuncDepth = methodBaseDepth + 1
			} else if currentBraceDepth > 0 {
				enclosingFuncDepth = 1
			}
		}

		// Find the end line of the await statement (balanced parentheses and semicolon)
		stmtEnd := i
		parenDepth := 0
		for k := i; k < len(lines); k++ {
			stmtEnd = k
			for _, ch := range lines[k] {
				if ch == '(' {
					parenDepth++
				} else if ch == ')' {
					parenDepth--
				}
			}
			if parenDepth <= 0 && strings.Contains(lines[k], ";") {
				break
			}
		}

		// Inspect subsequent lines (up to 50 lines) after the await statement completes
		end := stmtEnd + 50
		if end > len(lines) {
			end = len(lines)
		}

		var guardStack []guardScope
		cumulativeProvenReceivers := make(map[string]bool)
		scopeBraceDepth := 0

		runningBraceDepth := currentBraceDepth
		for cIdx := awaitPos; cIdx < len(line); cIdx++ {
			if line[cIdx] == '{' {
				runningBraceDepth++
			} else if line[cIdx] == '}' {
				runningBraceDepth--
			}
		}
		for k := i + 1; k <= stmtEnd && k < len(lines); k++ {
			for _, ch := range lines[k] {
				if ch == '{' {
					runningBraceDepth++
				} else if ch == '}' {
					runningBraceDepth--
				}
			}
		}

		for j := stmtEnd + 1; j < end; j++ {
			currLine := lines[j]
			currLineNum := block.firstLine + j

			// If a new method or top-level declaration begins, break
			if methodDeclRe.MatchString(currLine) || topLevelDeclRe.MatchString(currLine) {
				break
			}

			// Check for unconditional early exit of unmounted path
			if isExit, proven := getUnconditionalEarlyExitReceivers(lines, j); isExit {
				for k, v := range proven {
					if v {
						cumulativeProvenReceivers[k] = true
					}
				}
				if cumulativeProvenReceivers["this"] {
					break
				}
			}

			// Check for entering positive guard branch: if (mounted && ...) {
			var pendingGuardRecs map[string]bool
			isGuardLine := false
			if safe, recs := isSafePositiveMountedGuard(currLine); safe && strings.Contains(currLine, "{") {
				isGuardLine = true
				currentActive := getActiveReceivers(cumulativeProvenReceivers, guardStack)
				if f := r.checkConditionSinks(currLine, currLineNum, lineNum, currentActive, block, seen); f != nil {
					findings = append(findings, *f)
				}
				pendingGuardRecs = recs
			}

			for _, ch := range currLine {
				if ch == '{' {
					runningBraceDepth++
					scopeBraceDepth++
					if pendingGuardRecs != nil {
						guardStack = append(guardStack, guardScope{braceDepth: scopeBraceDepth, receivers: pendingGuardRecs})
						pendingGuardRecs = nil
					}
				} else if ch == '}' {
					runningBraceDepth--
					scopeBraceDepth--
					for len(guardStack) > 0 && scopeBraceDepth < guardStack[len(guardStack)-1].braceDepth {
						guardStack = guardStack[:len(guardStack)-1]
					}
				}
			}

			if isGuardLine {
				continue
			}

			// Stop only when the enclosing function or callback boundary exits
			if runningBraceDepth < enclosingFuncDepth {
				break
			}

			// Active receivers is union of proven receivers and active guard scopes
			activeReceivers := getActiveReceivers(cumulativeProvenReceivers, guardStack)

			if isCallProtectedByReceivers(currLine, activeReceivers) {
				continue
			}

			// Single-line ternary guard: mounted ? ... : ...
			if mountedTernaryRe.MatchString(currLine) {
				continue
			}

			// Unprotected call check
			if block.addedLines[currLineNum] || block.addedLines[lineNum] {
				matchedOp := ""
				if setStateRe.MatchString(currLine) {
					matchedOp = "setState()"
				} else if m := contextUseRe.FindString(currLine); m != "" {
					matchedOp = m
				} else if m := controllerRe.FindString(currLine); m != "" {
					matchedOp = strings.TrimSuffix(m, "(")
				}

				if matchedOp != "" {
					key := fmt.Sprintf("%s:%d:%s", block.file, currLineNum, matchedOp)
					if seen[key] {
						continue
					}
					seen[key] = true

					msg := fmt.Sprintf(
						"%s called across async gap (after await on line %d) without checking if (!mounted) or if (!context.mounted); throws if widget unmounts during async operation",
						matchedOp, lineNum,
					)
					remediation := "Add 'if (!mounted) return;' (or 'if (!context.mounted) return;') immediately after the await statement."

					finding := Finding{
						Rule:        "unmounted-async-gap",
						Severity:    "high",
						Category:    "quality",
						File:        block.file,
						Line:        currLineNum,
						Message:     msg,
						Remediation: remediation,
						Confidence:  "High",
						Snippet:     strings.TrimSpace(currLine),
						Explanation: &model.FindingExplanation{
							RuleRationale:   "Calling setState, BuildContext, or controllers after an asynchronous operation when the widget has been unmounted causes runtime exceptions.",
							EvidenceSummary: fmt.Sprintf("%s invoked across async boundary without mounted guard.", matchedOp),
							EvidenceKind:    "async-boundary",
							EvidenceSteps: []model.ExplainedStep{
								{
									StepNumber: 1,
									Kind:       "source",
									Location:   fmt.Sprintf("%s:%d", block.file, lineNum),
									Statement:  "Asynchronous await operation suspends execution",
								},
								{
									StepNumber: 2,
									Kind:       "sink",
									Location:   fmt.Sprintf("%s:%d", block.file, currLineNum),
									Statement:  fmt.Sprintf("%s called without verifying widget is still mounted", matchedOp),
								},
							},
						},
					}
					findings = append(findings, finding)
					break
				}
			}
		}
		processBraces(awaitPos, len(line))
	}

	return findings
}
