package slop

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// checkResourceClose reports http response bodies, sql.Rows and opened files
// that are never closed within the same function.
func (v *slopInspector) checkResourceClose(fn *ast.FuncDecl) {
	var respVars, rowsVars, fileVars []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			for i, e := range node.Rhs {
				call, ok := e.(*ast.CallExpr)
				if !ok || i >= len(node.Lhs) {
					continue
				}
				name := callName(call)
				lhs, ok := node.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				switch {
				case isHTTPDoCall(name):
					respVars = append(respVars, lhs.Name)
				case isSQLRowsCall(name):
					rowsVars = append(rowsVars, lhs.Name)
				case isFileOpenCall(name):
					fileVars = append(fileVars, lhs.Name)
				}
			}
		}
		return true
	})
	// A .Close() on any selector/ident counts as closing the variable it is
	// called on; collect closed base identifiers too.
	closedIdents := make(map[string]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Close" {
				base := baseIdent(sel.X)
				if base != "" {
					closedIdents[base] = true
				}
			}
		}
		return true
	})
	for _, name := range respVars {
		if !closedIdents[name] && !closedIdents[name+".Body"] {
			v.addFindingPos(fn.Pos(), "HTTP response body is never closed", "Defer resp.Body.Close() immediately after checking the error.")
		}
	}
	for _, name := range rowsVars {
		if !closedIdents[name] {
			v.addFindingPos(fn.Pos(), "sql.Rows is never closed", "Defer rows.Close() after checking the error.")
		}
	}
	for _, name := range fileVars {
		if !closedIdents[name] {
			v.addFindingPos(fn.Pos(), "Opened file is never closed", "Defer file.Close() or use a helper that closes it.")
		}
	}
}

func callName(call *ast.CallExpr) string {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			return id.Name + "." + sel.Sel.Name
		}
		return sel.Sel.Name
	}
	return ""
}

func baseIdent(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name + "." + x.Sel.Name
		}
		return x.Sel.Name
	}
	return ""
}

func isHTTPDoCall(name string) bool {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return false
	}
	switch name[i+1:] {
	case "Get", "Post", "PostForm", "Head", "Do":
		return true
	}
	return false
}

func isSQLRowsCall(name string) bool {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return false
	}
	switch name[i+1:] {
	case "Query", "QueryRow", "QueryContext", "QueryRowContext":
		return true
	}
	return false
}

func isFileOpenCall(name string) bool {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return false
	}
	switch name[i+1:] {
	case "Open", "Create", "OpenFile", "CreateTemp":
		return true
	}
	return false
}

// checkStringConcatLoop reports `s += ...` inside a for/range loop.
func (v *slopInspector) checkStringConcatLoop(stmt ast.Stmt) {
	var body *ast.BlockStmt
	switch s := stmt.(type) {
	case *ast.ForStmt:
		body = s.Body
	case *ast.RangeStmt:
		body = s.Body
	default:
		return
	}
	if body == nil {
		return
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if as, ok := n.(*ast.AssignStmt); ok && as.Tok == token.ADD_ASSIGN {
			if len(as.Lhs) > 0 {
				if _, ok := as.Lhs[0].(*ast.Ident); ok {
					found = true
				}
			}
		}
		return true
	})
	if found {
		line := v.fset.Position(stmt.Pos()).Line
		if v.lineMap[line] {
			v.addFinding(line, "String concatenation inside a loop", "Use strings.Builder or strings.Join to avoid quadratic allocation.")
		}
	}
}

// checkMustCompileFunc reports regexp.MustCompile calls inside functions
// (they recompile on every call; hoist to package level).
func (v *slopInspector) checkMustCompile(call *ast.CallExpr) {
	if !strings.Contains(callName(call), "MustCompile") {
		return
	}
	line := v.fset.Position(call.Pos()).Line
	if v.lineMap[line] {
		v.addFinding(line, "regexp.MustCompile inside a function", "Hoist the compiled regexp to package level to avoid recompiling per call.")
	}
}

// checkIgnoredErrorCall reports expression statements that discard error
// returns from well-known fallible APIs.
func (v *slopInspector) checkIgnoredErrorCall(stmt *ast.ExprStmt) {
	call, ok := stmt.X.(*ast.CallExpr)
	if !ok {
		return
	}
	name := callName(call)
	if name == "" {
		return
	}
	base := name
	if i := strings.LastIndex(base, "."); i >= 0 {
		base = base[i+1:]
	}
	switch base {
	case "Unmarshal", "Decode", "Atoi", "ParseInt", "ParseFloat", "ParseBool", "ParseUint", "Sscanf", "Fscanf", "Scan", "Scanln":
		line := v.fset.Position(stmt.Pos()).Line
		if v.lineMap[line] {
			v.addFinding(line, "Error return ignored on "+name+"()", "Check and handle the returned error explicitly.")
		}
	}
}

// checkUncheckedAssert reports bare type assertions whose result is discarded.
func (v *slopInspector) checkUncheckedAssert(stmt *ast.ExprStmt) {
	if _, ok := stmt.X.(*ast.TypeAssertExpr); ok {
		line := v.fset.Position(stmt.Pos()).Line
		if v.lineMap[line] {
			v.addFinding(line, "Unchecked type assertion", "Use the two-value form and handle the ok result.")
		}
	}
}

// checkDivBeforeMul reports `a / b * c` which loses precision; suggest
// `(a * c) / b` ordering when safe.
func (v *slopInspector) checkDivBeforeMul(expr *ast.BinaryExpr) {
	if expr.Op != token.MUL {
		return
	}
	left, ok := expr.X.(*ast.BinaryExpr)
	if !ok || left.Op != token.QUO {
		return
	}
	line := v.fset.Position(expr.Pos()).Line
	if v.lineMap[line] {
		v.addFinding(line, "Division before multiplication", "Reorder to (a * c) / b to reduce integer precision loss.")
	}
}

// checkDeferInLoop reports defer statements inside loop bodies.
func (v *slopInspector) checkDeferInLoop(stmt ast.Stmt) {
	var body *ast.BlockStmt
	switch s := stmt.(type) {
	case *ast.ForStmt:
		body = s.Body
	case *ast.RangeStmt:
		body = s.Body
	default:
		return
	}
	if body == nil {
		return
	}
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		if _, ok := n.(*ast.DeferStmt); ok {
			found = true
		}
		return true
	})
	if found {
		line := v.fset.Position(stmt.Pos()).Line
		if v.lineMap[line] {
			v.addFinding(line, "defer inside a loop", "Defers accumulate until function return; restructure to bound resource lifetime.")
		}
	}
}

// checkSleepInCode reports time.Sleep calls in non-test Go files.
func (v *slopInspector) checkSleep(call *ast.CallExpr) {
	if !strings.HasSuffix(v.file, "_test.go") && callName(call) == "Sleep" {
		line := v.fset.Position(call.Pos()).Line
		if v.lineMap[line] {
			v.addFinding(line, "time.Sleep in production code", "Avoid sleeps for synchronization; use channels, contexts or timers.")
		}
	}
}

// checkInitFunc reports init() functions with substantial bodies.
func (v *slopInspector) checkInitFunc(fn *ast.FuncDecl) {
	if fn.Recv != nil || fn.Name.Name != "init" || fn.Body == nil {
		return
	}
	stmts := len(fn.Body.List)
	if stmts < 3 {
		return
	}
	line := v.fset.Position(fn.Pos()).Line
	if v.lineMap[line] {
		v.addFinding(line, "init() with substantial body", "Prefer explicit initialization; init() runs implicitly and is hard to test.")
	}
}

// checkFatalOutsideMain reports os.Exit/log.Fatal in functions other than main.
func (v *slopInspector) checkFatalOutsideMain(fn *ast.FuncDecl, call *ast.CallExpr) {
	if fn.Name.Name == "main" || strings.Contains(v.file, "/cmd/") {
		return
	}
	name := callName(call)
	if name != "Exit" && name != "Fatal" && name != "Fatalf" && name != "Fatalln" {
		return
	}
	line := v.fset.Position(call.Pos()).Line
	if v.lineMap[line] {
		v.addFinding(line, "Process-exiting call outside main()", "Return an error instead of exiting the host process from library code.")
	}
}

// checkUnusedParams reports function parameters that are never referenced.
func (v *slopInspector) checkUnusedParams(fn *ast.FuncDecl) {
	if fn.Type.Params == nil {
		return
	}
	if fn.Body != nil {
		used := make(map[string]bool)
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				used[id.Name] = true
			}
			return true
		})
		for _, field := range fn.Type.Params.List {
			for _, name := range field.Names {
				param := name.Name
				if param == "_" || param == "this" || used[param] {
					continue
				}
				line := v.fset.Position(name.Pos()).Line
				if v.lineMap[line] {
					v.addFinding(line, "Unused parameter "+param, "Rename to _ if intentionally unused, or remove the parameter.")
				}
			}
		}
	}
}

// checkCyclomatic reports functions with high branch density.
func (v *slopInspector) checkCyclomatic(fn *ast.FuncDecl) {
	if fn.Body == nil {
		return
	}
	branches := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			branches++
		case *ast.BinaryExpr:
			if b, ok := n.(*ast.BinaryExpr); ok && (b.Op == token.LAND || b.Op == token.LOR) {
				branches++
			}
		}
		return true
	})
	if branches > 15 {
		line := v.fset.Position(fn.Pos()).Line
		if v.lineMap[line] {
			v.addFinding(line, "Function has high branch complexity ("+strconv.Itoa(branches)+" branches)", "Consider splitting into smaller functions or a lookup table.")
		}
	}
}

func (v *slopInspector) addFindingPos(pos token.Pos, message, remediation string) {
	line := v.fset.Position(pos).Line
	if v.lineMap[line] {
		v.addFinding(line, message, remediation)
	}
}

// enclosingFuncDecl returns the innermost function declaration on the
// inspector's ancestor stack, or nil at package level.
func (v *slopInspector) enclosingFuncDecl() *ast.FuncDecl {
	for i := len(v.stack) - 1; i >= 0; i-- {
		if fn, ok := v.stack[i].(*ast.FuncDecl); ok {
			return fn
		}
	}
	return nil
}
