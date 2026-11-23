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
	if fn.Body == nil {
		return
	}
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

// checkDeferBeforeErrCheck detects deferring .Close() on a resource before checking if err != nil.
// If the call returns an error, the resource is nil and calling .Close() causes a panic on return.
func (v *slopInspector) checkDeferBeforeErrCheck(fn *ast.FuncDecl) {
	if fn.Body == nil {
		return
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		block, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		for i := 0; i < len(block.List)-1; i++ {
			assign, ok := block.List[i].(*ast.AssignStmt)
			if !ok || len(assign.Lhs) < 2 || len(assign.Rhs) != 1 {
				continue
			}
			call, ok := assign.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			name := callName(call)
			if !isHTTPDoCall(name) && !isFileOpenCall(name) && !isSQLRowsCall(name) {
				continue
			}

			resIdent, ok1 := assign.Lhs[0].(*ast.Ident)
			errIdent, ok2 := assign.Lhs[len(assign.Lhs)-1].(*ast.Ident)
			if !ok1 || !ok2 {
				continue
			}
			resName := resIdent.Name
			errName := errIdent.Name

			deferStmt, ok := block.List[i+1].(*ast.DeferStmt)
			if !ok || deferStmt.Call == nil {
				continue
			}
			sel, ok := deferStmt.Call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Close" {
				continue
			}
			base := baseIdent(sel.X)
			if base != resName && base != resName+".Body" {
				continue
			}

			if i+2 < len(block.List) {
				if ifStmt, ok := block.List[i+2].(*ast.IfStmt); ok {
					if isErrCheck(ifStmt.Cond, errName) {
						v.addFindingPos(deferStmt.Pos(),
							"Resource closed with defer before checking error",
							"Check `if err != nil` before calling `defer "+base+".Close()`; a non-nil error leaves the resource nil and panics.")
					}
				}
			}
		}
		return true
	})
}

func isErrCheck(cond ast.Expr, errName string) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	if bin.Op == token.NEQ || bin.Op == token.EQL {
		if id, ok := bin.X.(*ast.Ident); ok && id.Name == errName {
			if id2, ok := bin.Y.(*ast.Ident); ok && id2.Name == "nil" {
				return true
			}
		}
		if id, ok := bin.Y.(*ast.Ident); ok && id.Name == errName {
			if id2, ok := bin.X.(*ast.Ident); ok && id2.Name == "nil" {
				return true
			}
		}
	}
	return false
}

// checkWaitGroupAddInGo detects calling sync.WaitGroup.Add inside a spawned goroutine.
func (v *slopInspector) checkWaitGroupAddInGo(goStmt *ast.GoStmt) {
	if goStmt == nil || goStmt.Call == nil {
		return
	}
	ast.Inspect(goStmt.Call, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Add" {
			base := baseIdent(sel.X)
			baseLower := strings.ToLower(base)
			if strings.Contains(baseLower, "wg") || strings.Contains(baseLower, "waitgroup") {
				v.addFindingPos(call.Pos(),
					"sync.WaitGroup.Add called inside spawned goroutine",
					"Call wg.Add in the coordinator goroutine before `go` to prevent a race where wg.Wait() finishes before the goroutine starts.")
			}
		}
		return true
	})
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

// checkCyclomatic reports functions with high branch density.
func (v *slopInspector) checkCyclomatic(fn *ast.FuncDecl) {
	if fn.Body == nil {
		return
	}
	branches := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IfStmt, *ast.ForStmt, *ast.RangeStmt, *ast.CaseClause, *ast.CommClause:
			branches++
		case *ast.BinaryExpr:
			if n.Op == token.LAND || n.Op == token.LOR {
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

// checkTypedNilError detects functions returning a concrete pointer variable
// as an error interface, which results in a typed nil (err != nil evaluates to true).
func (v *slopInspector) checkTypedNilError(fn *ast.FuncDecl) {
	if fn == nil || fn.Type == nil || fn.Type.Results == nil || fn.Body == nil {
		return
	}
	errorIndices := make(map[int]bool)
	for i, field := range fn.Type.Results.List {
		if id, ok := field.Type.(*ast.Ident); ok && id.Name == "error" {
			errorIndices[i] = true
		}
	}
	if len(errorIndices) == 0 {
		return
	}

	pointerVars := make(map[string]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch stmt := n.(type) {
		case *ast.DeclStmt:
			if gen, ok := stmt.Decl.(*ast.GenDecl); ok && gen.Tok == token.VAR {
				for _, spec := range gen.Specs {
					if vspec, ok := spec.(*ast.ValueSpec); ok {
						if _, ok := vspec.Type.(*ast.StarExpr); ok {
							for _, name := range vspec.Names {
								pointerVars[name.Name] = true
							}
						}
					}
				}
			}
		case *ast.AssignStmt:
			for i, rhs := range stmt.Rhs {
				if call, ok := rhs.(*ast.CallExpr); ok {
					if _, ok := call.Fun.(*ast.StarExpr); ok && i < len(stmt.Lhs) {
						if id, ok := stmt.Lhs[i].(*ast.Ident); ok {
							pointerVars[id.Name] = true
						}
					}
				}
			}
		}
		return true
	})

	if len(pointerVars) == 0 {
		return
	}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for i, res := range ret.Results {
			if !errorIndices[i] {
				continue
			}
			if id, ok := res.(*ast.Ident); ok && pointerVars[id.Name] {
				v.addFindingPos(ret.Pos(),
					"Concrete pointer returned as error interface",
					"Returning a concrete pointer variable as an error interface creates a typed-nil trap where `err != nil` evaluates to true; return nil explicitly or declare the variable as error.")
			}
		}
		return true
	})
}

// checkSubsliceRetention detects storing subslices directly in maps or long-lived state,
// which pins large backing buffers in memory and causes memory leaks.
func (v *slopInspector) checkSubsliceRetention(fn *ast.FuncDecl) {
	if fn == nil || fn.Body == nil {
		return
	}
	subsliceVars := make(map[string]bool)
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, rhs := range as.Rhs {
			if _, ok := rhs.(*ast.SliceExpr); ok && i < len(as.Lhs) {
				if id, ok := as.Lhs[i].(*ast.Ident); ok {
					subsliceVars[id.Name] = true
				}
			}
		}
		// Check assignment to map index
		if len(as.Lhs) == 1 && len(as.Rhs) == 1 {
			if _, ok := as.Lhs[0].(*ast.IndexExpr); ok {
				isSub := false
				if _, ok := as.Rhs[0].(*ast.SliceExpr); ok {
					isSub = true
				} else if id, ok := as.Rhs[0].(*ast.Ident); ok && subsliceVars[id.Name] {
					isSub = true
				}
				if isSub {
					v.addFindingPos(as.Pos(),
						"Subslice stored directly in map retains underlying allocation buffer",
						"Copy the subslice data with append([]byte(nil), sub...) or strings.Clone to prevent memory buffer pinning leaks.")
				}
			}
		}
		return true
	})
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
