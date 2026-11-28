package bug

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Rules returns all Go bug detector rule metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "go/bug/empty-branch", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "Empty if/else branch likely indicates incomplete logic"},
		{ID: "go/bug/defer-in-loop", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "defer inside loop delays cleanup until function returns"},
		{ID: "go/bug/waitgroup-add-in-goroutine", Category: protocol.CategoryBug, Severity: protocol.SeverityHigh, Summary: "WaitGroup.Add called inside goroutine races with Wait()"},
		{ID: "go/bug/unchecked-type-assert", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "Type assertion without comma-ok check can panic at runtime"},
		{ID: "go/bug/typed-nil-error", Category: protocol.CategoryBug, Severity: protocol.SeverityHigh, Summary: "Returning a typed nil pointer as error produces a non-nil interface"},
		{ID: "go/bug/vet-diagnostic", Category: protocol.CategoryBug, Severity: protocol.SeverityMedium, Summary: "Diagnostic reported by go vet"},
	}
}

// Analyze runs Go AST bug detectors on a single parsed file.
func Analyze(fset *token.FileSet, file *ast.File, filePath string, getLine func(int) string, lineAllowed func(int) bool, isTestFile bool) []protocol.Finding {
	if isTestFile {
		return nil
	}
	var out []protocol.Finding
	ast.Inspect(file, func(n ast.Node) bool {
		if ifStmt, ok := n.(*ast.IfStmt); ok && len(ifStmt.Body.List) == 0 {
			line := fset.Position(ifStmt.Pos()).Line
			if lineAllowed(line) {
				out = append(out, protocol.Finding{
					Rule:        "go/bug/empty-branch",
					Category:    protocol.CategoryBug,
					Severity:    protocol.SeverityMedium,
					Confidence:  protocol.ConfidenceHigh,
					File:        filePath,
					Line:        line,
					Message:     "Empty if branch",
					Evidence:    getLine(line),
					Remediation: "Implement the branch or remove the redundant condition.",
				})
			}
		}
		return true
	})

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		out = append(out, checkDeferInLoop(fset, fn.Body, filePath, getLine, lineAllowed)...)
		out = append(out, checkWaitGroupInGo(fset, fn.Body, filePath, getLine, lineAllowed)...)
		out = append(out, checkUncheckedTypeAssert(fset, fn.Body, filePath, getLine, lineAllowed)...)
		out = append(out, checkTypedNilError(fset, fn, filePath, getLine, lineAllowed)...)
	}
	return out
}

func checkDeferInLoop(fset *token.FileSet, body *ast.BlockStmt, filePath string, getLine func(int) string, lineAllowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	inspectLoop := func(loopBody *ast.BlockStmt, msg string) {
		ast.Inspect(loopBody, func(c ast.Node) bool {
			if _, isLit := c.(*ast.FuncLit); isLit {
				return false
			}
			if def, ok := c.(*ast.DeferStmt); ok {
				line := fset.Position(def.Pos()).Line
				if lineAllowed(line) {
					out = append(out, protocol.Finding{
						Rule:        "go/bug/defer-in-loop",
						Category:    protocol.CategoryBug,
						Severity:    protocol.SeverityMedium,
						Confidence:  protocol.ConfidenceHigh,
						File:        filePath,
						Line:        line,
						Message:     msg,
						Evidence:    getLine(line),
						Remediation: "Move the deferred cleanup into a helper function called per iteration.",
					})
				}
			}
			return true
		})
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ForStmt:
			inspectLoop(node.Body, "defer inside loop delays execution until enclosing function returns")
			return false
		case *ast.RangeStmt:
			inspectLoop(node.Body, "defer inside range loop delays execution until enclosing function returns")
			return false
		}
		return true
	})
	return out
}

func checkWaitGroupInGo(fset *token.FileSet, body *ast.BlockStmt, filePath string, getLine func(int) string, lineAllowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	ast.Inspect(body, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		ast.Inspect(goStmt.Call, func(c ast.Node) bool {
			call, ok := c.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Add" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && (id.Name == "wg" || id.Name == "group") {
				line := fset.Position(call.Pos()).Line
				if lineAllowed(line) {
					out = append(out, protocol.Finding{
						Rule:        "go/bug/waitgroup-add-in-goroutine",
						Category:    protocol.CategoryBug,
						Severity:    protocol.SeverityHigh,
						Confidence:  protocol.ConfidenceMedium,
						File:        filePath,
						Line:        line,
						Message:     "WaitGroup.Add called inside goroutine races with Wait()",
						Evidence:    getLine(line),
						Remediation: "Call wg.Add(1) before spawning the goroutine.",
					})
				}
			}
			return true
		})
		return true
	})
	return out
}

func checkUncheckedTypeAssert(fset *token.FileSet, body *ast.BlockStmt, filePath string, getLine func(int) string, lineAllowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.TypeSwitchStmt:
			return false
		case *ast.AssignStmt:
			if len(node.Lhs) == 2 && len(node.Rhs) == 1 {
				if _, ok := node.Rhs[0].(*ast.TypeAssertExpr); ok {
					return false
				}
			}
		case *ast.TypeAssertExpr:
			if node.Type == nil {
				return true
			}
			line := fset.Position(node.Pos()).Line
			if lineAllowed(line) {
				out = append(out, protocol.Finding{
					Rule:        "go/bug/unchecked-type-assert",
					Category:    protocol.CategoryBug,
					Severity:    protocol.SeverityMedium,
					Confidence:  protocol.ConfidenceHigh,
					File:        filePath,
					Line:        line,
					Message:     "Type assertion without comma-ok check can panic at runtime",
					Evidence:    getLine(line),
					Remediation: "Use v, ok := x.(T) and handle !ok.",
				})
			}
		}
		return true
	})
	return out
}

func checkTypedNilError(fset *token.FileSet, fn *ast.FuncDecl, filePath string, getLine func(int) string, lineAllowed func(int) bool) []protocol.Finding {
	if fn.Type == nil || fn.Type.Results == nil || len(fn.Type.Results.List) == 0 {
		return nil
	}
	errIdx := -1
	pos := 0
	for _, field := range fn.Type.Results.List {
		count := len(field.Names)
		if count == 0 {
			count = 1
		}
		if id, ok := field.Type.(*ast.Ident); ok && id.Name == "error" {
			errIdx = pos + count - 1
		}
		pos += count
	}
	if errIdx < 0 {
		return nil
	}

	typedNilVars := make(map[string]bool)
	pointerVars := make(map[string]bool)
	var out []protocol.Finding
	walkTypedNilStmts(fset, fn.Body.List, typedNilVars, pointerVars, errIdx, filePath, getLine, lineAllowed, &out)
	return out
}

func cloneStringBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func clearAssignedInNode(n ast.Node, vars map[string]bool) {
	if n == nil || len(vars) == 0 {
		return
	}
	ast.Inspect(n, func(node ast.Node) bool {
		switch stmt := node.(type) {
		case *ast.FuncLit:
			return false
		case *ast.AssignStmt:
			for _, lhs := range stmt.Lhs {
				if id, ok := lhs.(*ast.Ident); ok {
					delete(vars, id.Name)
				}
			}
		case *ast.UnaryExpr:
			if stmt.Op == token.AND {
				if id, ok := stmt.X.(*ast.Ident); ok {
					delete(vars, id.Name)
				}
			}
		}
		return true
	})
}

func walkTypedNilStmts(
	fset *token.FileSet,
	stmts []ast.Stmt,
	typedNilVars map[string]bool,
	pointerVars map[string]bool,
	errIdx int,
	filePath string,
	getLine func(int) string,
	lineAllowed func(int) bool,
	out *[]protocol.Finding,
) {
	for _, stmt := range stmts {
		switch s := stmt.(type) {
		case *ast.DeclStmt:
			gd, ok := s.Decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if _, isStar := vs.Type.(*ast.StarExpr); isStar {
					for _, name := range vs.Names {
						pointerVars[name.Name] = true
						if len(vs.Values) == 0 {
							typedNilVars[name.Name] = true
						} else {
							delete(typedNilVars, name.Name)
						}
					}
					continue
				}
				for _, name := range vs.Names {
					delete(typedNilVars, name.Name)
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range s.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue
				}
				isTypedNil := false
				if i < len(s.Rhs) {
					if call, ok := s.Rhs[i].(*ast.CallExpr); ok && len(call.Args) == 1 {
						if arg, ok := call.Args[0].(*ast.Ident); ok && arg.Name == "nil" {
							if _, isParen := call.Fun.(*ast.ParenExpr); isParen {
								pointerVars[id.Name] = true
								isTypedNil = true
							}
						}
					} else if rhsID, ok := s.Rhs[i].(*ast.Ident); ok && rhsID.Name == "nil" && pointerVars[id.Name] {
						isTypedNil = true
					}
				}
				if isTypedNil {
					typedNilVars[id.Name] = true
				} else {
					delete(typedNilVars, id.Name)
				}
			}
			for _, rhs := range s.Rhs {
				clearAssignedInNode(rhs, typedNilVars)
			}
		case *ast.ExprStmt:
			clearAssignedInNode(s.X, typedNilVars)
		case *ast.ReturnStmt:
			if errIdx < len(s.Results) {
				if id, ok := s.Results[errIdx].(*ast.Ident); ok && typedNilVars[id.Name] {
					line := fset.Position(s.Pos()).Line
					if lineAllowed(line) {
						*out = append(*out, protocol.Finding{
							Rule:        "go/bug/typed-nil-error",
							Category:    protocol.CategoryBug,
							Severity:    protocol.SeverityHigh,
							Confidence:  protocol.ConfidenceMedium,
							File:        filePath,
							Line:        line,
							Message:     "Returning typed nil pointer " + id.Name + " as error produces a non-nil error interface",
							Evidence:    getLine(line),
							Remediation: "Return untyped nil when there is no error.",
						})
					}
				}
			}
		case *ast.BlockStmt:
			walkTypedNilStmts(fset, s.List, typedNilVars, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
		case *ast.IfStmt:
			if s.Init != nil {
				walkTypedNilStmts(fset, []ast.Stmt{s.Init}, typedNilVars, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
			}
			clearAssignedInNode(s.Cond, typedNilVars)
			incoming := cloneStringBoolMap(typedNilVars)
			if s.Body != nil {
				walkTypedNilStmts(fset, s.Body.List, cloneStringBoolMap(incoming), pointerVars, errIdx, filePath, getLine, lineAllowed, out)
				clearAssignedInNode(s.Body, typedNilVars)
			}
			if s.Else != nil {
				walkTypedNilStmts(fset, []ast.Stmt{s.Else}, cloneStringBoolMap(incoming), pointerVars, errIdx, filePath, getLine, lineAllowed, out)
				clearAssignedInNode(s.Else, typedNilVars)
			}
		case *ast.ForStmt:
			if s.Init != nil {
				walkTypedNilStmts(fset, []ast.Stmt{s.Init}, typedNilVars, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
			}
			clearAssignedInNode(s.Body, typedNilVars)
			if s.Body != nil {
				branch := cloneStringBoolMap(typedNilVars)
				walkTypedNilStmts(fset, s.Body.List, branch, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
			}
		case *ast.RangeStmt:
			clearAssignedInNode(s.Body, typedNilVars)
			if s.Body != nil {
				branch := cloneStringBoolMap(typedNilVars)
				walkTypedNilStmts(fset, s.Body.List, branch, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
			}
		case *ast.SwitchStmt:
			if s.Init != nil {
				walkTypedNilStmts(fset, []ast.Stmt{s.Init}, typedNilVars, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
			}
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CaseClause); ok {
						branch := cloneStringBoolMap(typedNilVars)
						walkTypedNilStmts(fset, cc.Body, branch, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
					}
				}
				clearAssignedInNode(s.Body, typedNilVars)
			}
		case *ast.TypeSwitchStmt:
			if s.Init != nil {
				walkTypedNilStmts(fset, []ast.Stmt{s.Init}, typedNilVars, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
			}
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CaseClause); ok {
						branch := cloneStringBoolMap(typedNilVars)
						walkTypedNilStmts(fset, cc.Body, branch, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
					}
				}
				clearAssignedInNode(s.Body, typedNilVars)
			}
		case *ast.SelectStmt:
			if s.Body != nil {
				for _, clause := range s.Body.List {
					if cc, ok := clause.(*ast.CommClause); ok {
						branch := cloneStringBoolMap(typedNilVars)
						walkTypedNilStmts(fset, cc.Body, branch, pointerVars, errIdx, filePath, getLine, lineAllowed, out)
					}
				}
				clearAssignedInNode(s.Body, typedNilVars)
			}
		}
	}
}

type vetEntry struct {
	Posn    string `json:"posn"`
	Message string `json:"message"`
}

// RunVet executes `go vet -json ./...` when a worktree with go.mod is available.
func RunVet(root string, files []protocol.File) ([]protocol.Finding, []protocol.Diagnostic) {
	if root == "" || root == "." {
		return nil, nil
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return nil, nil
	}
	if _, err := exec.LookPath("go"); err != nil {
		return nil, []protocol.Diagnostic{{
			Level:   "warning",
			Message: "go binary not found; skipping go vet diagnostics",
		}}
	}

	sent := make(map[string]map[int]struct{}, len(files))
	for _, f := range files {
		if f.Status == "deleted" {
			continue
		}
		if len(f.AddedLines) == 0 {
			sent[f.Path] = nil
		} else {
			s := make(map[int]struct{}, len(f.AddedLines))
			for _, l := range f.AddedLines {
				s[l] = struct{}{}
			}
			sent[f.Path] = s
		}
	}
	if len(sent) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "vet", "-json", "./...")
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	var diags []protocol.Diagnostic
	if ctx.Err() != nil {
		diags = append(diags, protocol.Diagnostic{
			Level:   "error",
			Message: "go vet timed out: " + ctx.Err().Error(),
		})
	}

	// `go vet -json` writes its JSON stream (preceded by `# pkg` header lines) to stderr;
	// fall back to stdout if stderr is empty.
	rawPayload := bytes.TrimSpace(stderr.Bytes())
	if len(rawPayload) == 0 {
		rawPayload = bytes.TrimSpace(stdout.Bytes())
	}
	var jsonBuf bytes.Buffer
	for _, line := range bytes.Split(rawPayload, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 || trimmed[0] == '#' {
			continue
		}
		jsonBuf.Write(line)
		jsonBuf.WriteByte('\n')
	}
	jsonPayload := bytes.TrimSpace(jsonBuf.Bytes())

	var findings []protocol.Finding
	decodedAny := false
	if len(jsonPayload) > 0 {
		dec := json.NewDecoder(bytes.NewReader(jsonPayload))
		for dec.More() {
			var pkgMap map[string]map[string][]vetEntry
			if err := dec.Decode(&pkgMap); err != nil {
				if runErr == nil || decodedAny {
					diags = append(diags, protocol.Diagnostic{
						Level:   "error",
						Message: "failed to decode go vet JSON output: " + err.Error(),
					})
				}
				break
			}
			decodedAny = true
			for _, analyzerMap := range pkgMap {
				for analyzer, entries := range analyzerMap {
					for _, e := range entries {
						file, line := parseVetPosn(root, e.Posn)
						added, ok := sent[file]
						if !ok {
							continue
						}
						if added != nil {
							if _, ok := added[line]; !ok {
								continue
							}
						}
						findings = append(findings, protocol.Finding{
							Rule:       "go/bug/vet-diagnostic",
							Category:   protocol.CategoryBug,
							Severity:   protocol.SeverityMedium,
							Confidence: protocol.ConfidenceHigh,
							File:       file,
							Line:       line,
							Message:    "go vet (" + analyzer + "): " + e.Message,
							Evidence:   e.Posn,
						})
					}
				}
			}
		}
	}
	if runErr != nil && !decodedAny && ctx.Err() == nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = runErr.Error()
		}
		diags = append(diags, protocol.Diagnostic{
			Level:   "error",
			Message: "go vet failed: " + msg,
		})
	}
	return findings, diags
}

func parseVetPosn(root, posn string) (string, int) {
	parts := strings.Split(posn, ":")
	if len(parts) < 2 {
		return "", 0
	}
	filePart := parts[0]
	lineStr := parts[1]
	if len(parts[0]) == 1 && len(parts) >= 4 {
		filePart = parts[0] + ":" + parts[1]
		lineStr = parts[2]
	}
	line := 0
	for _, ch := range lineStr {
		if ch < '0' || ch > '9' {
			break
		}
		line = line*10 + int(ch-'0')
	}
	rel, err := filepath.Rel(root, filePart)
	if err != nil {
		return "", 0
	}
	return filepath.ToSlash(rel), line
}
