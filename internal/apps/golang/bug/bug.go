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
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			if _, isStar := node.Type.(*ast.StarExpr); isStar && len(node.Values) == 0 {
				for _, name := range node.Names {
					typedNilVars[name.Name] = true
				}
			}
		case *ast.AssignStmt:
			for i, rhs := range node.Rhs {
				if i >= len(node.Lhs) {
					continue
				}
				lhs, ok := node.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				if call, ok := rhs.(*ast.CallExpr); ok && len(call.Args) == 1 {
					if arg, ok := call.Args[0].(*ast.Ident); ok && arg.Name == "nil" {
						if _, isParen := call.Fun.(*ast.ParenExpr); isParen {
							typedNilVars[lhs.Name] = true
						}
					}
				}
			}
		}
		return true
	})
	if len(typedNilVars) == 0 {
		return nil
	}

	var out []protocol.Finding
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		ret, ok := n.(*ast.ReturnStmt)
		if !ok || errIdx >= len(ret.Results) {
			return true
		}
		if id, ok := ret.Results[errIdx].(*ast.Ident); ok && typedNilVars[id.Name] {
			line := fset.Position(ret.Pos()).Line
			if lineAllowed(line) {
				out = append(out, protocol.Finding{
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
		return true
	})
	return out
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

	var findings []protocol.Finding
	decodedAny := false
	dec := json.NewDecoder(&stdout)
	for dec.More() {
		var pkgMap map[string]map[string][]vetEntry
		if err := dec.Decode(&pkgMap); err != nil {
			diags = append(diags, protocol.Diagnostic{
				Level:   "error",
				Message: "failed to decode go vet JSON output: " + err.Error(),
			})
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
