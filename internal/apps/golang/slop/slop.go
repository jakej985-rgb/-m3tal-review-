package slop

import (
	"go/ast"
	"go/token"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Rules returns all Go slop detector rule metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "go/slop/restating-comment", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Comment restates the immediately following declaration"},
		{ID: "go/slop/redundant-bool-compare", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Redundant comparison to boolean literal"},
		{ID: "go/slop/deep-nesting", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Control flow nesting depth >= 4"},
		{ID: "go/slop/else-after-return", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "Unnecessary else block after return"},
		{ID: "go/slop/bool-if-return", Category: protocol.CategorySlop, Severity: protocol.SeverityLow, Summary: "if/return boolean literal can be simplified to a direct return"},
	}
}

// Analyze runs Go AST slop detectors on a single parsed file.
func Analyze(fset *token.FileSet, file *ast.File, filePath string, getLine func(int) string, lineAllowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fn.Doc != nil && len(fn.Doc.List) == 1 {
			docText := strings.TrimSpace(strings.TrimPrefix(fn.Doc.List[0].Text, "//"))
			fnName := fn.Name.Name
			if strings.EqualFold(docText, fnName+" function") || strings.EqualFold(docText, "returns "+fnName) {
				line := fset.Position(fn.Doc.Pos()).Line
				if lineAllowed(line) {
					out = append(out, protocol.Finding{
						Rule:        "go/slop/restating-comment",
						Category:    protocol.CategorySlop,
						Severity:    protocol.SeverityLow,
						Confidence:  protocol.ConfidenceHigh,
						File:        filePath,
						Line:        line,
						Message:     "Comment restates the function name without adding context",
						Evidence:    fn.Doc.List[0].Text,
						Remediation: "Explain why the function exists or what invariants it maintains, or remove the comment.",
					})
				}
			}
		}
		if fn.Body == nil {
			continue
		}
		out = append(out, checkRedundantBoolCompare(fset, fn.Body, filePath, getLine, lineAllowed)...)
		out = append(out, checkDeepNesting(fset, fn.Body, filePath, getLine, lineAllowed, 0)...)
		out = append(out, checkElseAfterReturn(fset, fn.Body, filePath, getLine, lineAllowed)...)
		out = append(out, checkBoolIfReturn(fset, fn.Body, filePath, getLine, lineAllowed)...)
	}
	return out
}

func checkRedundantBoolCompare(fset *token.FileSet, body *ast.BlockStmt, filePath string, getLine func(int) string, lineAllowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	ast.Inspect(body, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || (bin.Op != token.EQL && bin.Op != token.NEQ) {
			return true
		}
		if isBoolIdent(bin.X) || isBoolIdent(bin.Y) {
			line := fset.Position(bin.Pos()).Line
			if lineAllowed(line) {
				out = append(out, protocol.Finding{
					Rule:        "go/slop/redundant-bool-compare",
					Category:    protocol.CategorySlop,
					Severity:    protocol.SeverityLow,
					Confidence:  protocol.ConfidenceHigh,
					File:        filePath,
					Line:        line,
					Message:     "Redundant comparison to boolean literal",
					Evidence:    getLine(line),
					Remediation: "Use the boolean expression directly or negate with '!'.",
				})
			}
		}
		return true
	})
	return out
}

func isBoolIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && (id.Name == "true" || id.Name == "false")
}

func checkDeepNesting(fset *token.FileSet, stmts *ast.BlockStmt, filePath string, getLine func(int) string, lineAllowed func(int) bool, depth int) []protocol.Finding {
	if stmts == nil {
		return nil
	}
	var out []protocol.Finding
	for _, s := range stmts.List {
		switch node := s.(type) {
		case *ast.IfStmt:
			if depth+1 >= 4 {
				line := fset.Position(node.Pos()).Line
				if lineAllowed(line) {
					out = append(out, protocol.Finding{
						Rule:        "go/slop/deep-nesting",
						Category:    protocol.CategorySlop,
						Severity:    protocol.SeverityLow,
						Confidence:  protocol.ConfidenceHigh,
						File:        filePath,
						Line:        line,
						Message:     "Control flow nesting depth >= 4",
						Evidence:    getLine(line),
						Remediation: "Use early returns or extract a helper function to flatten control flow.",
					})
				}
			}
			out = append(out, checkDeepNesting(fset, node.Body, filePath, getLine, lineAllowed, depth+1)...)
			if blk, ok := node.Else.(*ast.BlockStmt); ok {
				out = append(out, checkDeepNesting(fset, blk, filePath, getLine, lineAllowed, depth+1)...)
			}
		case *ast.ForStmt:
			out = append(out, checkDeepNesting(fset, node.Body, filePath, getLine, lineAllowed, depth+1)...)
		case *ast.RangeStmt:
			out = append(out, checkDeepNesting(fset, node.Body, filePath, getLine, lineAllowed, depth+1)...)
		}
	}
	return out
}

func checkElseAfterReturn(fset *token.FileSet, body *ast.BlockStmt, filePath string, getLine func(int) string, lineAllowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	ast.Inspect(body, func(n ast.Node) bool {
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok || ifStmt.Else == nil || len(ifStmt.Body.List) == 0 {
			return true
		}
		last := ifStmt.Body.List[len(ifStmt.Body.List)-1]
		if _, isRet := last.(*ast.ReturnStmt); isRet {
			line := fset.Position(ifStmt.Else.Pos()).Line
			if lineAllowed(line) {
				out = append(out, protocol.Finding{
					Rule:        "go/slop/else-after-return",
					Category:    protocol.CategorySlop,
					Severity:    protocol.SeverityLow,
					Confidence:  protocol.ConfidenceHigh,
					File:        filePath,
					Line:        line,
					Message:     "Unnecessary else block after return",
					Evidence:    getLine(line),
					Remediation: "Remove the else keyword and unindent the fallback branch.",
				})
			}
		}
		return true
	})
	return out
}

func checkBoolIfReturn(fset *token.FileSet, body *ast.BlockStmt, filePath string, getLine func(int) string, lineAllowed func(int) bool) []protocol.Finding {
	var out []protocol.Finding
	ast.Inspect(body, func(n ast.Node) bool {
		blk, ok := n.(*ast.BlockStmt)
		if !ok || len(blk.List) < 2 {
			return true
		}
		for i := 0; i < len(blk.List)-1; i++ {
			ifStmt, ok := blk.List[i].(*ast.IfStmt)
			if !ok || ifStmt.Else != nil || len(ifStmt.Body.List) != 1 {
				continue
			}
			r1, ok1 := ifStmt.Body.List[0].(*ast.ReturnStmt)
			r2, ok2 := blk.List[i+1].(*ast.ReturnStmt)
			if !ok1 || !ok2 || len(r1.Results) != 1 || len(r2.Results) != 1 {
				continue
			}
			if isBoolIdent(r1.Results[0]) && isBoolIdent(r2.Results[0]) {
				line := fset.Position(ifStmt.Pos()).Line
				if lineAllowed(line) {
					out = append(out, protocol.Finding{
						Rule:        "go/slop/bool-if-return",
						Category:    protocol.CategorySlop,
						Severity:    protocol.SeverityLow,
						Confidence:  protocol.ConfidenceHigh,
						File:        filePath,
						Line:        line,
						Message:     "if/return boolean literal can be simplified to a direct return",
						Evidence:    getLine(line),
						Remediation: "Return the boolean condition directly.",
					})
				}
			}
		}
		return true
	})
	return out
}
