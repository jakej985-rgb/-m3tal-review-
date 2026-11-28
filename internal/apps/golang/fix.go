package golang

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Fix synthesizes AST-accurate deterministic patches for supported review-go findings.
func Fix(in protocol.FixInput) protocol.FixOutput {
	m := loadManifest()
	byPath := make(map[string]string, len(in.Files))
	for _, f := range in.Files {
		byPath[f.Path] = f.Content
	}

	var patches []protocol.Patch
	for _, fnd := range in.Findings {
		src, ok := byPath[fnd.File]
		if !ok || fnd.Line < 1 {
			continue
		}
		lines := strings.Split(src, "\n")
		if fnd.Line > len(lines) {
			continue
		}

		switch fnd.Rule {
		case "go/slop/redundant-bool-compare":
			if startLine, endLine, repl, ok := fixBoolCompareAST(fnd.File, src, fnd.Line); ok {
				patches = append(patches, protocol.Patch{
					Rule:        fnd.Rule,
					File:        fnd.File,
					StartLine:   startLine,
					EndLine:     endLine,
					Replacement: repl,
					Summary:     "Remove redundant boolean literal comparison",
				})
			}
		case "go/security/tls-insecure-skip-verify":
			if repl, ok := fixInsecureSkipVerifyAST(fnd.File, src, fnd.Line); ok {
				patches = append(patches, protocol.Patch{
					Rule:        fnd.Rule,
					File:        fnd.File,
					StartLine:   fnd.Line,
					EndLine:     fnd.Line,
					Replacement: repl,
					Summary:     "Disable InsecureSkipVerify",
				})
			}
		}
	}

	return protocol.FixOutput{
		Protocol: protocol.Version,
		App:      protocol.AppInfo{Name: m.Name, Version: m.Version},
		Patches:  patches,
	}
}

func fixBoolCompareAST(filePath, src string, targetLine int) (int, int, string, bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, src, 0)
	if err != nil {
		return 0, 0, "", false
	}

	var match *ast.BinaryExpr
	var keepExpr ast.Expr
	ast.Inspect(file, func(n ast.Node) bool {
		if match != nil {
			return false
		}
		bin, ok := n.(*ast.BinaryExpr)
		if !ok || fset.Position(bin.Pos()).Line != targetLine {
			return true
		}
		if bin.Op == token.EQL {
			if isIdent(bin.Y, "true") {
				match, keepExpr = bin, bin.X
			} else if isIdent(bin.X, "true") {
				match, keepExpr = bin, bin.Y
			}
		} else if bin.Op == token.NEQ {
			if isIdent(bin.Y, "false") {
				match, keepExpr = bin, bin.X
			} else if isIdent(bin.X, "false") {
				match, keepExpr = bin, bin.Y
			}
		}
		return match == nil
	})
	if match == nil || keepExpr == nil {
		return 0, 0, "", false
	}
	return replaceNodeLines(fset, src, match, keepExpr)
}

func fixInsecureSkipVerifyAST(filePath, src string, targetLine int) (string, bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, src, 0)
	if err != nil {
		return "", false
	}

	var trueIdent *ast.Ident
	ast.Inspect(file, func(n ast.Node) bool {
		if trueIdent != nil {
			return false
		}
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			if fset.Position(node.Pos()).Line == targetLine && isIdent(node.Key, "InsecureSkipVerify") && isIdent(node.Value, "true") {
				trueIdent = node.Value.(*ast.Ident)
			}
		case *ast.AssignStmt:
			if fset.Position(node.Pos()).Line == targetLine && len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					if sel, ok := lhs.(*ast.SelectorExpr); ok && sel.Sel.Name == "InsecureSkipVerify" && isIdent(node.Rhs[i], "true") {
						trueIdent = node.Rhs[i].(*ast.Ident)
						break
					}
				}
			}
		}
		return trueIdent == nil
	})
	if trueIdent == nil {
		return "", false
	}
	start := fset.Position(trueIdent.Pos()).Offset
	end := fset.Position(trueIdent.End()).Offset
	updated := src[:start] + "false" + src[end:]
	lines := strings.Split(updated, "\n")
	if targetLine < 1 || targetLine > len(lines) {
		return "", false
	}
	return lines[targetLine-1], true
}

func replaceNodeLines(fset *token.FileSet, src string, fullNode, keepNode ast.Node) (int, int, string, bool) {
	fullStart := fset.Position(fullNode.Pos()).Offset
	fullEnd := fset.Position(fullNode.End()).Offset
	keepStart := fset.Position(keepNode.Pos()).Offset
	keepEnd := fset.Position(keepNode.End()).Offset
	if fullStart < 0 || fullEnd > len(src) || keepStart < fullStart || keepEnd > fullEnd {
		return 0, 0, "", false
	}
	origStartLine := fset.Position(fullNode.Pos()).Line
	origEndLine := fset.Position(fullNode.End()).Line
	origLines := strings.Split(src, "\n")
	updated := src[:fullStart] + src[keepStart:keepEnd] + src[fullEnd:]
	updatedLines := strings.Split(updated, "\n")
	newEndLine := origEndLine - (len(origLines) - len(updatedLines))
	if origStartLine < 1 || newEndLine < origStartLine || newEndLine > len(updatedLines) {
		return 0, 0, "", false
	}
	return origStartLine, origEndLine, strings.Join(updatedLines[origStartLine-1:newEndLine], "\n"), true
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
