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
			if repl, ok := fixBoolCompareAST(fnd.File, src, fnd.Line); ok {
				patches = append(patches, protocol.Patch{
					Rule:        fnd.Rule,
					File:        fnd.File,
					StartLine:   fnd.Line,
					EndLine:     fnd.Line,
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

func fixBoolCompareAST(filePath, src string, targetLine int) (string, bool) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filePath, src, 0)
	if err != nil {
		return "", false
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
		return "", false
	}
	return replaceNodeOnLine(fset, src, targetLine, match, keepExpr)
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

func replaceNodeOnLine(fset *token.FileSet, src string, targetLine int, fullNode, keepNode ast.Node) (string, bool) {
	fullStart := fset.Position(fullNode.Pos()).Offset
	fullEnd := fset.Position(fullNode.End()).Offset
	keepStart := fset.Position(keepNode.Pos()).Offset
	keepEnd := fset.Position(keepNode.End()).Offset
	if fullStart < 0 || fullEnd > len(src) || keepStart < fullStart || keepEnd > fullEnd {
		return "", false
	}
	updated := src[:fullStart] + src[keepStart:keepEnd] + src[fullEnd:]
	lines := strings.Split(updated, "\n")
	if targetLine < 1 || targetLine > len(lines) {
		return "", false
	}
	return lines[targetLine-1], true
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}
