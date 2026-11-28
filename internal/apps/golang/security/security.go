package security

import (
	"go/ast"
	"go/token"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Rules returns all Go security detector rule metadata.
func Rules() []protocol.RuleInfo {
	return []protocol.RuleInfo{
		{ID: "go/security/tls-insecure-skip-verify", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "TLS InsecureSkipVerify disables certificate verification"},
		{ID: "go/security/exec-command-var", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "exec.Command called with non-literal command or shell"},
		{ID: "go/security/sql-string-concat", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "SQL query built with string concatenation"},
		{ID: "go/security/ssrf-unvalidated-url", Category: protocol.CategorySecurity, Severity: protocol.SeverityHigh, Summary: "Outbound HTTP request with non-constant URL"},
	}
}

// Analyze runs Go AST security detectors on a single parsed file.
func Analyze(fset *token.FileSet, file *ast.File, filePath string, getLine func(int) string, lineAllowed func(int) bool, isTestFile bool) []protocol.Finding {
	if isTestFile {
		return nil
	}
	var out []protocol.Finding
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.KeyValueExpr:
			if ident, ok := node.Key.(*ast.Ident); ok && ident.Name == "InsecureSkipVerify" {
				if val, ok := node.Value.(*ast.Ident); ok && val.Name == "true" {
					line := fset.Position(node.Pos()).Line
					if lineAllowed(line) {
						out = append(out, protocol.Finding{
							Rule:        "go/security/tls-insecure-skip-verify",
							Category:    protocol.CategorySecurity,
							Severity:    protocol.SeverityHigh,
							Confidence:  protocol.ConfidenceHigh,
							File:        filePath,
							Line:        line,
							Message:     "TLS InsecureSkipVerify set to true",
							Evidence:    getLine(line),
							Remediation: "Remove InsecureSkipVerify: true or configure proper RootCAs.",
						})
					}
				}
			}
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for idx, lhs := range node.Lhs {
					sel, ok := lhs.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != "InsecureSkipVerify" {
						continue
					}
					if val, ok := node.Rhs[idx].(*ast.Ident); ok && val.Name == "true" {
						line := fset.Position(node.Pos()).Line
						if lineAllowed(line) {
							out = append(out, protocol.Finding{
								Rule:        "go/security/tls-insecure-skip-verify",
								Category:    protocol.CategorySecurity,
								Severity:    protocol.SeverityHigh,
								Confidence:  protocol.ConfidenceHigh,
								File:        filePath,
								Line:        line,
								Message:     "TLS InsecureSkipVerify assigned true",
								Evidence:    getLine(line),
								Remediation: "Remove InsecureSkipVerify = true or configure proper RootCAs.",
							})
						}
					}
				}
			}
		case *ast.CallExpr:
			line := fset.Position(node.Pos()).Line
			if !lineAllowed(line) {
				return true
			}
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					if pkg.Name == "exec" && (sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext") {
						argIdx := 0
						if sel.Sel.Name == "CommandContext" {
							argIdx = 1
						}
						if len(node.Args) > argIdx && !isStringLit(node.Args[argIdx]) {
							out = append(out, protocol.Finding{
								Rule:        "go/security/exec-command-var",
								Category:    protocol.CategorySecurity,
								Severity:    protocol.SeverityHigh,
								Confidence:  protocol.ConfidenceMedium,
								File:        filePath,
								Line:        line,
								Message:     "exec.Command invoked with non-literal command",
								Evidence:    getLine(line),
								Remediation: "Use a fixed executable path and pass arguments separately.",
							})
						}
					}
					if pkg.Name == "http" {
						urlIdx := -1
						switch sel.Sel.Name {
						case "Get", "Post", "Head":
							urlIdx = 0
						case "NewRequest":
							urlIdx = 1
						case "NewRequestWithContext":
							urlIdx = 2
						}
						if urlIdx >= 0 && len(node.Args) > urlIdx && !isStringLit(node.Args[urlIdx]) {
							out = append(out, protocol.Finding{
								Rule:        "go/security/ssrf-unvalidated-url",
								Category:    protocol.CategorySecurity,
								Severity:    protocol.SeverityHigh,
								Confidence:  protocol.ConfidenceMedium,
								File:        filePath,
								Line:        line,
								Message:     "http." + sel.Sel.Name + " called with non-constant URL",
								Evidence:    getLine(line),
								Remediation: "Validate the URL host/scheme against an allowlist before making the request.",
							})
						}
					}
				}
				sqlArgIdx := -1
				switch sel.Sel.Name {
				case "Query", "QueryRow", "Exec":
					sqlArgIdx = 0
				case "QueryContext", "QueryRowContext", "ExecContext":
					sqlArgIdx = 1
				}
				if sqlArgIdx >= 0 && len(node.Args) > sqlArgIdx {
					if bin, ok := node.Args[sqlArgIdx].(*ast.BinaryExpr); ok && bin.Op == token.ADD {
						out = append(out, protocol.Finding{
							Rule:        "go/security/sql-string-concat",
							Category:    protocol.CategorySecurity,
							Severity:    protocol.SeverityHigh,
							Confidence:  protocol.ConfidenceHigh,
							File:        filePath,
							Line:        line,
							Message:     "SQL query constructed with string concatenation",
							Evidence:    getLine(line),
							Remediation: "Use parameterized queries ($1, ?) instead of string concatenation.",
						})
					}
				}
			}
		}
		return true
	})
	return out
}

func isStringLit(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.STRING
}
