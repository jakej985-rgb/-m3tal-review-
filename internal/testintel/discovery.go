package testintel

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// classifyTestKind determines the category of a test function by name and signature.
func classifyTestKind(name string) (TestKind, bool) {
	switch {
	case strings.HasPrefix(name, "Test"):
		lower := strings.ToLower(name)
		if strings.Contains(lower, "integration") || strings.Contains(lower, "e2e") {
			return TestKindIntegration, true
		}
		if strings.Contains(lower, "regression") {
			return TestKindRegression, true
		}
		return TestKindUnit, true
	case strings.HasPrefix(name, "Benchmark"):
		return TestKindBenchmark, true
	case strings.HasPrefix(name, "Fuzz"):
		return TestKindFuzz, true
	default:
		return "", false
	}
}

// parseTestFile parses a single Go test file AST and extracts test targets.
func parseTestFile(fset *token.FileSet, path string, src any) ([]TestTarget, error) {
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	pkgName := file.Name.Name
	var targets []TestTarget

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		kind, valid := classifyTestKind(fn.Name.Name)
		if !valid {
			continue
		}
		pos := fset.Position(fn.Pos())
		targets = append(targets, TestTarget{
			Package: pkgName,
			File:    path,
			Line:    pos.Line,
			Name:    fn.Name.Name,
			Kind:    kind,
		})
	}
	return targets, nil
}

// DiscoverTests scans a directory recursively for all *_test.go files and test targets.
func DiscoverTests(rootDir string) ([]TestTarget, error) {
	var targets []TestTarget
	fset := token.NewFileSet()

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), "_test.go") {
			return nil
		}
		found, parseErr := parseTestFile(fset, path, nil)
		if parseErr != nil {
			return nil
		}
		targets = append(targets, found...)
		return nil
	})
	return targets, err
}

// DiscoverTestsFromSource parses a test file directly from in-memory string content.
func DiscoverTestsFromSource(filePath, content string) ([]TestTarget, error) {
	fset := token.NewFileSet()
	return parseTestFile(fset, filePath, content)
}
