package apps

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchitectureImportGuards(t *testing.T) {
	checkPkgImports(t, "../../protocol", func(imp string) bool {
		return !strings.Contains(imp, ".") // stdlib only
	})
	checkPkgImports(t, ".", func(imp string) bool {
		if !strings.Contains(imp, ".") {
			return true // stdlib
		}
		return imp == "github.com/jakej985-rgb/m3tal-review/protocol"
	})
}

func checkPkgImports(t *testing.T, dir string, allowed func(string) bool) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		full := filepath.Join(dir, e.Name())
		f, err := parser.ParseFile(fset, full, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", full, err)
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if !allowed(p) {
				t.Errorf("%s imports disallowed package %q", full, p)
			}
		}
	}
}

func TestNoExtensionLiteralsInAppsOrchestrator(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	forbidden := []string{`".go"`, `".ts"`, `".tsx"`, `".js"`, `".py"`, `".rs"`}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		data, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := string(data)
		for _, lit := range forbidden {
			if strings.Contains(src, lit) {
				t.Errorf("%s contains hard-coded extension literal %s", e.Name(), lit)
			}
		}
	}
}
