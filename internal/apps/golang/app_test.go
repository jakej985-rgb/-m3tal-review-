package golang

import (
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

func TestManifestMatchesCatalog(t *testing.T) {
	m := loadManifest()
	if len(m.Rules) != len(catalog) {
		t.Fatalf("manifest rules (%d) != catalog (%d)", len(m.Rules), len(catalog))
	}
	seen := make(map[string]bool, len(catalog))
	for _, r := range catalog {
		seen[r.ID] = true
		if !protocol.IsValidRuleID(r.ID) {
			t.Errorf("invalid rule ID %q", r.ID)
		}
	}
	for _, id := range m.Rules {
		if !seen[id] {
			t.Errorf("manifest rule %q missing from catalog", id)
		}
	}
}

func TestGolangAppImportGuard(t *testing.T) {
	allowedPkg := func(imp string) bool {
		if !strings.Contains(imp, ".") {
			return true
		}
		switch imp {
		case "github.com/jakej985-rgb/m3tal-review/protocol",
			"github.com/jakej985-rgb/m3tal-review/internal/apps/golang/bug",
			"github.com/jakej985-rgb/m3tal-review/internal/apps/golang/security",
			"github.com/jakej985-rgb/m3tal-review/internal/apps/golang/slop":
			return true
		default:
			return false
		}
	}
	for _, dir := range []string{".", "bug", "security", "slop"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("readdir %s: %v", dir, err)
		}
		fset := token.NewFileSet()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, dir+"/"+e.Name(), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s/%s: %v", dir, e.Name(), err)
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if !allowedPkg(p) {
					t.Errorf("%s/%s imports disallowed package %q", dir, e.Name(), p)
				}
			}
		}
	}
}

func TestRunDetectsBugSecurityAndSlop(t *testing.T) {
	src := `package demo

import (
	"crypto/tls"
	"database/sql"
	"net/http"
	"os/exec"
)

// foo function
func foo(db *sql.DB, u string) {
	if u == "" {
	}
	_ = &tls.Config{InsecureSkipVerify: true}
	_ = exec.Command(u)
	_, _ = db.Query("SELECT * FROM users WHERE name = " + u)
	_, _ = http.Get(u)
}
`
	out := Run(protocol.Input{
		Protocol: protocol.Version,
		Files: []protocol.File{
			{Path: "demo.go", Status: "added", Content: src},
		},
	})
	if len(out.Findings) != 6 {
		t.Fatalf("expected 6 findings, got %d: %+v", len(out.Findings), out.Findings)
	}
	sent := map[string]struct{}{"demo.go": {}}
	if err := protocol.ValidateOutput(out, "review-go", sent); err != nil {
		t.Fatalf("ValidateOutput failed: %v", err)
	}
}

func TestRunCorrectnessAndSlopDetectors(t *testing.T) {
	src := `package demo

import (
	"os"
	"sync"
)

func f(items []string, v any, ok bool) {
	var wg sync.WaitGroup
	for _, p := range items {
		fh, _ := os.Open(p)
		defer fh.Close()
	}
	go func() {
		wg.Add(1)
		wg.Done()
	}()
	_ = v.(string)
	if ok == true {
		if len(items) > 0 {
			if items[0] != "" {
				if len(items[0]) > 1 {
					_ = items[0]
				}
			}
		}
	}
}

type myErr struct{}
func (e *myErr) Error() string { return "err" }
func retTypedNil() error {
	var err *myErr
	return err
}
`
	out := Run(protocol.Input{
		Protocol: protocol.Version,
		Files: []protocol.File{
			{Path: "demo.go", Status: "added", Content: src},
		},
	})
	want := map[string]bool{
		"go/bug/defer-in-loop":              false,
		"go/bug/waitgroup-add-in-goroutine": false,
		"go/bug/unchecked-type-assert":      false,
		"go/bug/typed-nil-error":            false,
		"go/slop/redundant-bool-compare":    false,
		"go/slop/deep-nesting":              false,
	}
	for _, f := range out.Findings {
		if _, ok := want[f.Rule]; ok {
			want[f.Rule] = true
		}
	}
	for rule, seen := range want {
		if !seen {
			t.Errorf("expected finding for %s, got %+v", rule, out.Findings)
		}
	}
}

func TestRunFix(t *testing.T) {
	fixOut := Fix(protocol.FixInput{
		Protocol: protocol.Version,
		Files: []protocol.File{{
			Path:    "a.go",
			Status:  "modified",
			Content: "package a\nfunc f(ok bool) bool {\n\tif ok == true {\n\t\treturn true\n\t}\n\treturn false\n}\n",
		}},
		Findings: []protocol.Finding{{
			Rule:     "go/slop/redundant-bool-compare",
			Category: protocol.CategorySlop,
			Severity: protocol.SeverityLow,
			File:     "a.go",
			Line:     3,
			Message:  "redundant",
		}},
	})
	if len(fixOut.Patches) != 1 || fixOut.Patches[0].Replacement != "\tif ok {" {
		t.Fatalf("unexpected patches: %+v", fixOut.Patches)
	}
	if err := protocol.ValidateFixOutput(fixOut, "review-go", map[string]struct{}{"a.go": {}}); err != nil {
		t.Fatalf("ValidateFixOutput failed: %v", err)
	}
}
