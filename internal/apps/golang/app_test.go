package golang

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
			Content: "package a\nfunc f(ok bool) bool {\n\tif ok == true { println(\"x == true\") }\n\treturn false\n}\n",
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
	want := "\tif ok { println(\"x == true\") }"
	if len(fixOut.Patches) != 1 || fixOut.Patches[0].Replacement != want {
		t.Fatalf("expected %q, got %+v", want, fixOut.Patches)
	}
	if err := protocol.ValidateFixOutput(fixOut, "review-go", map[string]struct{}{"a.go": {}}); err != nil {
		t.Fatalf("ValidateFixOutput failed: %v", err)
	}
}

func TestRunFixMultilineBoolCompare(t *testing.T) {
	src := "package a\nfunc f(ok bool) {\n\tif ok ==\n\t\ttrue {\n\t\tprintln(\"hi\")\n\t}\n}\n"
	fixOut := Fix(protocol.FixInput{
		Protocol: protocol.Version,
		Files: []protocol.File{{
			Path:    "a.go",
			Status:  "modified",
			Content: src,
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
	if len(fixOut.Patches) != 1 {
		t.Fatalf("expected 1 patch, got %+v", fixOut.Patches)
	}
	p := fixOut.Patches[0]
	if p.StartLine != 3 || p.EndLine != 4 || p.Replacement != "\tif ok {" {
		t.Fatalf("unexpected multiline patch: %+v", p)
	}
}

func TestBoolIfReturnRemediationVariants(t *testing.T) {
	src := `package a

func inverted(c bool) bool {
	if c {
		return false
	}
	return true
}

func constant(c bool) bool {
	if c {
		return true
	}
	return true
}
`
	out := Run(protocol.Input{
		Protocol: protocol.Version,
		Files:    []protocol.File{{Path: "a.go", Status: "added", Content: src}},
	})
	var sawInverted, sawConstant bool
	for _, f := range out.Findings {
		if f.Rule != "go/slop/bool-if-return" {
			continue
		}
		if f.Line == 4 && strings.Contains(f.Remediation, "!cond") {
			sawInverted = true
		}
		if f.Line == 11 && strings.Contains(f.Remediation, "Both branches return true") {
			sawConstant = true
		}
	}
	if !sawInverted || !sawConstant {
		t.Fatalf("expected inverted and constant remediations, got %+v", out.Findings)
	}
}

func TestTypedNilErrorTracksAssignments(t *testing.T) {
	src := `package a

type MyErr struct{}
func (*MyErr) Error() string { return "e" }

func validAssigned() error {
	var e *MyErr
	e = &MyErr{}
	return e
}

func validConditional(bad bool) error {
	var e *MyErr
	if bad {
		e = &MyErr{}
	}
	return e
}

func buggyNil() error {
	var e *MyErr
	return e
}

func nilReset() error {
	var e *MyErr
	e = &MyErr{}
	e = nil
	return e
}

func elseBranchBuggy(bad bool) error {
	var e *MyErr
	if bad {
		e = &MyErr{}
	} else {
		return e
	}
	return nil
}

func shadowedPointerInBlock() error {
	var e error
	{
		var e *MyErr
		_ = e
	}
	e = nil
	return e
}

func mixedShortDeclExistingPtr() error {
	var e *MyErr
	e, n := e, 1
	_ = n
	e = nil
	return e
}

func interfaceAssignedPointerThenNil() error {
	var e error
	var p *MyErr
	e = p
	e = nil
	return e
}

func inferredPointerVarNilReset() error {
	var e = &MyErr{}
	var p *MyErr
	e = p
	e = nil
	return e
}

func nilInterfaceCast() error {
	var e = (error)(nil)
	return e
}

func doubleParenNilPtr() error {
	var e = ((*MyErr))(nil)
	return e
}
`
	out := Run(protocol.Input{
		Protocol: protocol.Version,
		Files:    []protocol.File{{Path: "a.go", Status: "added", Content: src}},
	})
	var lines []int
	for _, f := range out.Findings {
		if f.Rule == "go/bug/typed-nil-error" {
			lines = append(lines, f.Line)
		}
	}
	if len(lines) != 6 || lines[0] != 22 || lines[1] != 29 || lines[2] != 37 || lines[3] != 57 || lines[4] != 73 || lines[5] != 83 {
		t.Fatalf("expected typed-nil-error on lines [22 29 37 57 73 83], got lines %v (%+v)", lines, out.Findings)
	}
}

func TestRunVetDecodesStderr(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/vettest\n\ngo 1.21\n"), 0644); err != nil {
		t.Fatal(err)
	}
	mainSrc := "package main\n\nimport \"fmt\"\n\nfunc main() {\n\t_ = fmt.Sprintf(\"%d\", \"not-an-int\")\n}\n"
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte(mainSrc), 0644); err != nil {
		t.Fatal(err)
	}
	out := Run(protocol.Input{
		Protocol: protocol.Version,
		Run:      protocol.RunInfo{Root: root, Mode: "audit"},
		Files:    []protocol.File{{Path: "main.go", Status: "modified", Content: mainSrc}},
	})
	var found bool
	for _, f := range out.Findings {
		if f.Rule == "go/bug/vet-diagnostic" && f.File == "main.go" && f.Line == 6 {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected go/bug/vet-diagnostic from stderr, got findings=%+v diags=%+v", out.Findings, out.Diagnostics)
	}
}
