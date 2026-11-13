// Package golang implements the Go frontend for the semantic program
// model: it loads a Go repository with go/packages, builds SSA with
// golang.org/x/tools/go/ssa, and converts the result into the
// engine-neutral semantic.Program model.
//
// The frontend is Go-first but the produced model contains no
// Go-specific types except where documented (File.AST,
// Package.TypesInfo), so downstream analyzers stay language-agnostic.
package golang

import (
	"context"
	"fmt"
	"go/token"
	"path/filepath"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// CallGraphMode selects how call sites are resolved to callee
// functions.
type CallGraphMode int

const (
	// CallGraphDefault uses class-hierarchy analysis: direct calls are
	// resolved exactly and interface/virtual calls get a may-set of
	// concrete implementations.
	CallGraphDefault CallGraphMode = iota
	// CallGraphCHA is an explicit alias for CallGraphDefault.
	CallGraphCHA
	// CallGraphStatic resolves only statically-known callees; dynamic
	// call sites get an empty callee set and Dynamic=true.
	CallGraphStatic
	// CallGraphNone performs no call resolution beyond recording call
	// sites.
	CallGraphNone
)

// Options controls a Go frontend load.
type Options struct {
	// Dir is the directory containing the Go module or package to
	// analyze. Empty means the current directory.
	Dir string
	// Pattern is the go/packages pattern selecting root packages.
	// Empty means "./..." (all packages under Dir).
	Pattern string
	// Tests includes test variants of packages (the "pkg [pkg.test]"
	// synthetic packages) in the load.
	Tests bool
	// BuildFlags are passed through to the go list driver (e.g.
	// "-tags=foo").
	BuildFlags []string
	// CallGraph selects call resolution. Zero value is CallGraphDefault
	// (CHA).
	CallGraph CallGraphMode
	// MaxPackages bounds the number of root packages modeled. Zero
	// means the default (256); negative means unlimited.
	MaxPackages int
	// MaxDiagnostics bounds recorded diagnostics. Zero means the
	// default (2048); negative means unlimited.
	MaxDiagnostics int
}

const (
	defaultMaxPackages    = 256
	defaultMaxDiagnostics = 2048
)

// Load analyzes the Go packages selected by opts and returns a
// deterministic semantic.Program. Load failures, type errors, and
// analysis limitations are reported as Program.Diagnostics; a non-nil
// error is returned only when the load itself cannot proceed (e.g. the
// go list driver fails outright).
func Load(ctx context.Context, opts Options) (*semantic.Program, error) {
	dir := opts.Dir
	if dir == "" {
		dir = "."
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	pattern := opts.Pattern
	if pattern == "" {
		pattern = "./..."
	}
	maxPkgs := opts.MaxPackages
	if maxPkgs == 0 {
		maxPkgs = defaultMaxPackages
	}
	maxDiags := opts.MaxDiagnostics
	if maxDiags == 0 {
		maxDiags = defaultMaxDiagnostics
	}

	roots, diags, err := loadPackages(ctx, dir, pattern, opts)
	if err != nil {
		return nil, err
	}

	prog := &semantic.Program{
		RootDir:     dir,
		Diagnostics: diags,
	}

	if maxPkgs >= 0 && len(roots) > maxPkgs {
		roots = roots[:maxPkgs]
		prog.Diagnostics = append(prog.Diagnostics, semantic.Diagnostic{
			Severity: semantic.SeverityWarning,
			Category: semantic.DiagLimit,
			Message:  fmt.Sprintf("package count exceeds MaxPackages=%d; remaining packages were not analyzed", maxPkgs),
		})
	}

	// Build SSA for the load set. Bodies are constructed only for root
	// packages; dependencies contribute signatures and types.
	ssaProg, ssaPkgs := ssautil.Packages(roots, ssa.InstantiateGenerics)
	ssaProg.Build()
	ssaIndex := make(map[*packages.Package]*ssa.Package, len(roots))
	var fset *token.FileSet
	for i, p := range roots {
		ssaIndex[p] = ssaPkgs[i]
		if fset == nil {
			fset = p.Fset
		}
	}

	conv := newConverter(prog, ssaProg, ssaIndex, fset, opts.CallGraph)
	// Register all root packages before populating any of them so that
	// cross-package references resolve to modeled packages.
	for _, p := range roots {
		conv.registerPackage(p)
	}
	for _, p := range roots {
		conv.populatePackage(p, conv.packageForRoot(p))
	}
	conv.finish()

	prog.Sort()
	prog.Diagnostics = truncateDiagnostics(prog.Diagnostics, maxDiags)
	prog.Index()
	return prog, nil
}

// truncateDiagnostics caps the diagnostic list, recording the truncation
// itself as a final diagnostic.
func truncateDiagnostics(diags []semantic.Diagnostic, max int) []semantic.Diagnostic {
	if max < 0 || len(diags) <= max {
		return diags
	}
	truncated := diags[:max]
	return append(truncated, semantic.Diagnostic{
		Severity: semantic.SeverityWarning,
		Category: semantic.DiagLimit,
		Message:  fmt.Sprintf("diagnostic count exceeds MaxDiagnostics=%d; %d diagnostics were dropped", max, len(diags)-max),
	})
}
