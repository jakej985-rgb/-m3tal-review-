package golang

import (
	"context"
	"fmt"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
	"golang.org/x/tools/go/packages"
)

// loadMode requests everything needed to build SSA: syntax, type
// information, export data for dependencies, and module metadata.
const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedExportFile |
	packages.NeedTypes |
	packages.NeedTypesSizes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedModule

// loadPackages runs the go list driver and returns the root packages
// sorted by import path, plus diagnostics for every package error the
// driver reported.
func loadPackages(ctx context.Context, dir, pattern string, opts Options) ([]*packages.Package, []semantic.Diagnostic, error) {
	cfg := &packages.Config{
		Mode:       loadMode,
		Context:    ctx,
		Dir:        dir,
		Tests:      opts.Tests,
		BuildFlags: opts.BuildFlags,
	}
	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, nil, fmt.Errorf("go/packages load %q in %s: %w", pattern, dir, err)
	}

	var diags []semantic.Diagnostic
	for _, p := range pkgs {
		diags = append(diags, packageDiagnostics(p)...)
	}
	if len(pkgs) == 0 {
		diags = append(diags, semantic.Diagnostic{
			Severity: semantic.SeverityWarning,
			Category: semantic.DiagNote,
			Message:  fmt.Sprintf("pattern %q matched no packages", pattern),
		})
	}

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PkgPath < pkgs[j].PkgPath })
	return pkgs, diags, nil
}

// packageDiagnostics converts a packages.Package's errors and ignored
// files into semantic diagnostics.
func packageDiagnostics(p *packages.Package) []semantic.Diagnostic {
	var diags []semantic.Diagnostic
	for _, e := range p.Errors {
		cat := semantic.DiagLoadError
		sev := semantic.SeverityError
		switch e.Kind {
		case packages.ParseError:
			cat = semantic.DiagParseError
		case packages.TypeError:
			cat = semantic.DiagTypeError
			sev = semantic.SeverityWarning
		case packages.ListError:
			cat = semantic.DiagLoadError
		}
		pos := parseDriverPos(e.Pos)
		diags = append(diags, semantic.Diagnostic{
			Severity: sev,
			Category: cat,
			Message:  e.Msg,
			Package:  p.PkgPath,
			Position: pos,
		})
	}
	for _, f := range p.IgnoredFiles {
		diags = append(diags, semantic.Diagnostic{
			Severity: semantic.SeverityInfo,
			Category: semantic.DiagBuildConstraint,
			Message:  "source file excluded by build constraints",
			Package:  p.PkgPath,
			Position: semantic.Position{File: f},
		})
	}
	return diags
}

// parseDriverPos parses the "file:line:col" or "file:line" position
// strings emitted by go list into a semantic.Position. It returns the
// zero Position when the string is empty or unparseable.
func parseDriverPos(s string) semantic.Position {
	if s == "" {
		return semantic.Position{}
	}
	rest := s
	line, col := 0, 0
	// Strip up to two trailing :number fields, right to left, so that
	// Windows paths like C:\dir\f.go:3:4 parse correctly.
	for i := 0; i < 2; i++ {
		idx := strings.LastIndexByte(rest, ':')
		if idx < 0 {
			break
		}
		n, err := strconv.Atoi(rest[idx+1:])
		if err != nil {
			break
		}
		if i == 0 {
			col = n
		} else {
			line = n
		}
		rest = rest[:idx]
	}
	if col != 0 && line == 0 {
		// Only one numeric field: it is the line, not the column.
		line, col = col, 0
	}
	if line == 0 {
		return semantic.Position{File: s}
	}
	return semantic.Position{File: rest, Line: line, Column: col}
}

// fsetPos converts a token.Pos to a semantic.Position using the shared
// driver FileSet. token.NoPos yields the zero Position.
func fsetPos(fset *token.FileSet, pos, end token.Pos) semantic.Position {
	if fset == nil || pos == token.NoPos {
		return semantic.Position{}
	}
	p := fset.PositionFor(pos, false)
	out := semantic.Position{
		File:   p.Filename,
		Offset: p.Offset,
		Line:   p.Line,
		Column: p.Column,
	}
	if end != token.NoPos {
		e := fset.PositionFor(end, false)
		out.EndOffset = e.Offset
		out.EndLine = e.Line
		out.EndColumn = e.Column
	}
	return out
}
