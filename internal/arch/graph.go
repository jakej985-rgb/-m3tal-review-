package arch

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GraphOptions configures repository graph construction.
type GraphOptions struct {
	ModulePath string
	MaxNodes   int
	MaxDepth   int
}

// computeContentHash generates a SHA256 hex string from byte contents.
func computeContentHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:16])
}

func extractGenExports(gen *ast.GenDecl) []string {
	var exports []string
	for _, spec := range gen.Specs {
		ts, ok := spec.(*ast.TypeSpec)
		if ok && ts.Name.IsExported() {
			exports = append(exports, ts.Name.Name)
		}
	}
	return exports
}

func parsePackageImports(
	fset *token.FileSet,
	imports []*ast.ImportSpec,
	filePath, modulePath string,
	isTest bool,
) []ImportEdge {
	var edges []ImportEdge
	for _, imp := range imports {
		rawPath := strings.Trim(imp.Path.Value, `"`)
		if !strings.HasPrefix(rawPath, modulePath) {
			continue
		}
		relPkg := strings.TrimPrefix(rawPath, modulePath)
		relPkg = strings.TrimPrefix(relPkg, "/")
		if relPkg == "" {
			relPkg = "."
		}
		pos := fset.Position(imp.Pos())
		edges = append(edges, ImportEdge{
			EdgeLocation: EdgeLocation{
				ToPkg: relPkg,
				File:  filePath,
				Line:  pos.Line,
			},
			IsTest: isTest,
		})
	}
	return edges
}

// inspectPackageFile parses a file AST for package name, exports, and internal imports.
func inspectPackageFile(
	fset *token.FileSet,
	filePath string,
	src any,
	modulePath string,
) (string, []string, []ImportEdge, error) {
	file, err := parser.ParseFile(fset, filePath, src, parser.SkipObjectResolution)
	if err != nil {
		return "", nil, nil, err
	}

	pkgName := file.Name.Name
	var exports []string
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.IsExported() {
			exports = append(exports, fn.Name.Name)
		}
		if gen, ok := decl.(*ast.GenDecl); ok {
			exports = append(exports, extractGenExports(gen)...)
		}
	}

	isTest := strings.HasSuffix(filePath, "_test.go")
	edges := parsePackageImports(fset, file.Imports, filePath, modulePath, isTest)
	return pkgName, exports, edges, nil
}

func findCycleStart(stack []string, target string) int {
	for i, s := range stack {
		if s == target {
			return i
		}
	}
	return -1
}

func checkCycleEdge(stack []string, v string, visited map[string]int) []string {
	if visited[v] != 1 {
		return nil
	}
	idx := findCycleStart(stack, v)
	if idx < 0 {
		return nil
	}
	cycle := append([]string{}, stack[idx:]...)
	return append(cycle, v)
}

// detectGraphCycles finds all circular dependency loops using depth-first search.
func detectGraphCycles(nodes map[string]*PackageNode) [][]string {
	var cycles [][]string
	visited := make(map[string]int)
	var stack []string

	var dfs func(u string)
	dfs = func(u string) {
		visited[u] = 1
		stack = append(stack, u)
		defer func() {
			stack = stack[:len(stack)-1]
			visited[u] = 2
		}()

		node := nodes[u]
		if node == nil {
			return
		}
		for _, edge := range node.Imports {
			v := edge.ToPkg
			if nodes[v] == nil {
				continue
			}
			if cycle := checkCycleEdge(stack, v, visited); cycle != nil {
				cycles = append(cycles, cycle)
			} else if visited[v] == 0 {
				dfs(v)
			}
		}
	}

	var keys []string
	for k := range nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if visited[k] == 0 {
			dfs(k)
		}
	}
	return cycles
}

type graphBuilder struct {
	repoRoot  string
	modPath   string
	opts      GraphOptions
	fset      *token.FileSet
	nodes     map[string]*PackageNode
	diags     []GraphDiagnostic
	truncated bool
}

func (b *graphBuilder) recordFile(
	relDir, relFile, pkgName string,
	content []byte,
	exports []string,
	edges []ImportEdge,
) {
	node := b.nodes[relDir]
	if node == nil {
		node = &PackageNode{
			Path:        relDir,
			Name:        pkgName,
			ContentHash: computeContentHash(content),
		}
		b.nodes[relDir] = node
	}
	node.Files = append(node.Files, relFile)
	node.ExportedSymbols = append(node.ExportedSymbols, exports...)
	for _, e := range edges {
		e.FromPkg = relDir
		node.Imports = append(node.Imports, e)
	}
}

func (b *graphBuilder) processFile(path string) error {
	relFile, _ := filepath.Rel(b.repoRoot, path)
	relDir := filepath.Dir(relFile)
	if relDir == "" {
		relDir = "."
	}

	if len(b.nodes) >= b.opts.MaxNodes && b.nodes[relDir] == nil {
		b.truncated = true
		limitMsg := fmt.Sprintf("Max node limit (%d) reached; package %s skipped", b.opts.MaxNodes, relDir)
		b.diags = append(b.diags, GraphDiagnostic{
			Category: "limit",
			Message:  limitMsg,
			Path:     relDir,
		})
		return filepath.SkipDir
	}

	content, readErr := os.ReadFile(path)
	if readErr != nil {
		return nil
	}
	pkgName, exports, edges, parseErr := inspectPackageFile(b.fset, relFile, content, b.modPath)
	if parseErr != nil {
		return nil
	}

	b.recordFile(relDir, relFile, pkgName, content, exports, edges)
	return nil
}

// BuildArchitectureGraph constructs an ArchitectureGraph from repo source files.
func BuildArchitectureGraph(repoRoot string, opts GraphOptions) (*ArchitectureGraph, error) {
	if opts.MaxNodes <= 0 {
		opts.MaxNodes = 500
	}
	modPath := opts.ModulePath
	if modPath == "" {
		modPath = "github.com/jakej985-rgb/m3tal-review"
	}

	b := &graphBuilder{
		repoRoot: repoRoot,
		modPath:  modPath,
		opts:     opts,
		fset:     token.NewFileSet(),
		nodes:    make(map[string]*PackageNode),
	}

	err := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			if info != nil && info.IsDir() && strings.HasPrefix(info.Name(), ".") &&
				info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(info.Name(), ".go") {
			return nil
		}
		return b.processFile(path)
	})
	if err != nil {
		return nil, err
	}

	cycles := detectGraphCycles(b.nodes)

	return &ArchitectureGraph{
		ModulePath:  modPath,
		Nodes:       b.nodes,
		Cycles:      cycles,
		Diagnostics: b.diags,
		Truncated:   b.truncated,
		BuiltAt:     time.Now().UTC(),
	}, nil
}
