package deps

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// ReachabilityStatus denotes whether a vulnerable dependency is reached by repository code.
type ReachabilityStatus string

const (
	ReachabilityReachable            ReachabilityStatus = "Reachable"
	ReachabilityPotentiallyReachable ReachabilityStatus = "Potentially Reachable"
	ReachabilityUnreachable          ReachabilityStatus = "Unreachable"
)

// DependencyType indicates whether a dependency is directly or transitively declared.
type DependencyType string

const (
	DependencyTypeDirect     DependencyType = "direct"
	DependencyTypeTransitive DependencyType = "transitive"
)

// ReachabilityContext records the reachability assessment, rationale, and call evidence.
type ReachabilityContext struct {
	Package           string             `json:"package"`
	Ecosystem         string             `json:"ecosystem"`
	DependencyType    DependencyType     `json:"dependency_type"`
	Status            ReachabilityStatus `json:"status"`
	Rationale         string             `json:"rationale"`
	ImportedBy        []string           `json:"imported_by,omitempty"`
	ReferencedSymbols []string           `json:"referenced_symbols,omitempty"`
	CallSitesCount    int                `json:"call_sites_count"`
}

// AssessReachability inspects repository code and dependency manifests to determine reachability.
func AssessReachability(repoRoot, depName, ecosystem string, isDirect bool) ReachabilityContext {
	depType := DependencyTypeDirect
	if !isDirect {
		depType = DependencyTypeTransitive
	}

	res := ReachabilityContext{
		Package:        depName,
		Ecosystem:      ecosystem,
		DependencyType: depType,
	}

	cleanDepName := strings.TrimSpace(depName)
	if cleanDepName == "" {
		res.Status = ReachabilityUnreachable
		res.Rationale = "Empty dependency name provided"
		return res
	}

	switch strings.ToLower(ecosystem) {
	case "go":
		return assessGoReachability(repoRoot, cleanDepName, isDirect)
	case "npm":
		return assessNpmReachability(repoRoot, cleanDepName, isDirect)
	case "pypi":
		return assessPythonReachability(repoRoot, cleanDepName, isDirect)
	default:
		// Generic heuristic for unknown ecosystems
		return assessGenericReachability(repoRoot, cleanDepName, isDirect)
	}
}

// assessGoReachability parses Go ASTs to find imports, symbol selectors, and call expressions.
func assessGoReachability(repoRoot, pkgPath string, isDirect bool) ReachabilityContext {
	depType := DependencyTypeDirect
	if !isDirect {
		depType = DependencyTypeTransitive
	}

	res := ReachabilityContext{
		Package:        pkgPath,
		Ecosystem:      "Go",
		DependencyType: depType,
	}

	// Verify direct vs indirect in go.mod if exists
	modPath := filepath.Join(repoRoot, "go.mod")
	if modData, err := os.ReadFile(modPath); err == nil {
		if mod, _ := ParseGoMod(string(modData)); mod != nil {
			foundInMod := false
			for _, req := range mod.Requires {
				if req.Path == pkgPath || strings.HasPrefix(pkgPath, req.Path+"/") {
					foundInMod = true
					if req.Indirect {
						res.DependencyType = DependencyTypeTransitive
					} else {
						res.DependencyType = DependencyTypeDirect
					}
					break
				}
			}
			if !foundInMod && !isDirect {
				res.DependencyType = DependencyTypeTransitive
			}
		}
	}

	fset := token.NewFileSet()
	var importedBy []string
	symbolsMap := make(map[string]bool)
	callSites := 0
	hasBlankImport := false

	_ = filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}

		relPath, _ := filepath.Rel(repoRoot, p)
		relPath = filepath.ToSlash(relPath)

		fileAst, parseErr := parser.ParseFile(fset, p, data, parser.ParseComments)
		if parseErr == nil && fileAst != nil {
			// Find if this file imports pkgPath or subpackages
			fileImportsPkg := false
			localIdents := make(map[string]bool)

			for _, imp := range fileAst.Imports {
				if imp == nil || imp.Path == nil {
					continue
				}
				cleanImp := strings.Trim(imp.Path.Value, `"`)
				if cleanImp == pkgPath || strings.HasPrefix(cleanImp, pkgPath+"/") {
					fileImportsPkg = true
					if imp.Name != nil {
						if imp.Name.Name == "_" {
							hasBlankImport = true
						} else if imp.Name.Name != "." {
							localIdents[imp.Name.Name] = true
						}
					} else {
						// Default local identifier is the last element of the import path
						ident := path.Base(cleanImp)
						localIdents[ident] = true
					}
				}
			}

			if fileImportsPkg {
				importedBy = append(importedBy, relPath)

				// Walk AST looking for selector expressions or calls matching local identifiers
				ast.Inspect(fileAst, func(n ast.Node) bool {
					switch node := n.(type) {
					case *ast.SelectorExpr:
						if xIdent, ok := node.X.(*ast.Ident); ok {
							if localIdents[xIdent.Name] {
								symbolsMap[node.Sel.Name] = true
							}
						}
					case *ast.CallExpr:
						if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
							if xIdent, ok := sel.X.(*ast.Ident); ok {
								if localIdents[xIdent.Name] {
									callSites++
									symbolsMap[sel.Sel.Name] = true
								}
							}
						}
					}
					return true
				})
			}
		} else {
			// Fallback regex parsing if file has syntax errors
			content := string(data)
			if strings.Contains(content, `"`+pkgPath+`"`) || strings.Contains(content, `"`+pkgPath+"/") {
				importedBy = append(importedBy, relPath)
				pkgIdent := path.Base(pkgPath)
				callRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(pkgIdent) + `\.([A-Z][a-zA-Z0-9_]*)`)
				matches := callRe.FindAllStringSubmatch(content, -1)
				for _, m := range matches {
					if len(m) >= 2 {
						symbolsMap[m[1]] = true
						callSites++
					}
				}
			}
		}
		return nil
	})

	sort.Strings(importedBy)
	res.ImportedBy = importedBy
	res.CallSitesCount = callSites

	var symbolsList []string
	for s := range symbolsMap {
		symbolsList = append(symbolsList, s)
	}
	sort.Strings(symbolsList)
	res.ReferencedSymbols = symbolsList

	// Reachability determination
	if len(symbolsList) > 0 || callSites > 0 {
		res.Status = ReachabilityReachable
		res.Rationale = fmt.Sprintf("%s dependency is imported in %d file(s) with confirmed symbol references (%s)",
			res.DependencyType, len(importedBy), strings.Join(symbolsList, ", "))
	} else if len(importedBy) > 0 {
		res.Status = ReachabilityPotentiallyReachable
		if hasBlankImport {
			res.Rationale = fmt.Sprintf("%s dependency is imported for side-effects via blank import (_) in %s",
				res.DependencyType, strings.Join(importedBy, ", "))
		} else {
			res.Rationale = fmt.Sprintf("%s dependency is imported in %s, but no explicit symbol call expressions were identified",
				res.DependencyType, strings.Join(importedBy, ", "))
		}
	} else {
		res.Status = ReachabilityUnreachable
		if res.DependencyType == DependencyTypeDirect {
			res.Rationale = "Direct dependency is declared in go.mod but not imported in any Go source file (unused direct dependency)"
		} else {
			res.Rationale = "Transitive dependency is not directly imported in any repository source file"
		}
	}

	return res
}

func assessNpmReachability(repoRoot, pkgName string, isDirect bool) ReachabilityContext {
	depType := DependencyTypeDirect
	if !isDirect {
		depType = DependencyTypeTransitive
	}

	res := ReachabilityContext{
		Package:        pkgName,
		Ecosystem:      "npm",
		DependencyType: depType,
	}

	importPatterns := []*regexp.Regexp{
		regexp.MustCompile(`require\s*\(\s*['"]` + regexp.QuoteMeta(pkgName) + `(?:/[^'"]*)?['"]\s*\)`),
		regexp.MustCompile(`from\s*['"]` + regexp.QuoteMeta(pkgName) + `(?:/[^'"]*)?['"]`),
		regexp.MustCompile(`import\s*\(\s*['"]` + regexp.QuoteMeta(pkgName) + `(?:/[^'"]*)?['"]\s*\)`),
	}

	var importedBy []string
	_ = filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				name := d.Name()
				if strings.HasPrefix(name, ".") || name == "node_modules" || name == "dist" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".js" && ext != ".ts" && ext != ".jsx" && ext != ".tsx" && ext != ".mjs" && ext != ".cjs" {
			return nil
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		content := string(data)
		for _, pat := range importPatterns {
			if pat.MatchString(content) {
				relPath, _ := filepath.Rel(repoRoot, p)
				importedBy = append(importedBy, filepath.ToSlash(relPath))
				break
			}
		}
		return nil
	})

	sort.Strings(importedBy)
	res.ImportedBy = importedBy

	if len(importedBy) > 0 {
		res.Status = ReachabilityReachable
		res.Rationale = fmt.Sprintf("%s npm package is imported in %d source file(s): %s",
			depType, len(importedBy), strings.Join(importedBy, ", "))
	} else {
		res.Status = ReachabilityUnreachable
		res.Rationale = fmt.Sprintf("%s npm package is declared in manifest but never imported across JavaScript/TypeScript sources", depType)
	}

	return res
}

func assessPythonReachability(repoRoot, pkgName string, isDirect bool) ReachabilityContext {
	depType := DependencyTypeDirect
	if !isDirect {
		depType = DependencyTypeTransitive
	}

	res := ReachabilityContext{
		Package:        pkgName,
		Ecosystem:      "PyPI",
		DependencyType: depType,
	}

	// Python import names replace hyphens with underscores
	moduleName := strings.ReplaceAll(pkgName, "-", "_")
	importPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*import\s+` + regexp.QuoteMeta(moduleName) + `\b`),
		regexp.MustCompile(`(?m)^\s*from\s+` + regexp.QuoteMeta(moduleName) + `\b`),
	}

	var importedBy []string
	_ = filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if d != nil && d.IsDir() {
				name := d.Name()
				if strings.HasPrefix(name, ".") || name == "venv" || name == ".venv" || name == "__pycache__" {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(p, ".py") {
			return nil
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}
		content := string(data)
		for _, pat := range importPatterns {
			if pat.MatchString(content) {
				relPath, _ := filepath.Rel(repoRoot, p)
				importedBy = append(importedBy, filepath.ToSlash(relPath))
				break
			}
		}
		return nil
	})

	sort.Strings(importedBy)
	res.ImportedBy = importedBy

	if len(importedBy) > 0 {
		res.Status = ReachabilityReachable
		res.Rationale = fmt.Sprintf("%s PyPI package is imported in %d Python file(s): %s",
			depType, len(importedBy), strings.Join(importedBy, ", "))
	} else {
		res.Status = ReachabilityUnreachable
		res.Rationale = fmt.Sprintf("%s PyPI package is pinned in requirements but never imported in repository Python files", depType)
	}

	return res
}

func assessGenericReachability(repoRoot, depName string, isDirect bool) ReachabilityContext {
	depType := DependencyTypeDirect
	if !isDirect {
		depType = DependencyTypeTransitive
	}

	if isDirect {
		return ReachabilityContext{
			Package:        depName,
			Ecosystem:      "Generic",
			DependencyType: depType,
			Status:         ReachabilityPotentiallyReachable,
			Rationale:      "Direct dependency declared in project manifest",
		}
	}
	return ReachabilityContext{
		Package:        depName,
		Ecosystem:      "Generic",
		DependencyType: depType,
		Status:         ReachabilityUnreachable,
		Rationale:      "Transitive dependency with no direct invocation evidence",
	}
}

// EnrichFindingWithReachability enriches a Finding with reachability metadata and evidence.
func EnrichFindingWithReachability(f *review.Finding, ctx ReachabilityContext) {
	if f == nil {
		return
	}
	f.Reachability = string(ctx.Status)
	if f.Metadata == nil {
		f.Metadata = make(map[string]string)
	}
	f.Metadata["reachability"] = string(ctx.Status)
	f.Metadata["reachability_rationale"] = ctx.Rationale
	f.Metadata["dependency_type"] = string(ctx.DependencyType)
	f.Metadata["package"] = ctx.Package
	f.Metadata["ecosystem"] = ctx.Ecosystem

	if len(ctx.ReferencedSymbols) > 0 {
		f.Metadata["referenced_symbols"] = strings.Join(ctx.ReferencedSymbols, ",")
	}
	if len(ctx.ImportedBy) > 0 {
		f.Metadata["imported_by"] = strings.Join(ctx.ImportedBy, ",")
	}
	if ctx.CallSitesCount > 0 {
		f.Metadata["call_sites_count"] = fmt.Sprintf("%d", ctx.CallSitesCount)
	}

	f.Evidence = append(f.Evidence, review.FindingEvidence{
		Analyzer: "reachability-analyzer",
		Rule:     "reachability-context",
		Severity: f.Severity,
		Message:  fmt.Sprintf("[%s] %s (%s)", ctx.Status, ctx.Rationale, ctx.DependencyType),
	})
}
