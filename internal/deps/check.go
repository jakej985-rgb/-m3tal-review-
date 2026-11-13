package deps

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// CheckDependencies runs module hygiene and license policy checks on the repository.
func CheckDependencies(repoRoot string, opts CheckOptions) (*DepReport, []review.Finding, error) {
	report, findings, err := AnalyzeGoModules(repoRoot)
	if err != nil {
		return nil, nil, err
	}

	// Multi-module repositories (a go.mod per plugin/package, possibly with
	// no root module) get structural checks on every nested manifest.
	nestedFindings, nestedRequires := analyzeNestedGoMods(repoRoot, report)
	findings = append(findings, nestedFindings...)

	// Licenses are inspected per module path+version: different manifests
	// may require different versions with different licenses, so each
	// result is attributed only to manifests requiring that exact version.
	type modVer struct{ path, version string }
	var order []modVer
	modFiles := make(map[modVer][]string)
	addReq := func(r RequireEntry, file string) {
		k := modVer{path: r.Path, version: r.Version}
		if _, ok := modFiles[k]; !ok {
			order = append(order, k)
		}
		modFiles[k] = appendUnique(modFiles[k], file)
	}
	if report.IsGoModule {
		// Read go.mod to extract required dependencies for license inspection
		modPath := filepath.Join(repoRoot, "go.mod")
		modData, _ := os.ReadFile(modPath)
		parsedMod, _ := ParseGoMod(string(modData))
		for _, r := range parsedMod.Requires {
			addReq(r, "go.mod")
		}
	}
	for _, nr := range nestedRequires {
		addReq(nr.req, nr.file)
	}

	if len(order) > 0 {
		report.Licenses = make(map[string]LicenseInfo, len(order))
		for _, k := range order {
			lic := InspectDependencyLicenses(repoRoot, []RequireEntry{{Path: k.path, Version: k.version}})
			// The report map is keyed by module path; keep the first
			// version seen (root go.mod first) for display.
			if _, ok := report.Licenses[k.path]; !ok {
				report.Licenses[k.path] = lic[k.path]
			}
			findings = append(findings, EvaluateLicensePolicyWithFiles(lic, opts.LicensePolicy, map[string][]string{k.path: modFiles[k]})...)
		}
	}

	// Deterministic ordering of findings
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Rule != findings[j].Rule {
			return findings[i].Rule < findings[j].Rule
		}
		return findings[i].Message < findings[j].Message
	})

	report.Findings = findings
	report.FindingsCount = len(findings)

	return report, findings, nil
}

// nestedRequire is a requirement plus the repo-relative go.mod declaring it.
type nestedRequire struct {
	req  RequireEntry
	file string
}

// underCountedModule reports whether dir lies inside any of the given module
// directories (whose source scans therefore already include dir's files).
// analyzeNestedGoMods and collectImportPaths skip the same directories via
// skipSourceDir, so any nested module found is covered by its ancestor.
func underCountedModule(dir string, counted []string) bool {
	for _, c := range counted {
		if strings.HasPrefix(dir, c+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func appendUnique(list []string, s string) []string {
	for _, v := range list {
		if v == s {
			return list
		}
	}
	return append(list, s)
}

// analyzeNestedGoMods runs the full module hygiene analysis (go.mod syntax,
// go.sum conflicts, duplicate and unused requirements) on every go.mod below
// root, excluding the root module itself and dependency directories.
// Finding paths are rewritten relative to root; unused-dependency checks are
// scoped to each module's own directory. Per-module totals (dependency
// counts, and source files when there is no root module) are aggregated
// into report so nested-only repositories don't print a zero summary.
func analyzeNestedGoMods(root string, report *DepReport) ([]review.Finding, []nestedRequire) {
	rootMod := filepath.Join(root, "go.mod")
	var findings []review.Finding
	var requires []nestedRequire
	var countedDirs []string
	var modPaths []string

	// Pass 1: collect nested go.mod paths. WalkDir visits entries in lexical
	// order, so a child module's go.mod can be seen before its parent's;
	// analysis must run shallowest-first for countedDirs to suppress
	// double-counted source files.
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p == root {
				return nil
			}
			// Same exclusions as collectImportPaths (dot-dirs, vendor,
			// testdata fixtures) plus non-Go dependency directories.
			switch name := d.Name(); {
			case skipSourceDir(name), name == "node_modules", name == "venv", name == "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" || p == rootMod {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil // skip symlinked manifests
		}
		info, err := d.Info()
		if err != nil || info.Size() > 4<<20 {
			return nil
		}
		modPaths = append(modPaths, p)
		return nil
	})
	_ = err // walk errors are non-fatal; partial results are returned

	// Shallowest modules first so a parent's source scan (which includes
	// nested module dirs) marks descendants as already counted.
	sort.Slice(modPaths, func(i, j int) bool {
		ci, cj := strings.Count(modPaths[i], string(filepath.Separator)), strings.Count(modPaths[j], string(filepath.Separator))
		if ci != cj {
			return ci < cj
		}
		return modPaths[i] < modPaths[j]
	})

	for _, p := range modPaths {
		modDir := filepath.Dir(p)
		relDir, err := filepath.Rel(root, modDir)
		if err != nil {
			continue
		}
		relDir = filepath.ToSlash(relDir)
		modReport, modFindings, err := AnalyzeGoModules(modDir)
		if err != nil {
			continue
		}
		report.NestedModules++
		report.DirectDeps += modReport.DirectDeps
		report.IndirectDeps += modReport.IndirectDeps
		// A module's source scan already walks nested directories, including
		// child modules. Only count files for top-most modules: skip when
		// there is a root module, or when an ancestor nested module was
		// already counted (modules are processed shallowest-first).
		if !report.IsGoModule && !underCountedModule(modDir, countedDirs) {
			report.TotalGoFiles += modReport.TotalGoFiles
			countedDirs = append(countedDirs, modDir)
		}
		for i := range modFindings {
			file := modFindings[i].File
			if file == "" {
				file = "go.mod"
			}
			modFindings[i].File = relDir + "/" + file
		}
		findings = append(findings, modFindings...)
		if data, err := os.ReadFile(p); err == nil {
			parsed, _ := ParseGoMod(string(data))
			for _, r := range parsed.Requires {
				requires = append(requires, nestedRequire{req: r, file: relDir + "/go.mod"})
			}
		}
	}
	return findings, requires
}
