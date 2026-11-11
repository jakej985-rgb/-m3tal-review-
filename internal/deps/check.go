package deps

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"

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
	nestedFindings, nestedRequires, nestedCount := analyzeNestedGoMods(repoRoot)
	findings = append(findings, nestedFindings...)
	report.NestedModules = nestedCount

	var requires []RequireEntry
	if report.IsGoModule {
		// Read go.mod to extract required dependencies for license inspection
		modPath := filepath.Join(repoRoot, "go.mod")
		modData, _ := os.ReadFile(modPath)
		parsedMod, _ := ParseGoMod(string(modData))
		requires = parsedMod.Requires
	}
	// Merge nested module requirements (deduplicated by module path).
	seenReq := make(map[string]bool, len(requires)+len(nestedRequires))
	for _, r := range requires {
		seenReq[r.Path] = true
	}
	for _, r := range nestedRequires {
		if !seenReq[r.Path] {
			seenReq[r.Path] = true
			requires = append(requires, r)
		}
	}

	if len(requires) > 0 {
		licenses := InspectDependencyLicenses(repoRoot, requires)
		report.Licenses = licenses
		findings = append(findings, EvaluateLicensePolicy(licenses, opts.LicensePolicy)...)
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

// analyzeNestedGoMods parses every go.mod below root (excluding the root
// module itself and dependency directories) and returns structural findings
// plus the union of required modules for license inspection.
func analyzeNestedGoMods(root string) ([]review.Finding, []RequireEntry, int) {
	rootMod := filepath.Join(root, "go.mod")
	var findings []review.Finding
	var requires []RequireEntry
	nestedCount := 0

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", ".venv", "venv", "__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "go.mod" || p == rootMod {
			return nil
		}
		nestedCount++
		data, err := os.ReadFile(p)
		if err != nil || len(data) > 4<<20 {
			return nil
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		parsed, modFindings := ParseGoMod(string(data))
		for i := range modFindings {
			modFindings[i].File = relSlash
		}
		findings = append(findings, modFindings...)
		requires = append(requires, parsed.Requires...)
		return nil
	})
	if err != nil {
		return findings, requires, nestedCount
	}
	return findings, requires, nestedCount
}
