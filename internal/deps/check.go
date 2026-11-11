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
	// modFiles maps each required module path to every manifest requiring
	// it, so license findings land on the right go.mod(s).
	modFiles := make(map[string][]string)
	if report.IsGoModule {
		// Read go.mod to extract required dependencies for license inspection
		modPath := filepath.Join(repoRoot, "go.mod")
		modData, _ := os.ReadFile(modPath)
		parsedMod, _ := ParseGoMod(string(modData))
		for _, r := range parsedMod.Requires {
			requires = append(requires, r)
			modFiles[r.Path] = appendUnique(modFiles[r.Path], "go.mod")
		}
	}
	// Merge nested module requirements (deduplicated by module path for
	// inspection, but every requiring manifest is remembered).
	for _, nr := range nestedRequires {
		if _, ok := modFiles[nr.req.Path]; !ok {
			requires = append(requires, nr.req)
		}
		modFiles[nr.req.Path] = appendUnique(modFiles[nr.req.Path], nr.file)
	}

	if len(requires) > 0 {
		licenses := InspectDependencyLicenses(repoRoot, requires)
		report.Licenses = licenses
		findings = append(findings, EvaluateLicensePolicyWithFiles(licenses, opts.LicensePolicy, modFiles)...)
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
// scoped to each module's own directory.
func analyzeNestedGoMods(root string) ([]review.Finding, []nestedRequire, int) {
	rootMod := filepath.Join(root, "go.mod")
	var findings []review.Finding
	var requires []nestedRequire
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
		if !d.Type().IsRegular() {
			return nil // skip symlinked manifests
		}
		info, err := d.Info()
		if err != nil || info.Size() > 4<<20 {
			return nil
		}
		nestedCount++
		modDir := filepath.Dir(p)
		relDir, err := filepath.Rel(root, modDir)
		if err != nil {
			return nil
		}
		relDir = filepath.ToSlash(relDir)
		_, modFindings, err := AnalyzeGoModules(modDir)
		if err != nil {
			return nil
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
		return nil
	})
	if err != nil {
		return findings, requires, nestedCount
	}
	return findings, requires, nestedCount
}
