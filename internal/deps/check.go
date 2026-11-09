package deps

import (
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
	if !report.IsGoModule {
		return report, nil, nil
	}

	// Read go.mod to extract required dependencies for license inspection
	modPath := filepath.Join(repoRoot, "go.mod")
	modData, _ := os.ReadFile(modPath)
	parsedMod, _ := ParseGoMod(string(modData))

	// Inspect licenses
	licenses := InspectDependencyLicenses(repoRoot, parsedMod.Requires)
	report.Licenses = licenses

	// Evaluate license policy if allow, deny, or strict unknown checking is configured
	licenseFindings := EvaluateLicensePolicy(licenses, opts.LicensePolicy)
	findings = append(findings, licenseFindings...)

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
