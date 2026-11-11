package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/deps"
	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func commandCheckDeps(args []string) error {
	format := "text"
	strict := false
	var allowLicenses, denyLicenses []string
	allowUnknown := false
	allowUnknownSet := false
	targetPath := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format":
			if i+1 >= len(args) {
				return fmt.Errorf("--format requires a value (text|json|jsonl)")
			}
			i++
			format = args[i]
			if format != "text" && format != "json" && format != "jsonl" {
				return fmt.Errorf("invalid format %q; expected text, json, or jsonl", format)
			}
		case strings.HasPrefix(arg, "--format="):
			format = strings.TrimPrefix(arg, "--format=")
			if format != "text" && format != "json" && format != "jsonl" {
				return fmt.Errorf("invalid format %q; expected text, json, or jsonl", format)
			}
		case arg == "--strict":
			strict = true
		case arg == "--allow-licenses":
			if i+1 >= len(args) {
				return fmt.Errorf("--allow-licenses requires a comma-separated list")
			}
			i++
			allowLicenses = splitRuleList(args[i])
		case strings.HasPrefix(arg, "--allow-licenses="):
			allowLicenses = splitRuleList(strings.TrimPrefix(arg, "--allow-licenses="))
		case arg == "--deny-licenses":
			if i+1 >= len(args) {
				return fmt.Errorf("--deny-licenses requires a comma-separated list")
			}
			i++
			denyLicenses = splitRuleList(args[i])
		case strings.HasPrefix(arg, "--deny-licenses="):
			denyLicenses = splitRuleList(strings.TrimPrefix(arg, "--deny-licenses="))
		case arg == "--allow-unknown":
			allowUnknown = true
			allowUnknownSet = true
		case arg == "--no-allow-unknown" || arg == "--disallow-unknown":
			allowUnknown = false
			allowUnknownSet = true
		case strings.HasPrefix(arg, "-"):
			return fmt.Errorf("unknown flag %q for check-deps", arg)
		default:
			if targetPath == "" {
				targetPath = arg
			} else {
				return fmt.Errorf("unexpected argument %q", arg)
			}
		}
	}

	repoRoot := targetPath
	if repoRoot == "" {
		workingDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}
		if root, err := git.RepositoryRoot(workingDir); err == nil {
			repoRoot = root
		} else {
			repoRoot = workingDir
		}
	}

	// Read repository policy if present
	policyConfig, _ := review.ReadLicensePolicyConfig(repoRoot, true)
	licensePolicy := deps.LicensePolicy{
		AllowUnknown: false,
	}
	if policyConfig != nil {
		licensePolicy.Allow = policyConfig.Allow
		licensePolicy.Deny = policyConfig.Deny
		if policyConfig.AllowUnknown != nil {
			licensePolicy.AllowUnknown = *policyConfig.AllowUnknown
		}
	}

	// CLI flags override policy
	if len(allowLicenses) > 0 {
		licensePolicy.Allow = allowLicenses
	}
	if len(denyLicenses) > 0 {
		licensePolicy.Deny = denyLicenses
	}
	if allowUnknownSet {
		licensePolicy.AllowUnknown = allowUnknown
	}

	report, findings, err := deps.CheckDependencies(repoRoot, deps.CheckOptions{
		Strict:        strict,
		Format:        format,
		LicensePolicy: licensePolicy,
	})
	if err != nil {
		return err
	}

	if !report.IsGoModule && report.NestedModules == 0 {
		if format == "json" {
			data, _ := json.MarshalIndent(report, "", "  ")
			fmt.Println(string(data))
		} else if format == "jsonl" {
			data, _ := json.Marshal(report)
			fmt.Println(string(data))
		} else {
			fmt.Println("No go.mod found; skipping Go module dependency analysis.")
		}
		return nil
	}

	switch format {
	case "json":
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	case "jsonl":
		for _, f := range findings {
			data, _ := json.Marshal(f)
			fmt.Println(string(data))
		}
	default:
		fmt.Println("M3TAL Review - Go Module & Dependency Analysis")
		fmt.Printf("Module: %s (Go %s)\n", displayText(report.ModulePath), displayText(report.GoVersion))
		fmt.Printf("Dependencies: %d direct, %d indirect\n", report.DirectDeps, report.IndirectDeps)
		fmt.Printf("Source files analyzed: %d\n", report.TotalGoFiles)

		if len(report.UnusedDeps) > 0 {
			fmt.Println("\nUnused direct dependencies:")
			for _, dep := range report.UnusedDeps {
				fmt.Printf("  %s\n", displayText(dep))
			}
		}

		if len(report.Duplicates) > 0 {
			fmt.Println("\nDuplicate/conflicting dependencies:")
			for _, dep := range report.Duplicates {
				fmt.Printf("  %s\n", displayText(dep))
			}
		}

		if len(report.Licenses) > 0 {
			fmt.Println("\nDependency Licenses:")
			mods := make([]string, 0, len(report.Licenses))
			for m := range report.Licenses {
				mods = append(mods, m)
			}
			sort.Strings(mods)
			for _, m := range mods {
				info := report.Licenses[m]
				fmt.Printf("  %-40s %s\n", displayText(m), displayText(info.License))
			}
		}

		if len(findings) == 0 {
			fmt.Println("\nFindings: (none)")
		} else {
			fmt.Printf("\nFindings (%d):\n", len(findings))
			for _, f := range findings {
				loc := f.File
				if f.Line > 0 {
					loc = fmt.Sprintf("%s:%d", loc, f.Line)
				}
				fmt.Printf("  [%s] %s: %s (%s)\n", f.Severity, loc, displayText(f.Message), f.Rule)
				if f.Remediation != "" {
					fmt.Printf("    Remediation: %s\n", displayText(f.Remediation))
				}
			}
		}
	}

	if strict && len(findings) > 0 {
		return fmt.Errorf("%d dependency hygiene finding(s) detected", len(findings))
	}

	return nil
}
