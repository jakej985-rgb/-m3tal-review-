package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analyzers"
	"github.com/jakej985-rgb/m3tal-review/internal/analyzers/defaultreg"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/buildsystem"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/framework"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/language"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

type detectCLIOptions struct {
	Target   string
	Format   string
	Profile  string
	Language []string
}

func parseDetectCLIOptions(args []string) (detectCLIOptions, error) {
	opts := detectCLIOptions{
		Target:  ".",
		Format:  "text",
		Profile: "fast",
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--format" && i+1 < len(args):
			i++
			opts.Format = args[i]
		case strings.HasPrefix(arg, "--format="):
			_, opts.Format, _ = strings.Cut(arg, "=")
		case arg == "--profile" && i+1 < len(args):
			i++
			opts.Profile = args[i]
		case strings.HasPrefix(arg, "--profile="):
			_, opts.Profile, _ = strings.Cut(arg, "=")
		case arg == "--language" && i+1 < len(args):
			i++
			opts.Language = append(opts.Language, strings.Split(args[i], ",")...)
		case strings.HasPrefix(arg, "--language="):
			_, v, _ := strings.Cut(arg, "=")
			opts.Language = append(opts.Language, strings.Split(v, ",")...)
		case !strings.HasPrefix(arg, "-"):
			opts.Target = arg
		default:
			return opts, fmt.Errorf("unknown flag %q", arg)
		}
	}
	if opts.Format != "text" && opts.Format != "json" {
		return opts, fmt.Errorf("invalid --format %q (expected text or json)", opts.Format)
	}
	return opts, nil
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runScanCommand(args []string) error {
	opts, err := parseDetectCLIOptions(args)
	if err != nil {
		return err
	}
	inv, err := scanner.Scan(opts.Target, scanner.ScanOptions{})
	if err != nil {
		return err
	}
	if opts.Format == "json" {
		return printJSON(inv)
	}
	fmt.Printf("Repository: %s\nFiles: %d\nManifests: %d\n", inv.Root, len(inv.Files), len(inv.Manifests))
	return nil
}

func runDetectCommand(args []string) error {
	opts, err := parseDetectCLIOptions(args)
	if err != nil {
		return err
	}
	inv, err := scanner.Scan(opts.Target, scanner.ScanOptions{})
	if err != nil {
		return err
	}
	det := language.Detect(inv, language.DetectConfig{})
	fws := framework.Detect(inv)
	builds := buildsystem.Detect(inv)

	if opts.Format == "json" {
		return printJSON(struct {
			Languages    language.RepositoryDetection  `json:"languages"`
			Frameworks   []framework.FrameworkInfo     `json:"frameworks"`
			BuildSystems []buildsystem.BuildSystemInfo `json:"build_systems"`
		}{Languages: det, Frameworks: fws, BuildSystems: builds})
	}

	fmt.Println("Detected languages:")
	for _, l := range det.Languages {
		fmt.Printf("  %-14s %4d file(s)  confidence=%.2f\n", l.Name, l.FileCount, l.Confidence)
	}
	if len(fws) > 0 {
		fmt.Println("Detected frameworks & infrastructure:")
		for _, f := range fws {
			fmt.Printf("  %-14s (%s)  confidence=%.2f\n", f.Name, f.Kind, f.Confidence)
		}
	}
	if len(builds) > 0 {
		fmt.Println("Detected build systems:")
		for _, b := range builds {
			fmt.Printf("  %-14s (%s)\n", b.Name, b.Manifest)
		}
	}
	return nil
}

func runLanguagesCommand(args []string) error {
	opts, err := parseDetectCLIOptions(args)
	if err != nil {
		return err
	}
	caps := language.SupportedLanguages()
	if opts.Format == "json" {
		return printJSON(caps)
	}
	fmt.Printf("%-12s %-4s %-7s %-6s %-6s %-8s %-6s %-6s\n", "LANGUAGE", "TIER", "DETECT", "AST", "SEM", "FLOW", "REPAIR", "EXTENSIONS")
	for _, c := range caps {
		fmt.Printf("%-12s %-4d %-7t %-6t %-6t %-8t %-6t %s\n",
			c.Name, c.Tier, c.Detection, c.AST, c.Semantic, c.Flow, c.Repair, strings.Join(c.Extensions, ","))
	}
	return nil
}

func runAnalyzersCommand(args []string) error {
	opts, err := parseDetectCLIOptions(args)
	if err != nil {
		return err
	}
	all := planning.DefaultAnalyzers()
	var filtered []planning.AnalyzerMetadata
	langSet := make(map[string]bool, len(opts.Language))
	for _, l := range opts.Language {
		if t := strings.TrimSpace(strings.ToLower(l)); t != "" {
			langSet[t] = true
		}
	}
	for _, a := range all {
		if len(langSet) > 0 {
			matched := false
			for _, l := range a.Languages {
				if langSet[strings.ToLower(l)] {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		filtered = append(filtered, a)
	}
	if opts.Format == "json" {
		return printJSON(filtered)
	}
	for _, a := range filtered {
		fmt.Printf("%-18s %-14s %s\n", a.ID, a.Kind, a.Description)
	}
	return nil
}

func runExplainCommand(args []string) error {
	opts, err := parseDetectCLIOptions(args)
	if err != nil {
		return err
	}
	inv, err := scanner.Scan(opts.Target, scanner.ScanOptions{})
	if err != nil {
		return err
	}
	det := language.Detect(inv, language.DetectConfig{})
	fws := framework.Detect(inv)
	builds := buildsystem.Detect(inv)
	plan := planning.BuildPlan(det, fws, builds, planning.PlanConfig{
		Profile:        opts.Profile,
		LanguageFilter: opts.Language,
	}, planning.DefaultAnalyzers())

	if opts.Format == "json" {
		return printJSON(plan)
	}
	fmt.Println("Selected analyzers:")
	for _, s := range plan.Selected {
		fmt.Printf("  [x] %-28s (%s)\n", s.Analyzer.Name, s.Reason)
	}
	fmt.Println("Skipped analyzers:")
	for _, sk := range plan.Skipped {
		fmt.Printf("  [ ] %-28s (%s)\n", sk.Analyzer.Name, sk.Reason)
	}
	return nil
}

func runMultiLangCheckCommand(args []string) error {
	opts, err := parseDetectCLIOptions(args)
	if err != nil {
		return err
	}
	inv, err := scanner.Scan(opts.Target, scanner.ScanOptions{})
	if err != nil {
		return err
	}
	det := language.Detect(inv, language.DetectConfig{})
	fws := framework.Detect(inv)
	builds := buildsystem.Detect(inv)

	reg := defaultreg.New()
	plan := planning.BuildPlan(det, fws, builds, planning.PlanConfig{
		Profile:        opts.Profile,
		LanguageFilter: opts.Language,
	}, reg.Catalog())

	langByPath := make(map[string]language.FileDetection, len(det.Files))
	for _, fd := range det.Files {
		langByPath[fd.Path] = fd
	}
	var targetFiles []analyzers.TargetFile
	for _, f := range inv.Files {
		if f.Excluded {
			continue
		}
		data, err := os.ReadFile(filepath.Join(inv.Root, filepath.FromSlash(f.Path)))
		if err != nil {
			continue
		}
		fd := langByPath[f.Path]
		targetFiles = append(targetFiles, analyzers.TargetFile{
			Path:      f.Path,
			Language:  fd.Language,
			Secondary: fd.SecondaryLanguages,
			Content:   string(data),
		})
	}

	cache := analyzers.NewResultCache(version)
	findings, ranIDs := reg.RunPlan(context.Background(), plan, inv.Root, targetFiles, det, cache)
	if opts.Format == "json" {
		return printJSON(struct {
			Analyzers []string         `json:"analyzers"`
			Findings  []review.Finding `json:"findings"`
		}{Analyzers: ranIDs, Findings: findings})
	}
	fmt.Printf("Ran %d analyzer(s), found %d issue(s).\n", len(ranIDs), len(findings))
	for _, f := range findings {
		fmt.Printf("%s:%d [%s] %s: %s\n", f.File, f.Line, f.Severity, f.Rule, f.Message)
	}
	return nil
}
