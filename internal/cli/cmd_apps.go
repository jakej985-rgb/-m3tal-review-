package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/apps"
	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

func runAppsCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("apps subcommand requires 'list' or 'doctor'")
	}
	sub := args[0]
	rest := args[1:]

	format := "text"
	var appPaths []string
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		switch {
		case arg == "--format" && i+1 < len(rest):
			i++
			format = rest[i]
		case strings.HasPrefix(arg, "--format="):
			_, format, _ = strings.Cut(arg, "=")
		case arg == "--app-path" && i+1 < len(rest):
			i++
			appPaths = append(appPaths, rest[i])
		case strings.HasPrefix(arg, "--app-path="):
			_, v, _ := strings.Cut(arg, "=")
			appPaths = append(appPaths, v)
		default:
			return fmt.Errorf("unknown flag %q for apps %s", arg, sub)
		}
	}
	if format != "text" && format != "json" {
		return fmt.Errorf("invalid --format %q (expected text or json)", format)
	}

	wd, _ := os.Getwd()
	root, err := git.RepositoryRoot(wd)
	if err != nil {
		root = wd
	}

	cfg := apps.RunConfig{
		Root:     root,
		AppPaths: appPaths,
	}

	switch sub {
	case "list":
		return runAppsList(cfg, format)
	case "doctor":
		return runAppsDoctor(cfg, format)
	default:
		return fmt.Errorf("unknown apps subcommand %q (expected list or doctor)", sub)
	}
}

func runAppsList(cfg apps.RunConfig, format string) error {
	discovered, diags, err := apps.Discover(context.Background(), cfg)
	if err != nil {
		return err
	}
	if format == "json" {
		payload := struct {
			Apps        []apps.App `json:"apps"`
			Diagnostics any        `json:"diagnostics,omitempty"`
		}{
			Apps:        discovered,
			Diagnostics: diags,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}
	if len(discovered) == 0 {
		fmt.Println("No language apps discovered.")
	} else {
		for _, a := range discovered {
			fmt.Printf("%-15s %-8s exts=%v patterns=%v rules=%d (%s)\n",
				a.Name, a.Version, a.Extensions, a.FilePatterns, len(a.Rules), a.Path)
		}
	}
	for _, d := range diags {
		fmt.Fprintf(os.Stderr, "[%s] %s\n", d.Level, d.Message)
	}
	return nil
}

func runAppsDoctor(cfg apps.RunConfig, format string) error {
	reg, err := apps.LoadRegistry()
	if err != nil {
		return err
	}
	discovered, diags, err := apps.Discover(context.Background(), cfg)
	if err != nil {
		return err
	}

	foundByName := make(map[string]apps.App, len(discovered))
	for _, a := range discovered {
		foundByName[a.Name] = a
	}

	var issues []string
	for _, entry := range reg.Apps {
		if _, ok := foundByName[entry.Name]; !ok {
			if !entry.Optional {
				issues = append(issues, fmt.Sprintf("missing required app %s (extensions: %v)", entry.Name, entry.Extensions))
			}
		}
	}
	for _, d := range diags {
		issues = append(issues, d.Message)
	}

	healthy := len(issues) == 0
	if format == "json" {
		payload := struct {
			Healthy    bool       `json:"healthy"`
			Discovered []apps.App `json:"discovered"`
			Issues     []string   `json:"issues,omitempty"`
		}{
			Healthy:    healthy,
			Discovered: discovered,
			Issues:     issues,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(payload); err != nil {
			return err
		}
	} else {
		fmt.Printf("Discovered %d app(s).\n", len(discovered))
		for _, a := range discovered {
			fmt.Printf("  OK  %-15s %s (%s)\n", a.Name, a.Version, a.Path)
		}
		for _, iss := range issues {
			fmt.Printf("  ISSUE: %s\n", iss)
		}
	}

	if !healthy {
		return fmt.Errorf("apps doctor found %d issue(s)", len(issues))
	}
	return nil
}
