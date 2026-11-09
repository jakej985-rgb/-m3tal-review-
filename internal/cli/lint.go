package cli

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

var (
	vetLinePattern         = regexp.MustCompile(`^(?:vet: )?(.+?):(\d+):(\d+): (.+)$`)
	staticcheckLinePattern = regexp.MustCompile(`^(.+?):(\d+):(\d+): (.+)$`)
	golangciLinePattern    = regexp.MustCompile(`^(.+?):(\d+)(?::(\d+))?: (.+)$`)
)

func commandLint(args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	if err := git.Available(); err != nil {
		return err
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	// 1. Load config from repo (.m3tal-review-config.json, .m3tal-review-policy.json) and user config
	cfg, _ := review.ReadLintConfig(repositoryRoot, true)
	if cfg == nil {
		cfg = &review.LintConfig{}
	}

	uCfg, _ := loadUserConfig()
	if uCfg.Lint != nil {
		if cfg.Profile == "" && uCfg.Lint.Profile != "" {
			cfg.Profile = uCfg.Lint.Profile
		}
		if len(cfg.Analyzers) == 0 && len(uCfg.Lint.Analyzers) > 0 {
			cfg.Analyzers = uCfg.Lint.Analyzers
		}
		cfg.Exclusions = append(cfg.Exclusions, uCfg.Lint.Exclusions...)
		cfg.Exclude = append(cfg.Exclude, uCfg.Lint.Exclude...)
		if cfg.ToolPaths == nil {
			cfg.ToolPaths = make(map[string]string)
		}
		for k, v := range uCfg.Lint.ToolPaths {
			if cfg.ToolPaths[k] == "" {
				cfg.ToolPaths[k] = v
			}
		}
	}

	// 2. Parse CLI flags
	var cliAnalyzers []string
	var cliExclusions []string
	cliProfile := ""
	cliScope := ""

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--profile" && i+1 < len(args):
			i++
			cliProfile = args[i]
		case strings.HasPrefix(arg, "--profile="):
			cliProfile = strings.TrimPrefix(arg, "--profile=")
		case arg == "--analyzer" && i+1 < len(args):
			i++
			cliAnalyzers = append(cliAnalyzers, strings.Split(args[i], ",")...)
		case strings.HasPrefix(arg, "--analyzer="):
			cliAnalyzers = append(cliAnalyzers, strings.Split(strings.TrimPrefix(arg, "--analyzer="), ",")...)
		case arg == "--exclude" && i+1 < len(args):
			i++
			cliExclusions = append(cliExclusions, strings.Split(args[i], ",")...)
		case strings.HasPrefix(arg, "--exclude="):
			cliExclusions = append(cliExclusions, strings.Split(strings.TrimPrefix(arg, "--exclude="), ",")...)
		case arg == "--scope" && i+1 < len(args):
			i++
			cliScope = args[i]
		case strings.HasPrefix(arg, "--scope="):
			cliScope = strings.TrimPrefix(arg, "--scope=")
		}
	}

	if cliProfile != "" {
		cfg.Profile = cliProfile
	}
	if len(cliAnalyzers) > 0 {
		cfg.Analyzers = cliAnalyzers
	}
	if len(cliExclusions) > 0 {
		cfg.Exclusions = append(cfg.Exclusions, cliExclusions...)
	}
	if cliScope != "" {
		cfg.Scope = cliScope
	}

	fmt.Println("M3TAL Review Lint")
	fmt.Println("Repository:", displayText(repositoryRoot))

	exclusions := cfg.EffectiveExclusions()
	analyzers := cfg.EffectiveAnalyzers()

	for _, analyzer := range analyzers {
		normAnalyzer := strings.ToLower(strings.TrimSpace(analyzer))
		switch normAnalyzer {
		case "gofmt":
			fmt.Println("Checking Go formatting...")
			execPath, err := cfg.ResolveToolExecutable("gofmt")
			if err != nil {
				return fmt.Errorf("gofmt is unavailable: %w", err)
			}
			formatOutput, err := runCommand(context.Background(), repositoryRoot, execPath, "-l", ".")
			if err != nil {
				return fmt.Errorf("run gofmt: %w\n%s", err, displayText(string(formatOutput)))
			}

			rawFiles := strings.Split(strings.TrimSpace(string(formatOutput)), "\n")
			var needFormat []string
			for _, file := range rawFiles {
				if file == "" {
					continue
				}
				cleanFile := filepath.ToSlash(file)
				if isLintExcluded(cleanFile, exclusions) {
					continue
				}
				needFormat = append(needFormat, cleanFile)
			}

			if len(needFormat) > 0 {
				fmt.Println("Files need formatting:")
				for _, file := range needFormat {
					fmt.Println(displayText(file))
				}
				return fmt.Errorf("gofmt check failed")
			}
			fmt.Println("Formatting passed.")

		case "govet", "go vet", "vet":
			fmt.Println("Running go vet...")
			execPath, err := cfg.ResolveToolExecutable("govet")
			if err != nil {
				return fmt.Errorf("go vet is unavailable: %w", err)
			}

			scope := "./..."
			if cfg.Scope != "" {
				scope = cfg.Scope
			}

			vetOutput, vetErr := runCommand(context.Background(), repositoryRoot, execPath, "vet", scope)
			if vetErr != nil {
				// Filter excluded files from vet output
				lines := strings.Split(string(vetOutput), "\n")
				var filteredLines []string
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					match := vetLinePattern.FindStringSubmatch(line)
					if match != nil {
						file := filepath.ToSlash(strings.TrimPrefix(match[1], "./"))
						if isLintExcluded(file, exclusions) {
							continue
						}
					}
					filteredLines = append(filteredLines, line)
				}
				if len(filteredLines) > 0 {
					return fmt.Errorf("go vet failed: %w\n%s", vetErr, displayText(strings.Join(filteredLines, "\n")))
				}
			}
			fmt.Println("go vet passed.")

		case "staticcheck":
			fmt.Println("Running staticcheck...")
			execPath, err := cfg.ResolveToolExecutable("staticcheck")
			if err != nil {
				return fmt.Errorf("staticcheck is unavailable: %w", err)
			}

			scope := "./..."
			if cfg.Scope != "" {
				scope = cfg.Scope
			}

			scOutput, scErr := runCommand(context.Background(), repositoryRoot, execPath, scope)
			if scErr != nil {
				lines := strings.Split(string(scOutput), "\n")
				var filteredLines []string
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					match := staticcheckLinePattern.FindStringSubmatch(line)
					if match != nil {
						file := filepath.ToSlash(strings.TrimPrefix(match[1], "./"))
						if isLintExcluded(file, exclusions) {
							continue
						}
					}
					filteredLines = append(filteredLines, line)
				}
				if len(filteredLines) > 0 {
					return fmt.Errorf("staticcheck failed: %w\n%s", scErr, displayText(strings.Join(filteredLines, "\n")))
				}
			}
			fmt.Println("staticcheck passed.")

		case "golangci-lint", "golangci":
			fmt.Println("Running golangci-lint...")
			execPath, err := cfg.ResolveToolExecutable("golangci-lint")
			if err != nil {
				return fmt.Errorf("golangci-lint is unavailable: %w", err)
			}

			scope := "./..."
			if cfg.Scope != "" {
				scope = cfg.Scope
			}

			gclOutput, gclErr := runCommand(context.Background(), repositoryRoot, execPath, "run", scope)
			if gclErr != nil {
				lines := strings.Split(string(gclOutput), "\n")
				var filteredLines []string
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					match := golangciLinePattern.FindStringSubmatch(line)
					if match != nil {
						file := filepath.ToSlash(strings.TrimPrefix(match[1], "./"))
						if isLintExcluded(file, exclusions) {
							continue
						}
					}
					filteredLines = append(filteredLines, line)
				}
				if len(filteredLines) > 0 {
					return fmt.Errorf("golangci-lint failed: %w\n%s", gclErr, displayText(strings.Join(filteredLines, "\n")))
				}
			}
			fmt.Println("golangci-lint passed.")

		default:
			// Configured custom analyzer
			execPath, err := cfg.ResolveToolExecutable(analyzer)
			if err != nil {
				return fmt.Errorf("analyzer %s is unavailable: %w", analyzer, err)
			}
			fmt.Printf("Running %s...\n", analyzer)
			out, err := runCommand(context.Background(), repositoryRoot, execPath)
			if err != nil {
				return fmt.Errorf("analyzer %s failed: %w\n%s", analyzer, err, displayText(string(out)))
			}
			fmt.Printf("%s passed.\n", analyzer)
		}
	}

	return nil
}

func isLintExcluded(file string, exclusions []string) bool {
	normFile := filepath.ToSlash(strings.ReplaceAll(file, "\\", "/"))
	base := path.Base(normFile)

	for _, pattern := range exclusions {
		normPattern := filepath.ToSlash(strings.ReplaceAll(pattern, "\\", "/"))
		if normFile == normPattern || base == normPattern {
			return true
		}
		if !strings.Contains(normPattern, "/") {
			if matched, _ := path.Match(normPattern, base); matched {
				return true
			}
		}
		if matchLintPattern(normPattern, normFile) {
			return true
		}
	}
	return false
}

func matchLintPattern(pattern, file string) bool {
	pParts := strings.Split(pattern, "/")
	fParts := strings.Split(file, "/")
	return matchLintMemo(pParts, fParts, 0, 0)
}

func matchLintMemo(pParts, fParts []string, pi, fi int) bool {
	if pi == len(pParts) {
		return fi == len(fParts)
	}
	if pParts[pi] == "**" {
		for next := fi; next <= len(fParts); next++ {
			if matchLintMemo(pParts, fParts, pi+1, next) {
				return true
			}
		}
		return false
	}
	if fi == len(fParts) {
		return false
	}
	matched, err := path.Match(pParts[pi], fParts[fi])
	return err == nil && matched && matchLintMemo(pParts, fParts, pi+1, fi+1)
}
