package review

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// LintConfig configures repository linting profiles, analyzers, exclusions, and tool paths.
type LintConfig struct {
	Profile    string            `json:"profile,omitempty"`
	Analyzers  []string          `json:"analyzers,omitempty"`
	Exclusions []string          `json:"exclusions,omitempty"`
	Exclude    []string          `json:"exclude,omitempty"`
	Scope      string            `json:"scope,omitempty"`
	ToolPaths  map[string]string `json:"tool_paths,omitempty"`
	Tools      map[string]string `json:"tools,omitempty"`
}

// EffectiveExclusions returns merged exclusions list.
func (c *LintConfig) EffectiveExclusions() []string {
	if c == nil {
		return nil
	}
	var res []string
	res = append(res, c.Exclusions...)
	res = append(res, c.Exclude...)
	return res
}

// EffectiveAnalyzers returns the list of analyzers based on profile or explicit list.
func (c *LintConfig) EffectiveAnalyzers() []string {
	if c != nil && len(c.Analyzers) > 0 {
		return c.Analyzers
	}
	profile := "fast"
	if c != nil && c.Profile != "" {
		profile = strings.ToLower(c.Profile)
	}
	switch profile {
	case "full":
		return []string{"gofmt", "govet", "staticcheck"}
	case "strict":
		return []string{"gofmt", "govet", "staticcheck", "golangci-lint"}
	case "fast", "default", "":
		return []string{"gofmt", "govet"}
	default:
		return []string{"gofmt", "govet"}
	}
}

// ResolveToolExecutable resolves the executable path for a given analyzer.
func (c *LintConfig) ResolveToolExecutable(name string) (string, error) {
	if c != nil {
		if path, ok := c.ToolPaths[name]; ok && path != "" {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			} else {
				return "", fmt.Errorf("configured path for %s does not exist: %w", name, err)
			}
		}
		if path, ok := c.Tools[name]; ok && path != "" {
			if _, err := os.Stat(path); err == nil {
				return path, nil
			} else {
				return "", fmt.Errorf("configured path for %s does not exist: %w", name, err)
			}
		}
	}

	execName := name
	if name == "govet" {
		execName = "go"
	}
	return exec.LookPath(execName)
}

type LintRule struct {
	RepositoryRoot string
	Config         *LintConfig
}

var (
	vetDiagnosticPattern         = regexp.MustCompile(`^(?:vet: )?(.+?):(\d+):(\d+): (.+)$`)
	staticcheckDiagnosticPattern = regexp.MustCompile(`^(.+?):(\d+):(\d+): (.+)$`)
	golangciDiagnosticPattern    = regexp.MustCompile(`^(.+?):(\d+)(?::(\d+))?: (.+)$`)
)

func (LintRule) Name() string {
	return "repository-lint"
}

func (r LintRule) Check(_ string) []Finding {
	var findings []Finding

	if r.RepositoryRoot == "" {
		return []Finding{{
			Rule:        r.Name(),
			Severity:    "high",
			Message:     "Repository root is not configured for lint checks",
			Remediation: "Configure the lint rule with a valid repository root.",
		}}
	}

	cfg := r.Config
	if cfg == nil {
		loadedCfg, _ := ReadLintConfig(r.RepositoryRoot, true)
		cfg = loadedCfg
	}

	exclusions := cfg.EffectiveExclusions()
	analyzers := cfg.EffectiveAnalyzers()

	for _, analyzer := range analyzers {
		normAnalyzer := strings.ToLower(strings.TrimSpace(analyzer))
		switch normAnalyzer {
		case "gofmt":
			execPath, err := cfg.ResolveToolExecutable("gofmt")
			if err != nil {
				findings = append(findings, Finding{
					Rule:        r.Name(),
					Severity:    "high",
					Message:     fmt.Sprintf("gofmt is unavailable: %s", err.Error()),
					Remediation: "Ensure gofmt is installed and available on PATH.",
				})
				continue
			}

			formatCmd := exec.Command(execPath, "-l", ".")
			formatCmd.Dir = r.RepositoryRoot

			formatOutput, formatErr := formatCmd.CombinedOutput()
			if formatErr != nil {
				findings = append(findings, Finding{
					Rule:        r.Name(),
					Severity:    "high",
					Message:     "gofmt execution failed: " + strings.TrimSpace(string(formatOutput)),
					Remediation: "Fix gofmt errors and run gofmt manually to verify.",
				})
			} else {
				for _, file := range strings.Split(strings.TrimSpace(string(formatOutput)), "\n") {
					if file == "" {
						continue
					}
					cleanFile := filepath.ToSlash(file)
					if isPathExcluded(cleanFile, exclusions) {
						continue
					}

					findings = append(findings, Finding{
						Rule:        r.Name(),
						Severity:    "medium",
						File:        cleanFile,
						Message:     "File is not formatted; run gofmt",
						Remediation: "Run 'gofmt -w .' to format the code.",
					})
				}
			}

		case "govet", "go vet", "vet":
			execPath, err := cfg.ResolveToolExecutable("govet")
			if err != nil {
				findings = append(findings, Finding{
					Rule:        r.Name(),
					Severity:    "high",
					Message:     fmt.Sprintf("go vet is unavailable: %s", err.Error()),
					Remediation: "Ensure go is installed and available on PATH.",
				})
				continue
			}

			scope := "./..."
			if cfg != nil && cfg.Scope != "" {
				scope = cfg.Scope
			}

			vetCmd := exec.Command(execPath, "vet", scope)
			vetCmd.Dir = r.RepositoryRoot

			vetOutput, vetErr := vetCmd.CombinedOutput()
			if vetErr != nil {
				parsed := false

				for _, line := range strings.Split(string(vetOutput), "\n") {
					line = strings.TrimSpace(line)
					match := vetDiagnosticPattern.FindStringSubmatch(line)
					if match == nil {
						continue
					}

					file := filepath.ToSlash(strings.TrimPrefix(match[1], "./"))
					if isPathExcluded(file, exclusions) {
						parsed = true
						continue
					}

					lineNumber, err := parsePositiveInt(match[2])
					if err != nil {
						continue
					}

					findings = append(findings, Finding{
						Rule:        r.Name(),
						Severity:    "high",
						File:        file,
						Line:        lineNumber,
						Message:     "go vet: " + match[4],
						Remediation: "Fix the issue reported by go vet.",
					})
					parsed = true
				}

				if !parsed && len(vetOutput) > 0 {
					findings = append(findings, Finding{
						Rule:        r.Name(),
						Severity:    "high",
						Message:     "go vet failed: " + strings.TrimSpace(string(vetOutput)),
						Remediation: "Fix the build errors preventing go vet from running.",
					})
				}
			}

		case "staticcheck":
			execPath, err := cfg.ResolveToolExecutable("staticcheck")
			if err != nil {
				findings = append(findings, Finding{
					Rule:        r.Name(),
					Severity:    "high",
					Message:     fmt.Sprintf("staticcheck is unavailable: %s", err.Error()),
					Remediation: "Install staticcheck (go install honnef.co/go/tools/cmd/staticcheck@latest) or adjust lint profile.",
				})
				continue
			}

			scope := "./..."
			if cfg != nil && cfg.Scope != "" {
				scope = cfg.Scope
			}

			scCmd := exec.Command(execPath, scope)
			scCmd.Dir = r.RepositoryRoot

			scOutput, scErr := scCmd.CombinedOutput()
			if scErr != nil {
				for _, line := range strings.Split(string(scOutput), "\n") {
					line = strings.TrimSpace(line)
					match := staticcheckDiagnosticPattern.FindStringSubmatch(line)
					if match == nil {
						continue
					}

					file := filepath.ToSlash(strings.TrimPrefix(match[1], "./"))
					if isPathExcluded(file, exclusions) {
						continue
					}

					lineNum, _ := parsePositiveInt(match[2])
					findings = append(findings, Finding{
						Rule:        r.Name(),
						Severity:    "high",
						File:        file,
						Line:        lineNum,
						Message:     "staticcheck: " + match[4],
						Remediation: "Fix the issue reported by staticcheck.",
					})
				}
			}

		case "golangci-lint", "golangci":
			execPath, err := cfg.ResolveToolExecutable("golangci-lint")
			if err != nil {
				findings = append(findings, Finding{
					Rule:        r.Name(),
					Severity:    "high",
					Message:     fmt.Sprintf("golangci-lint is unavailable: %s", err.Error()),
					Remediation: "Install golangci-lint or adjust lint profile.",
				})
				continue
			}

			scope := "./..."
			if cfg != nil && cfg.Scope != "" {
				scope = cfg.Scope
			}

			gclCmd := exec.Command(execPath, "run", scope)
			gclCmd.Dir = r.RepositoryRoot

			gclOutput, gclErr := gclCmd.CombinedOutput()
			if gclErr != nil {
				for _, line := range strings.Split(string(gclOutput), "\n") {
					line = strings.TrimSpace(line)
					match := golangciDiagnosticPattern.FindStringSubmatch(line)
					if match == nil {
						continue
					}

					file := filepath.ToSlash(strings.TrimPrefix(match[1], "./"))
					if isPathExcluded(file, exclusions) {
						continue
					}

					lineNum, _ := parsePositiveInt(match[2])
					findings = append(findings, Finding{
						Rule:        r.Name(),
						Severity:    "high",
						File:        file,
						Line:        lineNum,
						Message:     "golangci-lint: " + match[4],
						Remediation: "Fix the issue reported by golangci-lint.",
					})
				}
			}

		default:
			// Custom analyzer
			execPath, err := cfg.ResolveToolExecutable(analyzer)
			if err != nil {
				findings = append(findings, Finding{
					Rule:        r.Name(),
					Severity:    "high",
					Message:     fmt.Sprintf("analyzer %s is unavailable: %s", analyzer, err.Error()),
					Remediation: fmt.Sprintf("Install %s or check configured tool paths.", analyzer),
				})
				continue
			}

			customCmd := exec.Command(execPath)
			customCmd.Dir = r.RepositoryRoot
			if out, err := customCmd.CombinedOutput(); err != nil {
				findings = append(findings, Finding{
					Rule:        r.Name(),
					Severity:    "high",
					Message:     fmt.Sprintf("analyzer %s failed: %s", analyzer, strings.TrimSpace(string(out))),
					Remediation: fmt.Sprintf("Check %s configuration and fix reported errors.", analyzer),
				})
			}
		}
	}

	return findings
}

func isPathExcluded(file string, exclusions []string) bool {
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
		if matchesRepoPath(normPattern, normFile) {
			return true
		}
	}
	return false
}

// ReadLintConfig reads the lint configuration from .m3tal-review-config.json or .m3tal-review-policy.json.
func ReadLintConfig(repositoryRoot string, workingTree bool) (*LintConfig, error) {
	if repositoryRoot == "" {
		return &LintConfig{}, nil
	}

	var res LintConfig

	// 1. Check .m3tal-review-config.json
	cfgFile := filepath.Join(repositoryRoot, ".m3tal-review-config.json")
	if data, err := os.ReadFile(cfgFile); err == nil {
		var raw struct {
			Lint           *LintConfig       `json:"lint"`
			LintProfile    string            `json:"lint_profile"`
			LintExclusions []string          `json:"lint_exclusions"`
			LintAnalyzers  []string          `json:"lint_analyzers"`
			ToolPaths      map[string]string `json:"tool_paths"`
		}
		if err := json.Unmarshal(data, &raw); err == nil {
			if raw.Lint != nil {
				res = *raw.Lint
			}
			if raw.LintProfile != "" && res.Profile == "" {
				res.Profile = raw.LintProfile
			}
			if len(raw.LintExclusions) > 0 {
				res.Exclusions = append(res.Exclusions, raw.LintExclusions...)
			}
			if len(raw.LintAnalyzers) > 0 && len(res.Analyzers) == 0 {
				res.Analyzers = raw.LintAnalyzers
			}
			if len(raw.ToolPaths) > 0 {
				if res.ToolPaths == nil {
					res.ToolPaths = make(map[string]string)
				}
				for k, v := range raw.ToolPaths {
					if res.ToolPaths[k] == "" {
						res.ToolPaths[k] = v
					}
				}
			}
		}
	}

	// 2. Check .m3tal-review-policy.json
	policy, err := readReviewPolicy(repositoryRoot, workingTree)
	if err == nil && policy.Lint != nil {
		if res.Profile == "" && policy.Lint.Profile != "" {
			res.Profile = policy.Lint.Profile
		}
		if len(res.Analyzers) == 0 && len(policy.Lint.Analyzers) > 0 {
			res.Analyzers = policy.Lint.Analyzers
		}
		res.Exclusions = append(res.Exclusions, policy.Lint.Exclusions...)
		res.Exclude = append(res.Exclude, policy.Lint.Exclude...)
		if policy.Lint.Scope != "" && res.Scope == "" {
			res.Scope = policy.Lint.Scope
		}
		if len(policy.Lint.ToolPaths) > 0 {
			if res.ToolPaths == nil {
				res.ToolPaths = make(map[string]string)
			}
			for k, v := range policy.Lint.ToolPaths {
				if res.ToolPaths[k] == "" {
					res.ToolPaths[k] = v
				}
			}
		}
	}

	return &res, nil
}

func parsePositiveInt(value string) (int, error) {
	var number int
	_, err := fmt.Sscanf(value, "%d", &number)
	return number, err
}
