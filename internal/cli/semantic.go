package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis/pipeline"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// semanticCLIOptions carries the --semantic* flag state shared by the
// review and audit commands. Semantic analysis is strictly opt-in:
// Enabled stays false unless --semantic or config semantic.enabled
// is set.
type semanticCLIOptions struct {
	Enabled     bool
	Analyzers   []string
	ContractDir string
	MaxParallel int
	Timeout     time.Duration
	Depth       string
	Tests       bool
}

// parseSemanticFlag handles one --semantic* argument. It returns
// handled=false when arg is not a semantic flag. next yields the flag
// value, either from an inline "--flag=value" payload or the following
// argv element.
func (s *semanticCLIOptions) parseSemanticFlag(arg string, next func() (string, error)) (bool, error) {
	switch arg {
	case "--semantic":
		s.Enabled = true
		return true, nil
	case "--no-semantic":
		s.Enabled = false
		return true, nil
	case "--semantic-analyzers":
		v, err := next()
		if err != nil {
			return true, err
		}
		names := splitRuleList(v)
		for _, n := range names {
			if !pipeline.ValidAnalyzerName(n) {
				return true, fmt.Errorf("invalid --semantic-analyzers entry %q; valid: %s", n, strings.Join(pipeline.KnownAnalyzers(), ", "))
			}
		}
		s.Analyzers = names
		return true, nil
	case "--semantic-contracts":
		v, err := next()
		if err != nil {
			return true, err
		}
		s.ContractDir = v
		return true, nil
	case "--semantic-max-parallel":
		v, err := next()
		if err != nil {
			return true, err
		}
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return true, fmt.Errorf("invalid --semantic-max-parallel %q; expected a positive integer", v)
		}
		s.MaxParallel = n
		return true, nil
	case "--semantic-timeout":
		v, err := next()
		if err != nil {
			return true, err
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return true, fmt.Errorf("invalid --semantic-timeout %q; expected a positive Go duration (e.g. 10m)", v)
		}
		s.Timeout = d
		return true, nil
	case "--semantic-depth":
		v, err := next()
		if err != nil {
			return true, err
		}
		if v != "standard" && v != "deep" {
			return true, fmt.Errorf("invalid --semantic-depth %q; expected standard or deep", v)
		}
		s.Depth = v
		return true, nil
	case "--semantic-tests":
		s.Tests = true
		return true, nil
	}
	return false, nil
}

// pipelineOptions converts the flag state into pipeline.Options for
// the given repository root. Returns nil when semantic analysis is
// disabled.
func (s semanticCLIOptions) pipelineOptions(repositoryRoot string) *pipeline.Options {
	if !s.Enabled {
		return nil
	}
	opts := &pipeline.Options{
		Dir:             repositoryRoot,
		ContractDir:     s.ContractDir,
		Analyzers:       s.Analyzers,
		MaxParallel:     s.MaxParallel,
		AnalyzerTimeout: s.Timeout,
		Tests:           s.Tests,
	}
	if s.Depth != "" {
		opts.Depth = pipeline.Depth(s.Depth)
	}
	return opts
}

// semanticUserConfig is the userConfig.semantic JSON section.
type semanticUserConfig struct {
	Enabled     bool     `json:"enabled,omitempty"`
	Analyzers   []string `json:"analyzers,omitempty"`
	ContractDir string   `json:"contract_dir,omitempty"`
	MaxParallel int      `json:"max_parallel,omitempty"`
	Timeout     string   `json:"timeout,omitempty"`
	Depth       string   `json:"depth,omitempty"`
	Tests       bool     `json:"tests,omitempty"`
}

// applySemanticUserConfig fills semantic options the user did not set
// via flags. seen maps "--flag" -> explicitly passed.
func applySemanticUserConfig(s *semanticCLIOptions, cfg *semanticUserConfig, seen map[string]bool) error {
	if cfg == nil {
		return nil
	}
	if !seen["--semantic"] && !seen["--no-semantic"] && cfg.Enabled {
		s.Enabled = true
	}
	if !seen["--semantic-analyzers"] && len(cfg.Analyzers) > 0 {
		for _, n := range cfg.Analyzers {
			if !pipeline.ValidAnalyzerName(n) {
				return fmt.Errorf("invalid config semantic.analyzers entry %q", n)
			}
		}
		s.Analyzers = cfg.Analyzers
	}
	if !seen["--semantic-contracts"] && cfg.ContractDir != "" {
		s.ContractDir = cfg.ContractDir
	}
	if !seen["--semantic-max-parallel"] && cfg.MaxParallel > 0 {
		s.MaxParallel = cfg.MaxParallel
	}
	if !seen["--semantic-timeout"] && cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		if err != nil || d <= 0 {
			return fmt.Errorf("invalid config semantic.timeout %q", cfg.Timeout)
		}
		s.Timeout = d
	}
	if !seen["--semantic-depth"] && cfg.Depth != "" {
		if cfg.Depth != "standard" && cfg.Depth != "deep" {
			return fmt.Errorf("invalid config semantic.depth %q", cfg.Depth)
		}
		s.Depth = cfg.Depth
	}
	if !seen["--semantic-tests"] && cfg.Tests {
		s.Tests = true
	}
	return nil
}

// runSemanticPipeline executes the semantic pipeline for a review or
// audit run. It returns the converted findings (category "semantic"),
// per-analyzer check results, and the report analysis section. A nil
// options disables the pipeline entirely.
func runSemanticPipeline(cfg RunnerConfig) ([]review.Finding, []review.CheckResult, *review.AnalysisSection) {
	if cfg.Semantic == nil {
		return nil, nil, nil
	}
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}
	res, err := pipeline.Run(ctx, *cfg.Semantic)
	if err != nil {
		// Option validation happens at the CLI boundary; a failure here
		// is reported as a check, never aborts the review.
		return nil, []review.CheckResult{{
			Name:     "semantic-pipeline",
			Category: "semantic",
			Status:   "error",
			Message:  err.Error(),
		}}, nil
	}

	findings := review.ReviewFindingsFromAnalysis(res.Findings, cfg.RepositoryRoot)
	checks := semanticCheckResults(res)
	return findings, checks, buildAnalysisSection(res)
}

// semanticCheckResults renders per-analyzer outcomes as report check
// entries so they appear alongside lint/tool/confidence checks.
func semanticCheckResults(res *pipeline.Result) []review.CheckResult {
	checks := make([]review.CheckResult, 0, len(res.Analyzers)+1)
	if res.LoadError != "" {
		checks = append(checks, review.CheckResult{
			Name:     "semantic-frontend",
			Category: "semantic",
			Status:   "failed",
			Message:  res.LoadError,
		})
	}
	for _, a := range res.Analyzers {
		status := "passed"
		switch a.Status {
		case "skipped":
			status = "skipped"
		case "failed", "timeout":
			status = "failed"
		}
		msg := a.Message
		if a.Truncated {
			if msg != "" {
				msg += "; "
			}
			msg += "analysis truncated by budget"
		}
		checks = append(checks, review.CheckResult{
			Name:     "semantic:" + a.Name,
			Category: "semantic",
			Status:   status,
			Message:  msg,
		})
	}
	return checks
}

// buildAnalysisSection converts the pipeline result into the report's
// analysis section, deriving an honest overall status.
func buildAnalysisSection(res *pipeline.Result) *review.AnalysisSection {
	section := &review.AnalysisSection{
		LoadError:   res.LoadError,
		Truncated:   res.Truncated,
		Diagnostics: res.Diagnostics,
	}
	if res.Program != nil {
		section.Program = &review.AnalysisProgramSummary{
			Packages:  res.Program.Packages,
			Functions: res.Program.Functions,
			Values:    res.Program.Values,
			RootDir:   res.Program.RootDir,
		}
	}
	section.Analyzers = semanticCheckResults(res)

	switch {
	case res.LoadError != "":
		section.Status = "failed"
	case res.Truncated || hasFailedAnalyzer(res) || hasErrorDiagnostics(res):
		section.Status = "degraded"
	default:
		section.Status = "completed"
	}
	return section
}

func hasFailedAnalyzer(res *pipeline.Result) bool {
	for _, a := range res.Analyzers {
		if a.Status == "failed" || a.Status == "timeout" {
			return true
		}
	}
	return false
}

func hasErrorDiagnostics(res *pipeline.Result) bool {
	for _, d := range res.Diagnostics {
		if d.Severity == "error" {
			return true
		}
	}
	return false
}
