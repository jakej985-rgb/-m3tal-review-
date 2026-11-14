package cli

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis/pipeline"
)

func TestParseReviewOptionsSemantic(t *testing.T) {
	opts, err := parseReviewOptions([]string{
		"--semantic",
		"--semantic-analyzers", "typestate,concurrency",
		"--semantic-contracts", "contracts",
		"--semantic-max-parallel", "2",
		"--semantic-timeout", "5m",
		"--semantic-depth", "deep",
		"--semantic-tests",
	})
	if err != nil {
		t.Fatalf("parseReviewOptions: %v", err)
	}
	if !opts.Semantic.Enabled {
		t.Fatal("Semantic.Enabled = false, want true")
	}
	if len(opts.Semantic.Analyzers) != 2 || opts.Semantic.Analyzers[0] != "typestate" {
		t.Fatalf("Analyzers = %v", opts.Semantic.Analyzers)
	}
	if opts.Semantic.ContractDir != "contracts" {
		t.Fatalf("ContractDir = %q", opts.Semantic.ContractDir)
	}
	if opts.Semantic.MaxParallel != 2 {
		t.Fatalf("MaxParallel = %d", opts.Semantic.MaxParallel)
	}
	if opts.Semantic.Timeout.String() != "5m0s" {
		t.Fatalf("Timeout = %v", opts.Semantic.Timeout)
	}
	if opts.Semantic.Depth != "deep" {
		t.Fatalf("Depth = %q", opts.Semantic.Depth)
	}
	if !opts.Semantic.Tests {
		t.Fatal("Tests = false, want true")
	}

	popts := opts.Semantic.pipelineOptions("/repo")
	if popts == nil || popts.Dir != "/repo" {
		t.Fatalf("pipelineOptions = %+v", popts)
	}
	if popts.AnalyzerTimeout.String() != "5m0s" || popts.Depth != pipeline.DepthDeep {
		t.Fatalf("pipeline options not propagated: %+v", popts)
	}
}

func TestParseReviewOptionsSemanticDisabledByDefault(t *testing.T) {
	opts, err := parseReviewOptions(nil)
	if err != nil {
		t.Fatalf("parseReviewOptions: %v", err)
	}
	if opts.Semantic.Enabled {
		t.Fatal("semantic must be opt-in")
	}
	if opts.Semantic.pipelineOptions("/repo") != nil {
		t.Fatal("pipelineOptions must be nil when disabled")
	}
	opts2, err := parseReviewOptions([]string{"--no-semantic"})
	if err != nil {
		t.Fatalf("parseReviewOptions --no-semantic: %v", err)
	}
	if opts2.Semantic.pipelineOptions("/repo") != nil {
		t.Fatal("--no-semantic must disable the pipeline")
	}
}

func TestParseReviewOptionsSemanticValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--semantic-analyzers", "bogus"},
		{"--semantic-depth", "extreme"},
		{"--semantic-max-parallel", "0"},
		{"--semantic-timeout", "soon"},
	} {
		if _, err := parseReviewOptions(args); err == nil {
			t.Fatalf("parseReviewOptions(%v) expected error", args)
		}
	}
}

func TestParseAuditOptionsSemantic(t *testing.T) {
	opts, err := parseAuditOptions([]string{
		"--semantic",
		"--semantic-analyzers=flow,protocol",
		"--semantic-depth=standard",
	})
	if err != nil {
		t.Fatalf("parseAuditOptions: %v", err)
	}
	if !opts.Semantic.Enabled {
		t.Fatal("Semantic.Enabled = false")
	}
	if len(opts.Semantic.Analyzers) != 2 || opts.Semantic.Analyzers[1] != "protocol" {
		t.Fatalf("Analyzers = %v", opts.Semantic.Analyzers)
	}
	if opts.Semantic.Depth != "standard" {
		t.Fatalf("Depth = %q", opts.Semantic.Depth)
	}
}

func TestApplySemanticUserConfig(t *testing.T) {
	cfg := userConfig{
		Semantic: &semanticUserConfig{
			Enabled:     true,
			Analyzers:   []string{"concurrency"},
			ContractDir: "contracts",
			MaxParallel: 3,
			Timeout:     "2m",
			Depth:       "deep",
			Tests:       true,
		},
	}
	options := reviewOptions{seen: map[string]bool{}}
	if err := applyUserConfig(&options, cfg); err != nil {
		t.Fatalf("applyUserConfig: %v", err)
	}
	s := options.Semantic
	if !s.Enabled || len(s.Analyzers) != 1 || s.ContractDir != "contracts" ||
		s.MaxParallel != 3 || s.Timeout.String() != "2m0s" || s.Depth != "deep" || !s.Tests {
		t.Fatalf("semantic config not applied: %+v", s)
	}

	// Flags override config.
	options2 := reviewOptions{seen: map[string]bool{"--semantic-depth": true, "--semantic-analyzers": true}}
	options2.Semantic.Depth = "standard"
	options2.Semantic.Analyzers = []string{"flow"}
	if err := applyUserConfig(&options2, cfg); err != nil {
		t.Fatalf("applyUserConfig: %v", err)
	}
	if options2.Semantic.Depth != "standard" || options2.Semantic.Analyzers[0] != "flow" {
		t.Fatalf("flags should override config: %+v", options2.Semantic)
	}

	// Invalid config values are errors.
	bad := userConfig{Semantic: &semanticUserConfig{Analyzers: []string{"bogus"}}}
	if err := applyUserConfig(&reviewOptions{seen: map[string]bool{}}, bad); err == nil {
		t.Fatal("expected error for invalid semantic.analyzers")
	}
	badTimeout := userConfig{Semantic: &semanticUserConfig{Timeout: "later"}}
	if err := applyUserConfig(&reviewOptions{seen: map[string]bool{}}, badTimeout); err == nil {
		t.Fatal("expected error for invalid semantic.timeout")
	}
}

func TestRunSemanticPipelineE2E(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	repoRoot := filepath.Join("..", "..", "internal", "analysis", "pipeline", "testdata", "e2e")
	abs, err := filepath.Abs(repoRoot)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	findings, checks, section := runSemanticPipeline(RunnerConfig{
		RepositoryRoot: abs,
		Context:        context.Background(),
		Semantic: &pipeline.Options{
			Dir:       abs,
			Analyzers: []string{pipeline.AnalyzerTypeState, pipeline.AnalyzerConcurrency},
		},
	})
	if section == nil {
		t.Fatal("expected an analysis section")
	}
	if section.Status == "failed" {
		t.Fatalf("analysis section failed: %+v", section)
	}
	var sawSemantic bool
	for _, f := range findings {
		if f.Category == "semantic" {
			sawSemantic = true
			if f.Rule != "typestate-double-consume" {
				t.Fatalf("unexpected semantic rule %q", f.Rule)
			}
			// Paths must be repository-relative, not absolute.
			if filepath.IsAbs(f.File) {
				t.Fatalf("semantic finding file is absolute: %q", f.File)
			}
		}
	}
	if !sawSemantic {
		t.Fatal("expected a semantic-category finding from typestate")
	}
	if len(checks) == 0 {
		t.Fatal("expected per-analyzer check results")
	}
	for _, c := range checks {
		if c.Category != "semantic" {
			t.Fatalf("check category = %q, want semantic", c.Category)
		}
	}
}
