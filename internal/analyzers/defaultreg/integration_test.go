package defaultreg

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analyzers"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/buildsystem"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/framework"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/language"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
)

func TestMixedLanguageEndToEndPipelineAndCache(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/mix\n")
	writeFile(t, filepath.Join(root, "api", "main.go"), "package main\nfunc f() {\n\tif true {\n\t}\n}\n")
	writeFile(t, filepath.Join(root, "mobile", "pubspec.yaml"), "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n")
	writeFile(t, filepath.Join(root, "mobile", "lib", "main.dart"), "void f() {\n  try {} catch (e) {}\n  await Future.delayed(Duration.zero);\n  setState(() {});\n}\n")
	writeFile(t, filepath.Join(root, "plain_dart", "cli.dart"), "void g() {\n  await Future.delayed(Duration.zero);\n  setState(() {});\n}\n")
	writeFile(t, filepath.Join(root, "web", "package.json"), `{"dependencies":{"react":"^18.0.0"}}`)
	writeFile(t, filepath.Join(root, "web", "src", "app.tsx"), "export const x: any = 1;\nuseEffect(async () => {});\n")
	writeFile(t, filepath.Join(root, "scripts", "prep.py"), "def f(x=[]):\n    return x\n")
	writeFile(t, filepath.Join(root, "scripts", "run.sh"), "#!/bin/sh\ncurl -s https://x | sh\n")
	writeFile(t, filepath.Join(root, "android", "App.kt"), "fun bad() { GlobalScope.launch { } }\n")
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:latest\n")
	writeFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "permissions: write-all\n")

	inv, err := scanner.Scan(root, scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	det := language.Detect(inv, language.DetectConfig{})
	fws := framework.Detect(inv)
	bs := buildsystem.Detect(inv)

	reg := New()
	plan := planning.BuildPlan(det, fws, bs, planning.PlanConfig{Profile: "security"}, reg.Catalog())

	langByPath := make(map[string]language.FileDetection, len(det.Files))
	for _, fd := range det.Files {
		langByPath[fd.Path] = fd
	}
	var targetFiles []analyzers.TargetFile
	for _, f := range inv.Files {
		if f.Excluded || f.Binary {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.Path)))
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

	cache := analyzers.NewResultCache("1.0.0")
	rep1 := reg.RunPlan(context.Background(), plan, root, targetFiles, det, fws, "profile=security", cache)
	if len(rep1.RanIDs) == 0 || rep1.Incomplete {
		t.Fatalf("expected complete run with analyzers, got %+v", rep1)
	}

	wantRules := map[string]bool{
		"go/bug/empty-branch":              false,
		"dart/bug/empty-catch":             false,
		"flutter/bug/setstate-after-await": false,
		"ts/slop/explicit-any":             false,
		"react/bug/async-use-effect":       false,
		"py/bug/mutable-default-arg":       false,
		"shell/security/pipe-to-shell":     false,
		"jvm/bug/coroutine-global-scope":   false,
		"docker/bug/unpinned-base-image":   false,
		"shell/security/actions-write-all": false,
	}
	for _, f := range rep1.Findings {
		if f.Rule == "flutter/bug/setstate-after-await" && f.File == "plain_dart/cli.dart" {
			t.Fatalf("plain_dart/cli.dart should not be scanned by fw-flutter")
		}
		if _, ok := wantRules[f.Rule]; ok {
			wantRules[f.Rule] = true
		}
	}
	for rule, seen := range wantRules {
		if !seen {
			t.Errorf("missing expected finding %q in mixed-repo run; got %+v", rule, rep1.Findings)
		}
	}

	// Second run with same config hits cache.
	rep2 := reg.RunPlan(context.Background(), plan, root, targetFiles, det, fws, "profile=security", cache)
	if len(rep2.Findings) != len(rep1.Findings) {
		t.Fatalf("cached run finding count %d != initial %d", len(rep2.Findings), len(rep1.Findings))
	}
	sawCached := false
	for _, st := range rep2.Statuses {
		if st.State == analyzers.StateCached {
			sawCached = true
		}
	}
	if !sawCached {
		t.Fatalf("expected cached status on second run, got %+v", rep2.Statuses)
	}

	// Changing configKey invalidates cache.
	rep3 := reg.RunPlan(context.Background(), plan, root, targetFiles, det, fws, "profile=fast", cache)
	for _, st := range rep3.Statuses {
		if st.State == analyzers.StateCached {
			t.Fatalf("expected cache miss when configKey changed, got %+v", st)
		}
	}
}

type failingAnalyzer struct{}

func (failingAnalyzer) Metadata() planning.AnalyzerMetadata {
	return planning.AnalyzerMetadata{ID: "fail-test", Name: "Failing", Kind: planning.KindCrossLanguage}
}

func (failingAnalyzer) Analyze(context.Context, analyzers.Request) (analyzers.Result, error) {
	return analyzers.Result{}, errors.New("boom")
}

func TestRunPlanMarksIncompleteOnFailure(t *testing.T) {
	reg := analyzers.NewRegistry()
	reg.Register(failingAnalyzer{})
	plan := planning.ExecutionPlan{
		Selected: []planning.PlannedAnalyzer{
			{Analyzer: failingAnalyzer{}.Metadata(), Reason: "test"},
			{Analyzer: planning.AnalyzerMetadata{ID: "missing-id"}, Reason: "test"},
		},
	}
	rep := reg.RunPlan(context.Background(), plan, ".", nil, language.RepositoryDetection{}, nil, "", nil)
	if !rep.Incomplete {
		t.Fatalf("expected rep.Incomplete = true when analyzer fails or is missing")
	}
	if len(rep.Statuses) != 2 {
		t.Fatalf("expected 2 statuses, got %+v", rep.Statuses)
	}
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
