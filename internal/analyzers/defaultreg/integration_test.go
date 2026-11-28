package defaultreg

import (
	"context"
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
	writeFile(t, filepath.Join(root, "web", "package.json"), `{"dependencies":{"react":"^18.0.0"}}`)
	writeFile(t, filepath.Join(root, "web", "src", "app.tsx"), "export const x: any = 1;\nuseEffect(async () => {});\n")
	writeFile(t, filepath.Join(root, "scripts", "prep.py"), "def f(x=[]):\n    return x\n")
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
		if f.Excluded {
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
	findings1, ran1 := reg.RunPlan(context.Background(), plan, root, targetFiles, det, cache)
	if len(ran1) == 0 {
		t.Fatalf("expected analyzers to run")
	}

	wantRules := map[string]bool{
		"go/bug/empty-branch":              false,
		"dart/bug/empty-catch":             false,
		"flutter/bug/setstate-after-await": false,
		"ts/slop/explicit-any":             false,
		"react/bug/async-use-effect":       false,
		"py/bug/mutable-default-arg":       false,
		"docker/bug/unpinned-base-image":   false,
		"shell/security/actions-write-all": false,
	}
	for _, f := range findings1 {
		if _, ok := wantRules[f.Rule]; ok {
			wantRules[f.Rule] = true
		}
	}
	for rule, seen := range wantRules {
		if !seen {
			t.Errorf("missing expected finding %q in mixed-repo run; got %+v", rule, findings1)
		}
	}

	// Second run with populated cache must return identical findings.
	findings2, _ := reg.RunPlan(context.Background(), plan, root, targetFiles, det, cache)
	if len(findings2) != len(findings1) {
		t.Fatalf("cached run finding count %d != initial %d", len(findings2), len(findings1))
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
