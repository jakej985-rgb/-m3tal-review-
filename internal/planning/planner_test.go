package planning

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/detection/buildsystem"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/framework"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/language"
	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
)

func TestBuildPlanMixedLanguageRepository(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/app\n")
	writeFile(t, filepath.Join(root, "cmd", "api", "main.go"), "package main\n")
	writeFile(t, filepath.Join(root, "mobile", "pubspec.yaml"), "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n")
	writeFile(t, filepath.Join(root, "mobile", "lib", "main.dart"), "void main() {}\n")
	writeFile(t, filepath.Join(root, "web", "package.json"), `{"dependencies":{"react":"^18.0.0"}}`)
	writeFile(t, filepath.Join(root, "web", "src", "app.ts"), "export const x = 1;\n")
	writeFile(t, filepath.Join(root, "scripts", "prep.py"), "print(1)\n")
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.19\n")
	writeFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "on: push\n")

	inv, err := scanner.Scan(root, scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	det := language.Detect(inv, language.DetectConfig{})
	fws := framework.Detect(inv)
	bs := buildsystem.Detect(inv)

	plan := BuildPlan(det, fws, bs, PlanConfig{Profile: "security"}, DefaultAnalyzers())

	selected := make(map[string]bool, len(plan.Selected))
	for _, s := range plan.Selected {
		selected[s.Analyzer.ID] = true
	}

	for _, want := range []string{"lang-go", "lang-dart", "lang-ts", "lang-python", "fw-flutter", "fw-react", "infra-docker", "infra-gha", "cross-security", "semantic-go"} {
		if !selected[want] {
			t.Errorf("expected %s to be selected; selected=%+v", want, plan.Selected)
		}
	}
	for _, unwant := range []string{"lang-rust", "lang-java", "fw-android", "infra-terraform"} {
		if selected[unwant] {
			t.Errorf("did not expect %s to be selected", unwant)
		}
	}
	if plan.SemanticSupport["Go"] != "supported" {
		t.Errorf("expected Go semantic support = supported, got %q", plan.SemanticSupport["Go"])
	}
	if plan.SemanticSupport["Dart"] != "pending" {
		t.Errorf("expected Dart semantic support = pending, got %q", plan.SemanticSupport["Dart"])
	}

	// Verify --language filter limits selection without altering detection.
	filtered := BuildPlan(det, fws, bs, PlanConfig{Profile: "fast", LanguageFilter: []string{"go"}}, DefaultAnalyzers())
	for _, s := range filtered.Selected {
		if s.Analyzer.ID == "lang-python" || s.Analyzer.ID == "lang-ts" {
			t.Errorf("expected --language go to exclude %s", s.Analyzer.ID)
		}
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
