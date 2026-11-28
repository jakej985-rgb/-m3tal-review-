package framework

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
)

func TestDetectFrameworksAndInfrastructure(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "pubspec.yaml"), "name: app\ndependencies:\n  flutter:\n    sdk: flutter\n")
	mustWrite(t, filepath.Join(root, "web", "package.json"), `{"dependencies":{"react":"^18.0.0","next":"^14.0.0"}}`)
	mustWrite(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.19\n")
	mustWrite(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "on: push\n")
	mustWrite(t, filepath.Join(root, "infra", "main.tf"), "resource \"aws_s3_bucket\" \"b\" {}\n")

	inv, err := scanner.Scan(root, scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	got := Detect(inv)
	seen := make(map[string]bool, len(got))
	for _, f := range got {
		seen[f.Name] = true
	}
	for _, want := range []string{"Flutter", "React", "Next.js", "Docker", "GitHub Actions", "Terraform"} {
		if !seen[want] {
			t.Errorf("expected %s to be detected, got %+v", want, got)
		}
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
