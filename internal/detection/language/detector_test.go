package language

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
)

func TestMultiEvidenceLanguageDetection(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module example.com/mix\n")
	writeFile(t, filepath.Join(root, "main.go"), "package main\n")
	writeFile(t, filepath.Join(root, "scripts", "run"), "#!/usr/bin/env python3\nprint('hi')\n")
	writeFile(t, filepath.Join(root, "include", "ambig.h"), "int x;\n")
	writeFile(t, filepath.Join(root, "include", "cpp.h"), "#pragma once\nnamespace demo { class A {}; }\n")
	writeFile(t, filepath.Join(root, "Dockerfile"), "FROM alpine:3.19\n")
	writeFile(t, filepath.Join(root, "data.xyz"), "opaque\n")
	writeFile(t, filepath.Join(root, ".github", "workflows", "ci.yml"), "jobs:\n  test:\n    steps:\n      - run: echo hi\n")

	inv, err := scanner.Scan(root, scanner.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	det := Detect(inv, DetectConfig{
		Overrides: map[string]string{".xyz": "CustomDSL"},
	})

	byPath := make(map[string]FileDetection, len(det.Files))
	for _, f := range det.Files {
		byPath[f.Path] = f
	}

	if got := byPath["main.go"]; got.Status != Detected || got.Language != "Go" || got.Confidence < 0.95 {
		t.Errorf("unexpected main.go detection: %+v", got)
	}
	if got := byPath["scripts/run"]; got.Status != Detected || got.Language != "Python" {
		t.Errorf("expected shebang Python for scripts/run, got %+v", got)
	}
	if got := byPath["include/ambig.h"]; got.Status != Ambiguous {
		t.Errorf("expected ambiguous .h header, got %+v", got)
	}
	if got := byPath["include/cpp.h"]; got.Status != Detected || got.Language != "C++" {
		t.Errorf("expected C++ content detection for include/cpp.h, got %+v", got)
	}
	if got := byPath["Dockerfile"]; got.Status != Detected || got.Language != "Dockerfile" {
		t.Errorf("expected Dockerfile detection, got %+v", got)
	}
	if got := byPath["data.xyz"]; got.Status != Detected || got.Language != "CustomDSL" {
		t.Errorf("expected explicit override for data.xyz, got %+v", got)
	}
	if got := byPath[".github/workflows/ci.yml"]; len(got.SecondaryLanguages) == 0 || got.SecondaryLanguages[0] != "Shell" {
		t.Errorf("expected secondary Shell language in workflow, got %+v", got)
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
