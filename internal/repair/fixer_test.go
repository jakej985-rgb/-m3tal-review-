package repair

import (
	"context"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestAllowlistedFixersRegistry(t *testing.T) {
	fixers := AllowlistedFixers()
	if len(fixers) < 5 {
		t.Fatalf("expected at least 5 allowlisted fixers, got %d", len(fixers))
	}

	expectedNames := []string{
		"trailing-whitespace-fixer",
		"redundant-bool-fixer",
		"gofmt-fixer",
		"world-writable-file-mode-fixer",
		"debug-leftover-fixer",
	}

	for _, name := range expectedNames {
		if !IsAllowlistedFixer(name) {
			t.Errorf("expected fixer %q to be allowlisted", name)
		}
	}

	if IsAllowlistedFixer("arbitrary-unsafe-fixer") {
		t.Error("unexpected fixer accepted as allowlisted")
	}
}

func TestTrailingWhitespaceFixer(t *testing.T) {
	fixer := TrailingWhitespaceFixer{}
	f := review.Finding{
		Rule:    "code-slop",
		File:    "clean.go",
		Message: "Trailing whitespace detected",
	}

	if !fixer.CanFix(f) {
		t.Fatal("expected TrailingWhitespaceFixer to match finding")
	}

	content := "func main() {   \n\tval := 1\t\t\n}\n"
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prop == nil {
		t.Fatal("expected proposal to be generated")
	}

	expected := "func main() {\n\tval := 1\n}\n"
	if prop.ProposedContent != expected {
		t.Errorf("got %q, want %q", prop.ProposedContent, expected)
	}

	// No-op case: content is already clean
	propClean, err := fixer.GenerateProposal(context.Background(), "", f, []byte(expected))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if propClean != nil {
		t.Errorf("expected nil proposal for already clean content, got %+v", propClean)
	}
}

func TestRedundantBoolFixer(t *testing.T) {
	fixer := RedundantBoolFixer{}
	f := review.Finding{
		Rule:    "code-slop",
		File:    "eval.go",
		Line:    2,
		Message: "Redundant boolean comparison",
	}

	if !fixer.CanFix(f) {
		t.Fatal("expected RedundantBoolFixer to match finding")
	}

	content := "func check(isValid bool) bool {\n\tif isValid == true {\n\t\treturn true\n\t}\n\treturn false\n}\n"
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prop == nil {
		t.Fatal("expected proposal to be generated")
	}

	expected := "func check(isValid bool) bool {\n\tif isValid {\n\t\treturn true\n\t}\n\treturn false\n}\n"
	if prop.ProposedContent != expected {
		t.Errorf("got %q, want %q", prop.ProposedContent, expected)
	}
}

func TestGoFmtFixer(t *testing.T) {
	fixer := GoFmtFixer{}
	f := review.Finding{
		Rule:    "confidence-gofmt",
		File:    "unformatted.go",
		Message: "File is not formatted; run gofmt",
	}

	if !fixer.CanFix(f) {
		t.Fatal("expected GoFmtFixer to match finding")
	}

	unformatted := "package main\n\nfunc main(){\nvar a=1\n_ =a\n}\n"
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(unformatted))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prop == nil {
		t.Fatal("expected proposal to be generated")
	}

	if !strings.Contains(prop.ProposedContent, "var a = 1") {
		t.Errorf("expected canonical spacing, got %q", prop.ProposedContent)
	}
}

func TestWorldWritableFileModeFixer(t *testing.T) {
	fixer := WorldWritableFileModeFixer{}
	f := review.Finding{
		Rule:    "world-writable-file-mode",
		File:    "io.go",
		Line:    3,
		Message: "File operation grants world-write permission",
	}

	if !fixer.CanFix(f) {
		t.Fatal("expected WorldWritableFileModeFixer to match finding")
	}

	content := "package io\nfunc Save() {\n\tos.WriteFile(\"out.txt\", data, 0777)\n}\n"
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prop == nil {
		t.Fatal("expected proposal to be generated")
	}

	expected := "package io\nfunc Save() {\n\tos.WriteFile(\"out.txt\", data, 0644)\n}\n"
	if prop.ProposedContent != expected {
		t.Errorf("got %q, want %q", prop.ProposedContent, expected)
	}

	// Test Mkdir directory mode
	contentDir := "package io\nfunc Make() {\n\tos.MkdirAll(\"out\", 0777)\n}\n"
	propDir, err := fixer.GenerateProposal(context.Background(), "", f, []byte(contentDir))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(propDir.ProposedContent, "0755") {
		t.Errorf("expected 0755 for directory, got %q", propDir.ProposedContent)
	}
}

func TestDebugLeftoverFixer(t *testing.T) {
	fixer := DebugLeftoverFixer{}
	f := review.Finding{
		Rule:    "debug-leftover",
		File:    "handler.go",
		Line:    3,
		Message: "Debug print statement detected",
	}

	if !fixer.CanFix(f) {
		t.Fatal("expected DebugLeftoverFixer to match finding")
	}

	content := "package handler\nfunc Handle() {\n\tfmt.Println(\"got request\")\n}\n"
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if prop == nil {
		t.Fatal("expected proposal to be generated")
	}

	expected := "package handler\nfunc Handle() {\n\t// fmt.Println(\"got request\")\n}\n"
	if prop.ProposedContent != expected {
		t.Errorf("got %q, want %q", prop.ProposedContent, expected)
	}

	// Python debug statement with # comment prefix
	fPy := review.Finding{
		Rule:    "debug-leftover",
		File:    "script.py",
		Line:    1,
		Message: "Debug print statement detected",
	}
	contentPy := "print(\"debugging python\")\n"
	propPy, err := fixer.GenerateProposal(context.Background(), "", fPy, []byte(contentPy))
	if err != nil {
		t.Fatal(err)
	}
	if propPy == nil || propPy.ProposedContent != "# print(\"debugging python\")\n" {
		t.Fatalf("expected python # comment prefix, got: %+v", propPy)
	}
}

func TestRedundantBoolFixerExtendedForms(t *testing.T) {
	fixer := RedundantBoolFixer{}
	f := review.Finding{
		Rule:    "code-slop",
		File:    "test.js",
		Message: "Redundant boolean comparison",
	}

	cases := []struct {
		input    string
		expected string
	}{
		{"if (x === true) {", "if (x) {"},
		{"if (y !== false) {", "if (y) {"},
		{"if (true == isReady) {", "if (isReady) {"},
		{"if (false == isReady) {", "if (!isReady) {"},
		{"if (flag != true) {", "if (!flag) {"},
	}

	for _, tc := range cases {
		prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(tc.input+"\n"))
		if err != nil {
			t.Fatalf("error for %q: %v", tc.input, err)
		}
		if prop == nil {
			t.Fatalf("expected proposal for %q", tc.input)
		}
		if strings.TrimSpace(prop.ProposedContent) != tc.expected {
			t.Errorf("for %q: got %q, want %q", tc.input, strings.TrimSpace(prop.ProposedContent), tc.expected)
		}
	}
}

func TestWorldWritableFileModeFixer0666(t *testing.T) {
	fixer := WorldWritableFileModeFixer{}
	f := review.Finding{
		Rule:    "world-writable-file-mode",
		File:    "perm.go",
		Message: "File operation grants world-write permission",
	}

	content := "os.WriteFile(\"out.bin\", data, 0666)\n"
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if prop == nil {
		t.Fatal("expected proposal for 0666")
	}
	if !strings.Contains(prop.ProposedContent, "0644") {
		t.Errorf("expected 0666 to be replaced with 0644, got %q", prop.ProposedContent)
	}

	contentOctal := "os.WriteFile(\"out.bin\", data, 0o666)\n"
	propOctal, err := fixer.GenerateProposal(context.Background(), "", f, []byte(contentOctal))
	if err != nil {
		t.Fatal(err)
	}
	if propOctal == nil || !strings.Contains(propOctal.ProposedContent, "0o644") {
		t.Errorf("expected 0o666 to be replaced with 0o644, got %+v", propOctal)
	}
}
