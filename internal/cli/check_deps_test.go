package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCommandCheckDepsNonGoDir(t *testing.T) {
	tmpDir := t.TempDir()
	err := commandCheckDeps([]string{tmpDir})
	if err != nil {
		t.Fatalf("expected nil error for non-Go directory, got: %v", err)
	}
}

func TestCommandCheckDepsJSONFormat(t *testing.T) {
	tmpDir := t.TempDir()
	goMod := `module test.cli/pkg

go 1.23
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	err := commandCheckDeps([]string{"--format", "json", tmpDir})
	if err != nil {
		t.Fatalf("expected nil error for valid go.mod with json format, got: %v", err)
	}
}

func TestCommandCheckDepsStrictMode(t *testing.T) {
	tmpDir := t.TempDir()
	// Create go.mod with unused dependency
	goMod := `module test.cli/strict

go 1.23

require github.com/unused/dependency v1.0.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Without --strict, command exits 0 (reports findings without failing)
	errNormal := commandCheckDeps([]string{tmpDir})
	if errNormal != nil {
		t.Fatalf("expected nil error without strict mode, got: %v", errNormal)
	}

	// With --strict, command returns non-nil error
	errStrict := commandCheckDeps([]string{"--strict", tmpDir})
	if errStrict == nil {
		t.Fatalf("expected non-nil error in strict mode when findings exist")
	}
}

func TestCommandCheckDepsLicenseFlags(t *testing.T) {
	tmpDir := t.TempDir()
	goMod := `module test.cli/licenses

go 1.23

require github.com/gpl/dep v1.0.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	src := `package main
import _ "github.com/gpl/dep"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	vendorDir := filepath.Join(tmpDir, "vendor", "github.com", "gpl", "dep")
	if err := os.MkdirAll(vendorDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vendorDir, "LICENSE"), []byte("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007"), 0644); err != nil {
		t.Fatal(err)
	}

	// Denying GPL with --strict should fail
	errDenied := commandCheckDeps([]string{"--strict", "--deny-licenses", "GPL-3.0", tmpDir})
	if errDenied == nil {
		t.Fatalf("expected failure when denied license is present with --strict")
	}

	// Allowing only MIT with --strict should fail because GPL is not allowed
	errNotAllowed := commandCheckDeps([]string{"--strict", "--allow-licenses", "MIT", tmpDir})
	if errNotAllowed == nil {
		t.Fatalf("expected failure when license is not in allowlist with --strict")
	}
}
