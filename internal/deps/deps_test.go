package deps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetectLicenseFixtures(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		expected string
	}{
		{"MIT fixture", "testdata/licenses/mit-pkg/LICENSE", "MIT"},
		{"Apache fixture", "testdata/licenses/apache-pkg/LICENSE", "Apache-2.0"},
		{"GPL fixture", "testdata/licenses/gpl-pkg/LICENSE", "GPL-3.0"},
		{"Unknown fixture", "testdata/licenses/unknown-pkg/LICENSE", "Unknown"},
	}

	root := filepath.Join("..", "..")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, filepath.FromSlash(tc.file))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed to read fixture %s: %v", path, err)
			}
			got := DetectLicense(string(data))
			if got != tc.expected {
				t.Errorf("DetectLicense(%s) = %q, want %q", tc.file, got, tc.expected)
			}
		})
	}

	// In-memory tests for additional license variants
	variants := []struct {
		name string
		text string
		want string
	}{
		{"GPL-2.0", "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991", "GPL-2.0"},
		{"AGPL-3.0", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007", "AGPL-3.0"},
		{"BSD-3-Clause", "Redistribution and use in source and binary forms\nNeither the name of Example Corp", "BSD-3-Clause"},
		{"BSD-2-Clause", "Redistribution and use in source and binary forms\n1. Redistributions of source code\n2. Redistributions in binary form", "BSD-2-Clause"},
		{"Unlicense", "This is free and unencumbered software released into the public domain", "Unlicense"},
		{"ISC", "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee", "ISC"},
		{"MPL-2.0", "Mozilla Public License Version 2.0", "MPL-2.0"},
		{"No license", "", "NO-LICENSE"},
	}

	for _, v := range variants {
		got := DetectLicense(v.text)
		if got != v.want {
			t.Errorf("DetectLicense(%s) = %q, want %q", v.name, got, v.want)
		}
	}
}

func TestParseGoMod(t *testing.T) {
	validMod := `module github.com/example/testmod

go 1.23

require (
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.14.0 // indirect
)

require github.com/pkg/errors v0.9.1

replace github.com/old/mod => github.com/new/mod v1.0.0
`

	mod, findings := ParseGoMod(validMod)
	if len(findings) != 0 {
		t.Fatalf("unexpected findings for valid go.mod: %+v", findings)
	}
	if mod.ModulePath != "github.com/example/testmod" {
		t.Errorf("expected module path github.com/example/testmod, got %q", mod.ModulePath)
	}
	if mod.GoVersion != "1.23" {
		t.Errorf("expected go version 1.23, got %q", mod.GoVersion)
	}
	if len(mod.Requires) != 3 {
		t.Errorf("expected 3 requires, got %d", len(mod.Requires))
	}
	if !mod.Requires[1].Indirect {
		t.Errorf("expected golang.org/x/crypto to be indirect")
	}
	if mod.Requires[0].Indirect {
		t.Errorf("expected github.com/stretchr/testify to be direct")
	}
	if len(mod.Replaces) != 1 {
		t.Errorf("expected 1 replace, got %d", len(mod.Replaces))
	}
}

func TestParseGoModMalformed(t *testing.T) {
	malformed := `module
require (
	github.com/foo/bar v1.0.0
` // Missing module path and unclosed require block

	_, findings := ParseGoMod(malformed)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings for malformed go.mod, got %d", len(findings))
	}
	hasMissingModule := false
	hasUnclosedBlock := false
	for _, f := range findings {
		if strings.Contains(f.Message, "missing module path") {
			hasMissingModule = true
		}
		if strings.Contains(f.Message, "Unclosed require block") {
			hasUnclosedBlock = true
		}
	}
	if !hasMissingModule {
		t.Errorf("expected missing module path finding")
	}
	if !hasUnclosedBlock {
		t.Errorf("expected unclosed block finding")
	}
}

func TestParseGoSum(t *testing.T) {
	validSum := `github.com/stretchr/testify v1.8.4 h1:abc123hash=
github.com/stretchr/testify v1.8.4/go.mod h1:modhash=
`
	sum, findings := ParseGoSum(validSum)
	if len(findings) != 0 {
		t.Fatalf("unexpected findings for valid go.sum: %+v", findings)
	}
	if len(sum.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(sum.Entries))
	}
	if sum.Entries[0].IsGoMod {
		t.Errorf("first entry should not be go.mod")
	}
	if !sum.Entries[1].IsGoMod {
		t.Errorf("second entry should be go.mod")
	}
}

func TestParseGoSumMalformed(t *testing.T) {
	malformedSum := `bad_line_only_one_field
github.com/foo/bar v1.0.0 invalidhashprefix
`
	_, findings := ParseGoSum(malformedSum)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings for malformed go.sum, got %d", len(findings))
	}
}

func TestAnalyzeGoModulesNonGoRepo(t *testing.T) {
	tmpDir := t.TempDir()
	report, findings, err := AnalyzeGoModules(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error for non-Go repo: %v", err)
	}
	if report.IsGoModule {
		t.Errorf("expected IsGoModule = false")
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for non-Go repo, got %d", len(findings))
	}
}

func TestAnalyzeGoModulesUnusedAndDuplicate(t *testing.T) {
	tmpDir := t.TempDir()

	goModContent := `module example.com/myrepo

go 1.23

require (
	github.com/used/pkg v1.0.0
	github.com/unused/pkg v2.0.0
	github.com/indirect/pkg v1.5.0 // indirect
	github.com/used/pkg v1.0.1
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatal(err)
	}

	mainGoContent := `package main

import (
	"fmt"
	"github.com/used/pkg/sub"
)

func main() {
	fmt.Println("hello")
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainGoContent), 0644); err != nil {
		t.Fatal(err)
	}

	goSumContent := `github.com/used/pkg v1.0.0 h1:hashA=
github.com/used/pkg v1.0.0 h1:hashB_conflict=
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.sum"), []byte(goSumContent), 0644); err != nil {
		t.Fatal(err)
	}

	report, findings, err := AnalyzeGoModules(tmpDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !report.IsGoModule {
		t.Fatalf("expected IsGoModule = true")
	}

	// Verify duplicate was found
	hasDuplicate := false
	hasUnused := false
	hasChecksumConflict := false

	for _, f := range findings {
		if f.Rule == "go-module-duplicate-dependency" && strings.Contains(f.Message, "github.com/used/pkg") {
			hasDuplicate = true
		}
		if f.Rule == "go-module-unused-dependency" && strings.Contains(f.Message, "github.com/unused/pkg") {
			hasUnused = true
		}
		if f.Rule == "go-sum-checksum-conflict" {
			hasChecksumConflict = true
		}
	}

	if !hasDuplicate {
		t.Errorf("expected go-module-duplicate-dependency finding")
	}
	if !hasUnused {
		t.Errorf("expected go-module-unused-dependency finding for github.com/unused/pkg")
	}
	if !hasChecksumConflict {
		t.Errorf("expected go-sum-checksum-conflict finding")
	}
}

func TestEvaluateLicensePolicy(t *testing.T) {
	licenses := map[string]LicenseInfo{
		"github.com/mit/pkg": {
			Module:  "github.com/mit/pkg",
			License: "MIT",
		},
		"github.com/apache/pkg": {
			Module:  "github.com/apache/pkg",
			License: "Apache-2.0",
		},
		"github.com/gpl/pkg": {
			Module:  "github.com/gpl/pkg",
			License: "GPL-3.0",
		},
		"github.com/mystery/pkg": {
			Module:  "github.com/mystery/pkg",
			License: "Unknown",
		},
	}

	// Policy 1: Allowlist allows only MIT and Apache-2.0, disallows unknown
	policy1 := LicensePolicy{
		Allow:        []string{"MIT", "Apache-2.0"},
		AllowUnknown: false,
	}
	findings1 := EvaluateLicensePolicy(licenses, policy1)

	hasGplNotAllowed := false
	hasUnknown := false
	for _, f := range findings1 {
		if f.Rule == "dependency-license-not-allowed" && strings.Contains(f.Message, "github.com/gpl/pkg") {
			hasGplNotAllowed = true
		}
		if f.Rule == "dependency-license-unknown" && strings.Contains(f.Message, "github.com/mystery/pkg") {
			hasUnknown = true
		}
	}
	if !hasGplNotAllowed {
		t.Errorf("expected dependency-license-not-allowed for GPL package")
	}
	if !hasUnknown {
		t.Errorf("expected dependency-license-unknown for mystery package")
	}

	// Policy 2: Denylist denies GPL-3.0, allows unknown
	policy2 := LicensePolicy{
		Deny:         []string{"GPL-3.0"},
		AllowUnknown: true,
	}
	findings2 := EvaluateLicensePolicy(licenses, policy2)
	hasGplDenied := false
	hasUnknownFlagged := false
	for _, f := range findings2 {
		if f.Rule == "dependency-license-denied" && strings.Contains(f.Message, "github.com/gpl/pkg") {
			hasGplDenied = true
		}
		if f.Rule == "dependency-license-unknown" {
			hasUnknownFlagged = true
		}
	}
	if !hasGplDenied {
		t.Errorf("expected dependency-license-denied for GPL package")
	}
	if hasUnknownFlagged {
		t.Errorf("did not expect unknown license finding when AllowUnknown is true")
	}
}

func TestCheckDependenciesIntegration(t *testing.T) {
	tmpDir := t.TempDir()

	// Create go.mod
	goMod := `module test.integration/mod

go 1.23

require (
	github.com/vendor/mit v1.0.0
	github.com/vendor/gpl v1.0.0
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatal(err)
	}

	// Create source file using both
	src := `package main

import (
	_ "github.com/vendor/mit"
	_ "github.com/vendor/gpl"
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	// Create vendor directories with licenses
	mitVendor := filepath.Join(tmpDir, "vendor", "github.com", "vendor", "mit")
	if err := os.MkdirAll(mitVendor, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mitVendor, "LICENSE"), []byte("The MIT License\nPermission is hereby granted, free of charge..."), 0644); err != nil {
		t.Fatal(err)
	}

	gplVendor := filepath.Join(tmpDir, "vendor", "github.com", "vendor", "gpl")
	if err := os.MkdirAll(gplVendor, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gplVendor, "LICENSE"), []byte("GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007..."), 0644); err != nil {
		t.Fatal(err)
	}

	opts := CheckOptions{
		LicensePolicy: LicensePolicy{
			Allow: []string{"MIT"},
		},
	}

	report, findings, err := CheckDependencies(tmpDir, opts)
	if err != nil {
		t.Fatalf("CheckDependencies failed: %v", err)
	}
	if !report.IsGoModule {
		t.Fatalf("expected IsGoModule = true")
	}
	if report.Licenses["github.com/vendor/mit"].License != "MIT" {
		t.Errorf("expected MIT license, got %q", report.Licenses["github.com/vendor/mit"].License)
	}
	if report.Licenses["github.com/vendor/gpl"].License != "GPL-3.0" {
		t.Errorf("expected GPL-3.0 license, got %q", report.Licenses["github.com/vendor/gpl"].License)
	}

	hasGplViolation := false
	for _, f := range findings {
		if f.Rule == "dependency-license-not-allowed" && strings.Contains(f.Message, "github.com/vendor/gpl") {
			hasGplViolation = true
		}
	}
	if !hasGplViolation {
		t.Errorf("expected GPL license violation in findings")
	}
}
