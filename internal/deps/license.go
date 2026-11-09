package deps

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

var candidateLicenseFileNames = []string{
	"LICENSE",
	"LICENSE.txt",
	"LICENSE.md",
	"LICENCE",
	"LICENCE.txt",
	"LICENCE.md",
	"COPYING",
	"COPYING.txt",
	"COPYING.LESSER",
	"UNLICENSE",
	"LICENSE-MIT",
	"LICENSE-APACHE",
}

// DetectLicense classifies the license type from license text content.
func DetectLicense(text string) string {
	cleaned := strings.TrimSpace(text)
	if cleaned == "" {
		return "NO-LICENSE"
	}

	lower := strings.ToLower(cleaned)

	// Unlicense
	if strings.Contains(lower, "this is free and unencumbered software released into the public domain") {
		return "Unlicense"
	}

	// AGPL
	if strings.Contains(lower, "gnu affero general public license") {
		return "AGPL-3.0"
	}

	// LGPL
	if strings.Contains(lower, "gnu lesser general public license") {
		if strings.Contains(lower, "version 3") || strings.Contains(lower, "v3") {
			return "LGPL-3.0"
		}
		return "LGPL-2.1"
	}

	// GPL
	if strings.Contains(lower, "gnu general public license") {
		if strings.Contains(lower, "version 3") || strings.Contains(lower, "v3") {
			return "GPL-3.0"
		}
		if strings.Contains(lower, "version 2") || strings.Contains(lower, "v2") {
			return "GPL-2.0"
		}
		return "GPL"
	}

	// Apache-2.0
	if strings.Contains(lower, "apache license, version 2.0") ||
		strings.Contains(lower, "licensed under the apache license, version 2.0") ||
		strings.Contains(lower, "http://www.apache.org/licenses/license-2.0") ||
		strings.Contains(lower, "https://www.apache.org/licenses/license-2.0") {
		return "Apache-2.0"
	}

	// MIT
	if strings.Contains(lower, "permission is hereby granted, free of charge, to any person obtaining a copy") ||
		strings.Contains(lower, "the mit license") ||
		strings.Contains(lower, "mit license") {
		return "MIT"
	}

	// ISC
	if strings.Contains(lower, "permission to use, copy, modify, and/or distribute this software for any purpose with or without fee") {
		return "ISC"
	}

	// MPL-2.0
	if strings.Contains(lower, "mozilla public license") && (strings.Contains(lower, "version 2.0") || strings.Contains(lower, "2.0")) {
		return "MPL-2.0"
	}

	// BSD
	if strings.Contains(lower, "redistribution and use in source and binary forms") {
		if strings.Contains(lower, "neither the name") || strings.Contains(lower, "3. neither the name") {
			return "BSD-3-Clause"
		}
		return "BSD-2-Clause"
	}

	return "Unknown"
}

// escapeModulePath implements go's module cache directory path escaping (uppercase -> !lowercase).
func escapeModulePath(path string) string {
	var sb strings.Builder
	for _, r := range path {
		if unicode.IsUpper(r) {
			sb.WriteRune('!')
			sb.WriteRune(unicode.ToLower(r))
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// findLicenseInDir looks for standard license files within a directory.
func findLicenseInDir(dir string) (string, string) {
	for _, name := range candidateLicenseFileNames {
		target := filepath.Join(dir, name)
		if info, err := os.Stat(target); err == nil && !info.IsDir() {
			data, err := os.ReadFile(target)
			if err == nil {
				return DetectLicense(string(data)), target
			}
		}
	}
	return "", ""
}

// InspectDependencyLicenses inspects license files for Go dependencies from vendor/ or module cache.
func InspectDependencyLicenses(repoRoot string, reqs []RequireEntry) map[string]LicenseInfo {
	result := make(map[string]LicenseInfo, len(reqs))

	// Resolve GOPATH
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			gopath = filepath.Join(home, "go")
		}
	}
	modCacheDir := ""
	if gopath != "" {
		modCacheDir = filepath.Join(gopath, "pkg", "mod")
	}

	for _, req := range reqs {
		modPath := req.Path
		info := LicenseInfo{
			Module:  modPath,
			Version: req.Version,
			License: "Unknown",
		}

		// 1. Try vendor directory
		vendorDir := filepath.Join(repoRoot, "vendor", filepath.FromSlash(modPath))
		if lic, file := findLicenseInDir(vendorDir); lic != "" {
			info.License = lic
			info.LicenseFile = file
			info.Confidence = "high"
			result[modPath] = info
			continue
		}

		// 2. Try GOPATH module cache if version is available
		if modCacheDir != "" && req.Version != "" {
			escapedPath := escapeModulePath(modPath)
			cacheDir := filepath.Join(modCacheDir, escapedPath+"@"+req.Version)
			if lic, file := findLicenseInDir(cacheDir); lic != "" {
				info.License = lic
				info.LicenseFile = file
				info.Confidence = "high"
				result[modPath] = info
				continue
			}
		}

		// 3. Fallback: check repo test fixtures or subdirs
		fixtureDir := filepath.Join(repoRoot, "testdata", "licenses", filepath.Base(modPath))
		if lic, file := findLicenseInDir(fixtureDir); lic != "" {
			info.License = lic
			info.LicenseFile = file
			info.Confidence = "fixture"
			result[modPath] = info
			continue
		}

		result[modPath] = info
	}

	return result
}

func containsLicense(list []string, lic string) bool {
	normLic := strings.ToUpper(strings.TrimSpace(lic))
	for _, item := range list {
		if strings.ToUpper(strings.TrimSpace(item)) == normLic {
			return true
		}
	}
	return false
}

// EvaluateLicensePolicy evaluates detected licenses against an allow/deny policy.
func EvaluateLicensePolicy(licenses map[string]LicenseInfo, policy LicensePolicy) []review.Finding {
	var findings []review.Finding

	// Sort modules deterministically
	mods := make([]string, 0, len(licenses))
	for m := range licenses {
		mods = append(mods, m)
	}
	sort.Strings(mods)

	for _, mod := range mods {
		info := licenses[mod]
		lic := info.License

		// Check denylist first
		if len(policy.Deny) > 0 && containsLicense(policy.Deny, lic) {
			findings = append(findings, review.Finding{
				Category:    "security",
				Rule:        "dependency-license-denied",
				Severity:    "high",
				File:        "go.mod",
				Message:     fmt.Sprintf("Dependency %q uses denied license %q", mod, lic),
				Remediation: "Replace this dependency or seek an organizational license exception.",
			})
			continue
		}

		// Check unknown handling
		if lic == "Unknown" || lic == "NO-LICENSE" {
			if !policy.AllowUnknown && (len(policy.Allow) > 0 || len(policy.Deny) > 0) {
				findings = append(findings, review.Finding{
					Category:    "confidence",
					Rule:        "dependency-license-unknown",
					Severity:    "medium",
					File:        "go.mod",
					Message:     fmt.Sprintf("Dependency %q has unknown or missing license", mod),
					Remediation: "Inspect the dependency source and verify license terms, or add to allowlist.",
				})
			}
			continue
		}

		// Check allowlist
		if len(policy.Allow) > 0 && !containsLicense(policy.Allow, lic) {
			findings = append(findings, review.Finding{
				Category:    "security",
				Rule:        "dependency-license-not-allowed",
				Severity:    "high",
				File:        "go.mod",
				Message:     fmt.Sprintf("Dependency %q has license %q which is not in the allowlist", mod, lic),
				Remediation: "Verify the license complies with project policy and add it to the allowlist if approved.",
			})
		}
	}

	return findings
}
