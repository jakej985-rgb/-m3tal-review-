package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// AsymmetricStorageRule detects classes that wrap multiple storage backends
// (e.g. SharedPreferences and StorageService) where some methods check both
// backends, but other CRUD methods check only one backend, causing silent data loss
// or failure when only the second backend is provided.
type AsymmetricStorageRule struct {
	ruleRuntime
}

func (AsymmetricStorageRule) Name() string { return "asymmetric-storage-wrapper" }

var (
	sourceFileRe = regexp.MustCompile(`\.(?:dart|ts|js|go|java|kt)$`)

	// dualStorageFieldsRe matches having both prefs and storage fields in a class.
	prefsFieldRe   = regexp.MustCompile(`\b(?:SharedPreferences\??|\bprefs\b|_prefs\b)`)
	storageFieldRe = regexp.MustCompile(`\b(?:StorageService\??|\bstorage\b|_storage\b)`)

	// dualCheckRe matches checking both backends in a method.
	dualCheckRe = regexp.MustCompile(`(?:\b_?prefs\b[^\n]*\?\?|\b_?storage\b[^\n]*\?\?|else\s+if\s*\(\s*_?storage\b)`)

	// singlePrefsCheckRe matches methods that only guard on prefs.
	singlePrefsCheckRe = regexp.MustCompile(`if\s*\(\s*_?prefs\s*!=\s*null\s*\)`)
)

func (r AsymmetricStorageRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r AsymmetricStorageRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !sourceFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// Does this file/block contain references to both prefs and storage?
		hasPrefs := prefsFieldRe.MatchString(scanText)
		hasStorage := storageFieldRe.MatchString(scanText)
		hasDualCheck := dualCheckRe.MatchString(scanText)

		if !hasPrefs || !hasStorage || !hasDualCheck {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			// Check if this line guards on prefs only
			if singlePrefsCheckRe.MatchString(line) {
				// Verify if the next ~10 lines have an else if for storage
				hasStorageBranch := false
				for j := 1; j < 12 && i+j < len(lines); j++ {
					if strings.Contains(lines[i+j], "_storage") || strings.Contains(lines[i+j], "storage") {
						hasStorageBranch = true
						break
					}
				}

				if !hasStorageBranch {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "asymmetric-storage-wrapper",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "Storage wrapper supports multiple backends but method guards exclusively on prefs, ignoring the alternative storage backend",
							Remediation: "Ensure all CRUD methods check and persist across the configured storage instance or delegate to a unified storage abstraction.",
						})
					}
				}
			}
		}
	}

	return findings
}
