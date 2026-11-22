package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// BackupRecoveryRule detects storage methods that declare backup/snapshot recovery
// mechanisms, but early-return empty/default values when the primary store key
// is null or empty without inspecting the backup snapshot. This causes missing or
// wiped primary keys to bypass recovery, leading to downstream data overwrite.
type BackupRecoveryRule struct {
	ruleRuntime
}

func (BackupRecoveryRule) Name() string { return "backup-recovery-bypass" }

var (
	backupStorageFileRe = regexp.MustCompile(`(?i)(?:storage|datasource|repository|store|cache).*\.(?:dart|ts|js|go|java|kt|py)$`)

	// backupKeyRefRe matches mentions of backup snapshot keys or variables.
	backupKeyRefRe = regexp.MustCompile(`\b(?:_?backup(?:Key|Raw|Snapshot|String)?|_?snapshot(?:Key|Raw)?)\b`)

	// earlyNullEmptyReturnRe matches early returns when primary raw data is null or empty.
	earlyNullEmptyReturnRe = regexp.MustCompile(`if\s*\(\s*(?:raw|_?rawProgress|_?rawProfiles|_?data)\s*(?:==\s*null\s*\|\|\s*(?:raw|_?data)\.isEmpty|\.isEmpty\s*\|\|\s*==\s*null)\s*\)\s*(?:return\s*[^;]*;|{\s*return\s*[^;]*;\s*})`)
)

func (r BackupRecoveryRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r BackupRecoveryRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !backupStorageFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if !backupKeyRefRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			if !block.addedLines[lineNum] && r.workingTree == false {
				continue
			}

			// Check if line is an early return on null/empty raw data
			if earlyNullEmptyReturnRe.MatchString(line) {
				// Verify if this function later attempts backup recovery (e.g. in catch or fallback)
				// Look ahead in the next 30 lines for backup reading
				hasBackupRecoveryLater := false
				endIdx := i + 35
				if endIdx > len(lines) {
					endIdx = len(lines)
				}
				for j := i + 1; j < endIdx; j++ {
					if backupKeyRefRe.MatchString(lines[j]) && strings.Contains(lines[j], "getString") {
						hasBackupRecoveryLater = true
						break
					}
				}

				if hasBackupRecoveryLater {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "backup-recovery-bypass",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "Storage reader early-returns on null/empty primary data without checking available backup snapshot",
							Remediation: "Inspect the backup snapshot when primary data is missing or empty before returning an empty fallback.",
						})
					}
				}
			}
		}
	}

	return findings
}
