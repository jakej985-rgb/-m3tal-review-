package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// LedgerReplaySnapshotRule detects event-sourced models with bounded/trimmed event ledgers
// whose replay methods reconstruct state starting strictly from empty without accepting
// a base snapshot parameter.
// When event ledgers are trimmed to prevent unbounded memory growth, replaying surviving
// events from empty silently drops earlier progress and state.
type LedgerReplaySnapshotRule struct {
	ruleRuntime
}

func (LedgerReplaySnapshotRule) Name() string {
	return "event-ledger-snapshot-truncation"
}

var (
	replayMethodRe   = regexp.MustCompile(`\b(?:replayFromEvents|reconstructFromLedger|replayLedger)\s*\(`)
	ledgerBoundaryRe = regexp.MustCompile(`(?i)(?:maxLedgerEvents|trimToSize|evictOldEvents|maxEvents|ledgerCapacity)`)
	baseSnapshotRe   = regexp.MustCompile(`(?i)\bbaseSnapshot\b`)
)

func (r LedgerReplaySnapshotRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r LedgerReplaySnapshotRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !dartSourceFileRe.MatchString(block.file) || isTestFile(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if !replayMethodRe.MatchString(scanText) {
			continue
		}

		// Only apply when the model maintains bounded/trimmed ledgers
		if !ledgerBoundaryRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			if replayMethodRe.MatchString(line) {
				// Check parameter declaration for baseSnapshot support
				endIdx := i + 5
				if endIdx > len(lines) {
					endIdx = len(lines)
				}
				sigSnippet := strings.Join(lines[i:endIdx], " ")
				if baseSnapshotRe.MatchString(sigSnippet) {
					continue
				}

				lineNum := startLine + i
				if len(block.addedLines) > 0 && !block.addedLines[lineNum] {
					continue
				}
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "event-ledger-snapshot-truncation",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Trimmed event ledger replay method reconstructs state from empty without base snapshot support",
						Remediation: "Accept a 'baseSnapshot' parameter in replayFromEvents so trimmed ledgers can accurately reconstruct state across eviction boundaries.",
					})
				}
			}
		}
	}

	return findings
}
