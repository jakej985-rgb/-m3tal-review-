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
	replayMethodDeclRe = regexp.MustCompile(`(?m)^\s*(?:@\w+\s+)*(?:(?:static|final)\s+)?(?:(?:void|Future<[^>]*>|[A-Za-z0-9_<>?]+)\s+)?(replayFromEvents|reconstructFromLedger|replayLedger)\s*\(`)
	ledgerBoundaryRe   = regexp.MustCompile(`(?i)\b(?:maxLedgerEvents|trimToSize|evictOldEvents|maxEvents|ledgerCapacity)\b`)
	baseSnapshotRe     = regexp.MustCompile(`(?i)\bbaseSnapshot\b`)
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

		// Only apply when the model maintains bounded/trimmed ledgers
		if !ledgerBoundaryRe.MatchString(scanText) {
			continue
		}

		declMatches := replayMethodDeclRe.FindAllStringIndex(scanText, -1)
		if len(declMatches) == 0 {
			continue
		}

		// Collect added lines for ledger boundary matches
		var firstAddedBoundaryLine int
		for _, bLoc := range ledgerBoundaryRe.FindAllStringIndex(scanText, -1) {
			bLine := startLine + strings.Count(scanText[:bLoc[0]], "\n")
			if block.addedLines[bLine] {
				firstAddedBoundaryLine = bLine
				break
			}
		}

		for _, m := range declMatches {
			declStart := m[0]
			openParen := m[1] - 1
			closeParen := -1
			parenDepth := 1
			for idx := openParen + 1; idx < len(scanText); idx++ {
				if scanText[idx] == '(' {
					parenDepth++
				} else if scanText[idx] == ')' {
					parenDepth--
					if parenDepth == 0 {
						closeParen = idx
						break
					}
				}
			}

			if closeParen == -1 {
				continue
			}

			// Verify this is a method declaration by checking following token
			afterParams := strings.TrimSpace(scanText[closeParen+1:])
			if !strings.HasPrefix(afterParams, "{") &&
				!strings.HasPrefix(afterParams, "=>") &&
				!strings.HasPrefix(afterParams, "async") {
				continue
			}

			params := scanText[openParen+1 : closeParen]
			if baseSnapshotRe.MatchString(params) {
				continue
			}

			declStartLine := startLine + strings.Count(scanText[:declStart], "\n")
			declEndLine := startLine + strings.Count(scanText[:closeParen], "\n")

			lineNum := declStartLine
			if len(block.addedLines) > 0 {
				declTouchesAdded := false
				for l := declStartLine; l <= declEndLine; l++ {
					if block.addedLines[l] {
						declTouchesAdded = true
						lineNum = l
						break
					}
				}
				if !declTouchesAdded {
					if firstAddedBoundaryLine > 0 {
						lineNum = firstAddedBoundaryLine
					} else {
						continue
					}
				}
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

	return findings
}
