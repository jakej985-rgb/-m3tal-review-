package review

import (
	"context"
	"regexp"
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
	replayMethodDeclRe = regexp.MustCompile(
		`(?m)^\s*(?:@\w+\s+)*(?:(?:static|final)\s+)?(?:(?:void|Future<[^>]*>|[A-Za-z0-9_<>?]+)\s+)?` +
			`(replayFromEvents|reconstructFromLedger|replayLedger)\s*\(`,
	)
	ledgerBoundaryRe = regexp.MustCompile(
		`(?i)\b(?:maxLedgerEvents|trimToSize|evictOldEvents|maxEvents|ledgerCapacity)\b`,
	)
	baseSnapshotRe = regexp.MustCompile(`(?i)\bbaseSnapshot\b`)
)

func (r LedgerReplaySnapshotRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func findCloseParen(s string, openParen int) int {
	parenDepth := 1
	for idx := openParen + 1; idx < len(s); idx++ {
		if s[idx] == '(' {
			parenDepth++
		} else if s[idx] == ')' {
			parenDepth--
			if parenDepth == 0 {
				return idx
			}
		}
	}
	return -1
}

func isMethodDeclarationAfter(s string, closeParen int) bool {
	afterParams := strings.TrimSpace(s[closeParen+1:])
	return strings.HasPrefix(afterParams, "{") ||
		strings.HasPrefix(afterParams, "=>") ||
		strings.HasPrefix(afterParams, "async")
}

func findBoundaryAddedLine(block diffSourceBlock, scanText string, startLine int) int {
	for _, bLoc := range ledgerBoundaryRe.FindAllStringIndex(scanText, -1) {
		bLine := startLine + strings.Count(scanText[:bLoc[0]], "\n")
		if block.addedLines[bLine] {
			return bLine
		}
	}
	return 0
}

func checkReplayDecl(
	block diffSourceBlock,
	scanText string,
	startLine, firstBoundaryLine int,
	m []int,
	seen map[string]bool,
) (Finding, bool) {
	declStart := m[0]
	openParen := m[1] - 1
	closeParen := findCloseParen(scanText, openParen)
	if closeParen == -1 || !isMethodDeclarationAfter(scanText, closeParen) {
		return Finding{}, false
	}

	params := scanText[openParen+1 : closeParen]
	if baseSnapshotRe.MatchString(params) {
		return Finding{}, false
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
			if firstBoundaryLine > 0 {
				lineNum = firstBoundaryLine
			} else {
				return Finding{}, false
			}
		}
	}

	if dedupeFinding(seen, block.file, lineNum) {
		return Finding{}, false
	}
	return Finding{
		Rule:     "event-ledger-snapshot-truncation",
		Severity: "high",
		File:     block.file,
		Line:     lineNum,
		Message:  "Trimmed event ledger replay method reconstructs state from empty without base snapshot support",
		Remediation: "Accept a 'baseSnapshot' parameter in replayFromEvents so trimmed ledgers " +
			"can accurately reconstruct state across eviction boundaries.",
	}, true
}

func checkLedgerReplayBlock(b diffSourceBlock, text string, start int, seen map[string]bool) []Finding {
	if !ledgerBoundaryRe.MatchString(text) {
		return nil
	}
	declMatches := replayMethodDeclRe.FindAllStringIndex(text, -1)
	if len(declMatches) == 0 {
		return nil
	}
	var findings []Finding
	firstAddedBoundaryLine := findBoundaryAddedLine(b, text, start)
	for _, m := range declMatches {
		if f, ok := checkReplayDecl(b, text, start, firstAddedBoundaryLine, m, seen); ok {
			findings = append(findings, f)
		}
	}
	return findings
}

func (r LedgerReplaySnapshotRule) CheckContext(ctx context.Context, diff string) []Finding {
	return executeBlockRule(ctx, diff, r.repositoryRoot, r.workingTree, func(f string) bool {
		return dartSourceFileRe.MatchString(f) && !isTestFile(f)
	}, checkLedgerReplayBlock)
}
