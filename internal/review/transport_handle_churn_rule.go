package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// TransportHandleChurnRule detects transport and driver handle caches that clear all
// handles on discovery/rescan while generating IDs from ephemeral counters. This wipes
// handles recently issued by device pickers (e.g. `requestPort()`), causing subsequent
// connection attempts to fail because the handle was discarded.
type TransportHandleChurnRule struct {
	ruleRuntime
}

func (TransportHandleChurnRule) Name() string { return "transport-handle-identity-churn" }

var (
	transportDriverFileRe = regexp.MustCompile(`(?i)(?:transport|serial|device_manager|hardware_manager).*\.(?:dart|ts|js|go|py|kt)$`)

	// handlesClearRe detects wiping the handles cache map
	handlesClearRe = regexp.MustCompile(`(?i)(?:_handles|_ports|_connections)\.clear\s*\(\s*\)`)

	// ephemeralCounterIdRe detects generating IDs with incrementing counters
	ephemeralCounterIdRe = regexp.MustCompile(`(?i)(?:_nextId\+\+|\+\+_nextId|\$\{_nextId\}|idCounter\+\+)`)
)

func (r TransportHandleChurnRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r TransportHandleChurnRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !transportDriverFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if !ephemeralCounterIdRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			if handlesClearRe.MatchString(trimmed) {
				if block.addedLines[lineNum] || r.workingTree {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "transport-handle-identity-churn",
							Severity:    "medium",
							File:        block.file,
							Line:        lineNum,
							Message:     "Transport discovery clears all handle references while allocating ephemeral counter-based IDs",
							Remediation: "Preserve active handle identities across scans using stable port references so picker-selected handles are not invalidated.",
						})
					}
				}
			}
		}
	}

	return findings
}
