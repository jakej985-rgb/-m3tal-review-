package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// LazyStreamSubscriptionRule detects screens managing connections to broadcast streams
// (such as serial monitors or hardware bridges) where stream log providers are only
// accessed in lazy child widgets without eager initialization in initState().
// On broadcast streams, connection output produced before the child widget mounts
// is dropped and never received by late-subscribing listeners.
type LazyStreamSubscriptionRule struct {
	ruleRuntime
}

func (LazyStreamSubscriptionRule) Name() string {
	return "flutter-lazy-stream-listener"
}

var (
	connectTriggerRe    = regexp.MustCompile(`(?i)\b(?:bridge|serial|transport)\.(?:connect|scanDevices|open)\s*\(`)
	serialLogsProvideRe = regexp.MustCompile(`(?i)\b(?:hardwareSerialLogsProvider|serialLogsProvider|deviceLogsProvider)\b`)
	eagerInitReadRe     = regexp.MustCompile(`(?i)initState\s*\(\s*\)[\s\S]*?\bref\.read\s*\(\s*(?:hardwareSerialLogsProvider|serialLogsProvider|deviceLogsProvider)`)
)

func (r LazyStreamSubscriptionRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r LazyStreamSubscriptionRule) CheckContext(ctx context.Context, diff string) []Finding {
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

		if !connectTriggerRe.MatchString(scanText) || !serialLogsProvideRe.MatchString(scanText) {
			continue
		}

		// If initState contains an eager read of the log provider, initial connection output is preserved
		if eagerInitReadRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			if connectTriggerRe.MatchString(line) {
				lineNum := startLine + i
				if len(block.addedLines) > 0 && !block.addedLines[lineNum] {
					continue
				}
				key := block.file + ":" + strconv.Itoa(lineNum)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						Rule:        "flutter-lazy-stream-listener",
						Severity:    "high",
						File:        block.file,
						Line:        lineNum,
						Message:     "Broadcast stream connection initiated without eager log listener subscription in initState",
						Remediation: "Warm up the log stream provider subscription via 'ref.read(...LogsProvider)' in initState() before initiating connections to avoid dropping initial output.",
					})
				}
			}
		}
	}

	return findings
}
