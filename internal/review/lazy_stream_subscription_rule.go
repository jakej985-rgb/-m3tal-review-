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
	serialLogsProvideRe = regexp.MustCompile(
		`(?i)\b(?:hardwareSerialLogsProvider|serialLogsProvider|deviceLogsProvider)\b`,
	)
	screenWatchLogsRe = regexp.MustCompile(
		`(?i)\b(?:ref|context)\s*\.\s*(?:watch|listen)\s*\(\s*` +
			`(?:hardwareSerialLogsProvider|serialLogsProvider|deviceLogsProvider)\b`,
	)
	logReadRe = regexp.MustCompile(
		`(?i)\bref\s*\.\s*(?:read|listen)\s*\(\s*` +
			`(?:hardwareSerialLogsProvider|serialLogsProvider|deviceLogsProvider)\b`,
	)
	initStateHeaderRe = regexp.MustCompile(`\binitState\s*\(\s*\)\s*\{`)
)

func enclosingClassBody(scanText string, offset int) string {
	classStart := strings.LastIndex(scanText[:offset], "class ")
	if classStart == -1 {
		return scanText
	}
	braceIdx := strings.Index(scanText[classStart:], "{")
	if braceIdx == -1 {
		return scanText
	}
	braceStart := classStart + braceIdx
	body := extractMethodBody(scanText, braceStart)
	if offset < braceStart+len(body) {
		return body
	}
	return scanText
}

func hasEagerInitRead(text string) bool {
	matches := initStateHeaderRe.FindAllStringIndex(text, -1)
	for _, m := range matches {
		braceStart := m[1] - 1
		body := extractMethodBody(text, braceStart)
		logReadLoc := logReadRe.FindStringIndex(body)
		if logReadLoc != nil {
			connectLoc := connectTriggerRe.FindStringIndex(body)
			if connectLoc == nil || logReadLoc[0] < connectLoc[0] {
				return true
			}
		}
	}
	return false
}

func hasScreenLevelWatch(text string) bool {
	return screenWatchLogsRe.MatchString(text)
}

func isInsideInitState(scanText string, offset int) bool {
	matches := initStateHeaderRe.FindAllStringIndex(scanText, -1)
	for _, m := range matches {
		braceStart := m[1] - 1
		body := extractMethodBody(scanText, braceStart)
		if offset >= braceStart && offset < braceStart+len(body) {
			return true
		}
	}
	return false
}

func initStateReadsBeforeConnect(scanText string, connectOffset int) bool {
	matches := initStateHeaderRe.FindAllStringIndex(scanText, -1)
	for _, m := range matches {
		braceStart := m[1] - 1
		body := extractMethodBody(scanText, braceStart)
		if connectOffset >= braceStart && connectOffset < braceStart+len(body) {
			relOffset := connectOffset - braceStart
			logReadLoc := logReadRe.FindStringIndex(body)
			if logReadLoc != nil && logReadLoc[0] < relOffset {
				return true
			}
		}
	}
	return false
}

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

		connectMatches := connectTriggerRe.FindAllStringIndex(scanText, -1)
		for _, m := range connectMatches {
			offset := m[0]
			clsBody := enclosingClassBody(scanText, offset)
			if isInsideInitState(scanText, offset) {
				if initStateReadsBeforeConnect(scanText, offset) {
					continue
				}
			} else {
				if hasEagerInitRead(clsBody) || hasScreenLevelWatch(clsBody) {
					continue
				}
			}

			lineNum := startLine + strings.Count(scanText[:offset], "\n")
			if len(block.addedLines) > 0 && !block.addedLines[lineNum] {
				continue
			}

			key := block.file + ":" + strconv.Itoa(lineNum)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					Rule:     "flutter-lazy-stream-listener",
					Severity: "high",
					File:     block.file,
					Line:     lineNum,
					Message:  "Broadcast stream connection initiated without eager log listener subscription in initState",
					Remediation: "Warm up the log stream provider subscription via " +
						"'ref.read(...LogsProvider)' in initState() before initiating connections to avoid dropping initial output.",
				})
			}
		}
	}

	return findings
}
