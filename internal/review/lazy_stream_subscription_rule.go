package review

import (
	"context"
	"regexp"
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
	eagerReadFound := false
	matches := initStateHeaderRe.FindAllStringIndex(text, -1)
	for _, m := range matches {
		braceStart := m[1] - 1
		body := extractMethodBody(text, braceStart)
		logReadLoc := logReadRe.FindStringIndex(body)
		if logReadLoc != nil {
			connectLoc := connectTriggerRe.FindStringIndex(body)
			if connectLoc == nil || logReadLoc[0] < connectLoc[0] {
				eagerReadFound = true
				break
			}
		}
	}
	return eagerReadFound
}

func hasScreenLevelWatch(text string) bool {
	return screenWatchLogsRe.MatchString(text)
}

func findEnclosingInitState(scanText string, offset int) (body string, braceStart int, found bool) {
	matches := initStateHeaderRe.FindAllStringIndex(scanText, -1)
	for _, m := range matches {
		bStart := m[1] - 1
		b := extractMethodBody(scanText, bStart)
		if offset >= bStart && offset < bStart+len(b) {
			return b, bStart, true
		}
	}
	return "", 0, false
}

func isInsideInitState(scanText string, offset int) bool {
	_, _, found := findEnclosingInitState(scanText, offset)
	return found
}

func initStateReadsBeforeConnect(scanText string, connectOffset int) bool {
	body, braceStart, found := findEnclosingInitState(scanText, connectOffset)
	if !found {
		return false
	}
	relOffset := connectOffset - braceStart
	logReadLoc := logReadRe.FindStringIndex(body)
	return logReadLoc != nil && logReadLoc[0] < relOffset
}

func isConnectSafe(scanText, clsBody string, offset int) bool {
	if isInsideInitState(scanText, offset) {
		return initStateReadsBeforeConnect(scanText, offset)
	}
	return hasEagerInitRead(clsBody) || hasScreenLevelWatch(clsBody)
}

func (r LazyStreamSubscriptionRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func checkLazyStreamBlock(b diffSourceBlock, text string, start int, seen map[string]bool) []Finding {
	if !connectTriggerRe.MatchString(text) || !serialLogsProvideRe.MatchString(text) {
		return nil
	}
	var findings []Finding
	connectMatches := connectTriggerRe.FindAllStringIndex(text, -1)
	for _, m := range connectMatches {
		offset := m[0]
		clsBody := enclosingClassBody(text, offset)
		if isConnectSafe(text, clsBody, offset) {
			continue
		}

		lineNum := start + strings.Count(text[:offset], "\n")
		if !shouldReportFinding(b, lineNum, false, seen) {
			continue
		}
		findings = append(findings, Finding{
			Rule:     "flutter-lazy-stream-listener",
			Severity: "high",
			File:     b.file,
			Line:     lineNum,
			Message:  "Broadcast stream connection initiated without eager log listener subscription in initState",
			Remediation: "Warm up the log stream provider subscription via " +
				"'ref.read(...LogsProvider)' in initState() before initiating connections to avoid dropping initial output.",
		})
	}
	return append([]Finding(nil), findings...)
}

func (r LazyStreamSubscriptionRule) CheckContext(ctx context.Context, diff string) []Finding {
	return executeBlockRule(ctx, diff, r.repositoryRoot, r.workingTree, func(f string) bool {
		return dartSourceFileRe.MatchString(f) && !isTestFile(f)
	}, checkLazyStreamBlock)
}
