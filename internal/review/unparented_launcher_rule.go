package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// UnparentedLauncherRule detects child-directed application screens that invoke external
// browser launchers (`launchUrl`, `launch`, `window.open`) directly without gating the
// action behind a parental authorization check (e.g. `ParentGateDialog` or parent session verification).
// COPPA and App Store Child Safety guidelines require parental consent before learners can be
// navigated away to arbitrary third-party web destinations.
type UnparentedLauncherRule struct {
	ruleRuntime
}

func (UnparentedLauncherRule) Name() string { return "unparented-external-launcher" }

var (
	childUiFileRe = regexp.MustCompile(`(?i)(?:feature|screen|view|dialog).*\.(?:dart|ts|js)$`)

	// externalLauncherCallRe matches invoking external URL launchers
	externalLauncherCallRe = regexp.MustCompile(`\b(?:launchUrl|launch|canLaunchUrl)\s*\(`)

	// parentGateCheckRe matches parent authorization or gate dialogs
	parentGateCheckRe = regexp.MustCompile(`(?i)(?:parentGate|ParentGateDialog|parentSession|isParentSessionActive|verifyParent)`)

	// allowedParentScreenRe matches screens that are already restricted to parents
	allowedParentScreenRe = regexp.MustCompile(`(?i)(?:parent_screen|parent_settings|parent_gate|test/)`)
)

func (r UnparentedLauncherRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r UnparentedLauncherRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !childUiFileRe.MatchString(block.file) || allowedParentScreenRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// If the file already verifies parent session or shows ParentGateDialog, skip
		if parentGateCheckRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			if externalLauncherCallRe.MatchString(trimmed) {
				if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "unparented-external-launcher",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "Child-facing screen launches external URL without verifying parental gate authorization",
							Remediation: "Route external URL launches through ParentGateDialog or verify parental authorization before opening third-party web content.",
						})
					}
				}
			}
		}
	}

	return findings
}
