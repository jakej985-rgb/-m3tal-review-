package review

import (
	"context"
	"fmt"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/model"
)

// DeactivatedContextRule detects inherited widget lookups and BuildContext operations
// inside State.dispose(), preventing runtime assertion exceptions against deactivated element ancestors.
type DeactivatedContextRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (DeactivatedContextRule) Name() string {
	return "deactivated-context-lifecycle"
}

func (r *DeactivatedContextRule) EnableWorkingTree() {
	r.WorkingTree = true
}

func (r DeactivatedContextRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r DeactivatedContextRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(strings.ToLower(filePath), ".dart") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		if r.RepositoryRoot != "" {
			if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
				blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
			}
		}

		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r DeactivatedContextRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	currentMethod := ""
	methodBaseDepth := 0
	currentBraceDepth := 0

	for i, line := range lines {
		lineNum := block.firstLine + i

		if m := methodDeclRe.FindStringSubmatch(line); len(m) > 1 {
			currentMethod = m[1]
			methodBaseDepth = currentBraceDepth
		}

		for _, ch := range line {
			if ch == '{' {
				currentBraceDepth++
			} else if ch == '}' {
				currentBraceDepth--
				if currentMethod != "" && currentBraceDepth <= methodBaseDepth {
					currentMethod = ""
				}
			}
		}

		if currentMethod == "dispose" && deactivatedContextRe.MatchString(line) && block.addedLines[lineNum] {
			m := deactivatedContextRe.FindString(line)
			op := strings.TrimSuffix(m, "(")
			key := fmt.Sprintf("%s:%d:dispose-deactivated-%s", block.file, lineNum, op)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        "deactivated-context-lifecycle",
					Severity:    "high",
					Category:    "quality",
					File:        block.file,
					Line:        lineNum,
					Message:     fmt.Sprintf("Calling %s() inside dispose() attempts to query deactivated widget element ancestors and throws runtime assertions", op),
					Remediation: "Remove context-dependent lookups from dispose(); perform cleanup on listeners, subscriptions, and controllers directly.",
					Confidence:  "High",
					Explanation: &model.FindingExplanation{
						RuleRationale:   "In Flutter, State.dispose() is called after the widget element is permanently removed from the tree; lookups to inherited ancestors or BuildContext will fail with runtime assertions.",
						EvidenceSummary: fmt.Sprintf("%s invoked during dispose() lifecycle.", op),
						EvidenceKind:    "lifecycle-violation",
					},
				})
			}
		}
	}

	return findings
}

// WatchOutsideBuildRule detects context.watch() or ref.watch() called outside of
// Widget build() methods or inside user event callbacks, preventing runtime exceptions
// and leaked reactive subscriptions.
type WatchOutsideBuildRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (WatchOutsideBuildRule) Name() string {
	return "watch-outside-build"
}

func (r *WatchOutsideBuildRule) EnableWorkingTree() {
	r.WorkingTree = true
}

func (r WatchOutsideBuildRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r WatchOutsideBuildRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(strings.ToLower(filePath), ".dart") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		if r.RepositoryRoot != "" {
			if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
				blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
			}
		}

		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r WatchOutsideBuildRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	currentMethod := ""
	methodBaseDepth := 0
	var callbackDepthStack []int
	currentBraceDepth := 0

	for i, line := range lines {
		lineNum := block.firstLine + i

		if m := methodDeclRe.FindStringSubmatch(line); len(m) > 1 {
			currentMethod = m[1]
			methodBaseDepth = currentBraceDepth
		}

		cbSpans := eventCallbackRe.FindAllStringIndex(line, -1)
		cbIdx := 0
		watchMatches := watchOutsideBuildRe.FindAllStringIndex(line, -1)
		watchIdx := 0
		inArrowCallback := false

		for j := 0; j < len(line); {
			// Check if a watch expression begins at j
			if watchIdx < len(watchMatches) && j == watchMatches[watchIdx][0] {
				if block.addedLines[lineNum] {
					inCallback := len(callbackDepthStack) > 0 || inArrowCallback
					isWatchViolation := false
					violationMsg := ""

					if inCallback {
						isWatchViolation = true
						violationMsg = "Calling context.watch() inside an event callback runs on user interaction rather than during build, causing runtime exceptions; use context.read() instead"
					} else if currentMethod != "" && currentMethod != "build" {
						isWatchViolation = true
						violationMsg = "Calling context.watch() or ref.watch() outside of Widget build() causes runtime exceptions and leaks subscriptions; use context.read() or ref.read() instead"
					}

					if isWatchViolation {
						key := fmt.Sprintf("%s:%d:watch-outside-build", block.file, lineNum)
						if !seen[key] {
							seen[key] = true
							findings = append(findings, Finding{
								Rule:        "watch-outside-build",
								Severity:    "high",
								Category:    "quality",
								File:        block.file,
								Line:        lineNum,
								Message:     violationMsg,
								Remediation: "Use context.read() or ref.read() in callbacks and async methods.",
								Confidence:  "High",
								Explanation: &model.FindingExplanation{
									RuleRationale:   "Reactive subscriptions (watch) must only be registered during Widget build().",
									EvidenceSummary: "watch() invoked outside build().",
									EvidenceKind:    "lifecycle-violation",
								},
							})
						}
					}
				}
				watchIdx++
			}

			// Check if a callback begins at j
			if cbIdx < len(cbSpans) && j == cbSpans[cbIdx][0] {
				cbEnd := cbSpans[cbIdx][1]
				cbStr := line[j:cbEnd]
				if strings.Contains(cbStr, "=>") {
					inArrowCallback = true
				} else if strings.Contains(cbStr, "{") {
					currentBraceDepth++
					callbackDepthStack = append(callbackDepthStack, currentBraceDepth)
				}
				cbIdx++
				j = cbEnd
				continue
			}

			ch := line[j]
			if ch == '{' {
				currentBraceDepth++
			} else if ch == '}' {
				if len(callbackDepthStack) > 0 && currentBraceDepth <= callbackDepthStack[len(callbackDepthStack)-1] {
					callbackDepthStack = callbackDepthStack[:len(callbackDepthStack)-1]
				}
				currentBraceDepth--
				if currentMethod != "" && currentBraceDepth <= methodBaseDepth {
					currentMethod = ""
				}
			} else if ch == ';' || ch == ',' {
				inArrowCallback = false
			}
			j++
		}
	}

	return findings
}

// LifecycleSetStateRule detects setState() calls inside initState() or dispose(),
// where widget re-rendering cannot occur and runtime exceptions are thrown.
type LifecycleSetStateRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (LifecycleSetStateRule) Name() string {
	return "invalid-lifecycle-setstate"
}

func (r *LifecycleSetStateRule) EnableWorkingTree() {
	r.WorkingTree = true
}

func (r LifecycleSetStateRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r LifecycleSetStateRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(strings.ToLower(filePath), ".dart") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		if r.RepositoryRoot != "" {
			if source, err := readRuleSource(r.RepositoryRoot, fileDiff.Path, r.WorkingTree); err == nil {
				blocks = []diffSourceBlock{fullSourceBlock(fileDiff.Path, source, fileDiff.AddedLines)}
			}
		}

		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r LifecycleSetStateRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	currentMethod := ""
	methodBaseDepth := 0
	currentBraceDepth := 0

	for i, line := range lines {
		lineNum := block.firstLine + i

		if m := methodDeclRe.FindStringSubmatch(line); len(m) > 1 {
			currentMethod = m[1]
			methodBaseDepth = currentBraceDepth
		}

		for _, ch := range line {
			if ch == '{' {
				currentBraceDepth++
			} else if ch == '}' {
				currentBraceDepth--
				if currentMethod != "" && currentBraceDepth <= methodBaseDepth {
					currentMethod = ""
				}
			}
		}

		if (currentMethod == "initState" || currentMethod == "dispose") && setStateRe.MatchString(line) && block.addedLines[lineNum] {
			key := fmt.Sprintf("%s:%d:lifecycle-%s-setstate", block.file, lineNum, currentMethod)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        "invalid-lifecycle-setstate",
					Severity:    "high",
					Category:    "quality",
					File:        block.file,
					Line:        lineNum,
					Message:     fmt.Sprintf("Calling setState() inside %s() throws or is redundant; the framework cannot re-render unmounted/building widgets", currentMethod),
					Remediation: fmt.Sprintf("In %s(), assign state variables directly without calling setState().", currentMethod),
					Confidence:  "High",
					Explanation: &model.FindingExplanation{
						RuleRationale:   "Calling setState inside initState or dispose is invalid because the widget element cannot be scheduled for re-rendering.",
						EvidenceSummary: fmt.Sprintf("setState() invoked inside %s().", currentMethod),
						EvidenceKind:    "lifecycle-violation",
					},
				})
			}
		}
	}

	return findings
}
