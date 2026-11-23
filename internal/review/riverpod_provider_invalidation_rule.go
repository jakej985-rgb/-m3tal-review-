package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// RiverpodProviderInvalidationRule detects StateNotifier or Riverpod controller
// mutators that persist or delete records via backing repositories without invalidating
// or refreshing associated query providers (e.g. allProfilesProvider).
// Omitting ref.invalidate leaves cached collection queries stale across the app.
type RiverpodProviderInvalidationRule struct {
	ruleRuntime
}

func (RiverpodProviderInvalidationRule) Name() string {
	return "riverpod-stale-provider-mutation"
}

var (
	riverpodProviderFileRe = regexp.MustCompile(`(?i)(?:provider|notifier|controller|view_?model).*\.dart$`)

	// riverpodNotifierClassRe matches StateNotifier or Notifier classes
	riverpodNotifierClassRe = regexp.MustCompile(`class\s+\w+\s+extends\s+(?:StateNotifier|Notifier|AsyncNotifier)<`)

	// mutationMethodRe matches save/delete/create/remove methods in notifiers
	mutationMethodRe = regexp.MustCompile(`(?m)^\s*Future<[^>]*>\s*(save\w+|delete\w+|create\w+|remove\w+)\s*\([^)]*\)\s*async\s*\{`)

	// repoMutationCallRe detects calls to repo mutation methods
	repoMutationCallRe = regexp.MustCompile(`\b_?(?:\w*repo|\w*repository|\w*datasource)\s*\.\s*(?:save\w+|delete\w+|create\w+|remove\w+)\s*\(`)

	// providerInvalidateRe detects cache invalidation or refresh
	providerInvalidateRe = regexp.MustCompile(`\b(?:_?ref\s*\.\s*(?:invalidate|refresh)|state\s*=\s*)`)
)

func (r RiverpodProviderInvalidationRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r RiverpodProviderInvalidationRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !riverpodProviderFileRe.MatchString(block.file) || isTestFile(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		if !riverpodNotifierClassRe.MatchString(scanText) {
			continue
		}

		methodMatches := mutationMethodRe.FindAllStringIndex(scanText, -1)
		for _, m := range methodMatches {
			bodyStart := m[1]
			// Find closing brace or next method
			bodyEnd := len(scanText)
			if nextMethod := mutationMethodRe.FindStringIndex(scanText[bodyStart:]); nextMethod != nil {
				bodyEnd = bodyStart + nextMethod[0]
			}
			body := scanText[bodyStart:bodyEnd]

			// Must perform a backing repository mutation
			if !repoMutationCallRe.MatchString(body) {
				continue
			}

			// If it does not invalidate cached providers
			if !strings.Contains(body, "invalidate") && !strings.Contains(body, "refresh") {
				lineNum := startLine + strings.Count(scanText[:m[0]], "\n")
				if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "riverpod-stale-provider-mutation",
							Severity:    "high",
							File:        block.file,
							Line:        lineNum,
							Message:     "Notifier mutator writes to backing repository without invalidating cached collection providers",
							Remediation: "Call ref.invalidate(queryProvider) or ref.refresh(queryProvider) after mutating backing storage to ensure cached lists update immediately.",
						})
					}
				}
			}
		}
	}

	return findings
}
