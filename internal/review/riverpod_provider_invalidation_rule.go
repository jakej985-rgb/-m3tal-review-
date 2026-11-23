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
	mutationMethodRe = regexp.MustCompile(`(?m)^\s*Future<[^>]*>\s*(save\w*|delete\w*|create\w*|remove\w*)\s*\([^)]*\)\s*async\s*\{`)

	// repoMutationCallRe detects calls to repo mutation methods
	repoMutationCallRe = regexp.MustCompile(`\b_?(?:\w*repo|\w*repository|\w*datasource)\s*\.\s*(?:save\w*|delete\w*|create\w*|remove\w*)\s*\(`)

	// providerInvalidateCallRe detects cache invalidation or refresh of providers on ref
	providerInvalidateCallRe = regexp.MustCompile(`\b_?ref\s*\.\s*(?:invalidate|refresh)\s*\(\s*([a-zA-Z0-9_]+)`)
)

func extractMethodBody(src string, braceStart int) string {
	depth := 0
	inString := byte(0)
	inLineComment := false
	inBlockComment := false
	for i := braceStart; i < len(src); i++ {
		ch := src[i]
		if inLineComment {
			if ch == '\n' {
				inLineComment = false
			}
			continue
		}
		if inBlockComment {
			if ch == '*' && i+1 < len(src) && src[i+1] == '/' {
				inBlockComment = false
				i++
			}
			continue
		}
		if inString != 0 {
			if ch == '\\' {
				i++
				continue
			}
			if ch == inString {
				inString = 0
			}
			continue
		}
		if ch == '/' && i+1 < len(src) {
			if src[i+1] == '/' {
				inLineComment = true
				i++
				continue
			} else if src[i+1] == '*' {
				inBlockComment = true
				i++
				continue
			}
		}
		if ch == '"' || ch == '\'' {
			inString = ch
			continue
		}
		if ch == '{' {
			depth++
		} else if ch == '}' {
			depth--
			if depth <= 0 {
				return src[braceStart : i+1]
			}
		}
	}
	return src[braceStart:]
}

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
			braceStart := m[1] - 1
			body := extractMethodBody(scanText, braceStart)

			// Must perform a backing repository mutation
			loc := repoMutationCallRe.FindStringIndex(body)
			if loc == nil {
				continue
			}

			// Invalidation or refresh of provider must occur after repository mutation
			afterMutation := body[loc[1]:]
			if !providerInvalidateCallRe.MatchString(afterMutation) {
				lineNum := startLine + strings.Count(scanText[:m[0]], "\n")
				if len(block.addedLines) > 0 && !block.addedLines[lineNum] {
					continue
				}
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

	return findings
}
