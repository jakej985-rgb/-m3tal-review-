package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// CSharpAsyncRule detects critical C# async/await anti-patterns:
// 1. "async void" methods that are not UI/event handlers (causes unhandled exceptions to crash the process).
// 2. Sync-over-async blocking via .Result, .Wait(), or .GetAwaiter().GetResult() (causes thread pool starvation & deadlocks).
type CSharpAsyncRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (CSharpAsyncRule) Name() string {
	return "csharp-async-anti-pattern"
}

func (r CSharpAsyncRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	// async void MethodName(params)
	asyncVoidRe = regexp.MustCompile(
		`\basync\s+void\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)`,
	)
	eventParamRe = regexp.MustCompile(
		`(?i)(?:object\s+\w+,\s*[A-Za-z0-9_]*EventArgs\s+\w+|RoutedEventArgs\s+\w+)`,
	)

	// sync-over-async blocking patterns
	syncOverAsyncRe = regexp.MustCompile(
		`(?:\.GetAwaiter\s*\(\s*\)\s*\.\s*GetResult\s*\(\s*\)|(?:[a-zA-Z0-9_]+Async\s*\([^)]*\)|Task\.(?:Run|WhenAll|WhenAny|FromResult))\s*\.\s*(?:Result\b|Wait\s*\(\s*\)))`,
	)
)

func (r CSharpAsyncRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(strings.ToLower(filePath), ".cs") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r CSharpAsyncRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		findingLine := block.firstLine + i
		if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Check 1: async void
		if m := asyncVoidRe.FindStringSubmatch(line); len(m) > 1 {
			methodName := m[1]
			params := m[2]

			// Allow event handlers
			isEventHandler := eventParamRe.MatchString(params) ||
				strings.HasSuffix(methodName, "Click") ||
				strings.HasSuffix(methodName, "Clicked") ||
				strings.HasSuffix(methodName, "Handler") ||
				strings.HasPrefix(methodName, "On")

			if !isEventHandler {
				key := fmt.Sprintf("%s:%d:csharp-async-void", block.file, findingLine)
				if !seen[key] {
					seen[key] = true
					findings = append(findings, Finding{
						File:        block.file,
						Line:        findingLine,
						Rule:        "csharp-async-anti-pattern",
						Severity:    "high",
						Category:    "quality",
						Confidence:  "high",
						Message:     fmt.Sprintf("Avoid 'async void' on method %q; unhandled exceptions crash the runtime and cannot be awaited or caught. Return 'Task' instead.", methodName),
						Remediation: "Change return type from 'async void' to 'async Task' (or 'async ValueTask'). Only UI event handlers should use async void.",
					})
				}
			}
		}

		// Check 2: sync-over-async
		if syncOverAsyncRe.MatchString(line) {
			key := fmt.Sprintf("%s:%d:csharp-sync-over-async", block.file, findingLine)
			if !seen[key] {
				seen[key] = true
				findings = append(findings, Finding{
					File:        block.file,
					Line:        findingLine,
					Rule:        "csharp-async-anti-pattern",
					Severity:    "high",
					Category:    "quality",
					Confidence:  "high",
					Message:     "Sync-over-async hazard: blocking on asynchronous code via .Result, .Wait(), or .GetAwaiter().GetResult() risks thread pool starvation and synchronization deadlocks.",
					Remediation: "Make the calling method async and use 'await' instead of synchronously blocking on the Task.",
				})
			}
		}
	}

	return findings
}
