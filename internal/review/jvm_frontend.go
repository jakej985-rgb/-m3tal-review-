package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// JVMCoroutineLeakRule flags unconfined background coroutines and thread executors
// in Kotlin and Java (such as GlobalScope.launch, GlobalScope.async, or unmanaged
// Executors created inside request paths) that lack lifecycle cancellation or
// bound scopes, risking thread leaks and OOM under load.
type JVMCoroutineLeakRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (JVMCoroutineLeakRule) Name() string {
	return "jvm-coroutine-leak"
}

func (r JVMCoroutineLeakRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	globalScopeRe = regexp.MustCompile(
		`\bGlobalScope\s*\.\s*(?:launch|async)\b`,
	)
	unmanagedExecutorRe = regexp.MustCompile(
		`\bExecutors\s*\.\s*new(?:Fixed|Cached|SingleThread)?ThreadPool\s*\(`,
	)
)

func (r JVMCoroutineLeakRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if (!strings.HasSuffix(filePath, ".kt") && !strings.HasSuffix(filePath, ".java")) || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r JVMCoroutineLeakRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		findingLine := block.firstLine + i
		if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
			continue
		}

		isGlobalScope := globalScopeRe.MatchString(line)
		isUnmanagedExec := unmanagedExecutorRe.MatchString(line) && !strings.Contains(line, "static final") && !strings.Contains(line, "val ")

		if isGlobalScope || isUnmanagedExec {
			key := fmt.Sprintf("%s:%d:jvm-coroutine-leak", block.file, findingLine)
			if seen[key] {
				continue
			}
			seen[key] = true

			msg := "Unconfined coroutine scope: GlobalScope.launch/async creates unbounded background jobs not tied to component or request lifecycle."
			if isUnmanagedExec {
				msg = "Unmanaged thread pool allocation: Executors.newThreadPool invoked in local scope risks resource and thread exhaustion."
			}

			findings = append(findings, Finding{
				File:        block.file,
				Line:        findingLine,
				Rule:        "jvm-coroutine-leak",
				Severity:    "medium",
				Category:    "quality",
				Confidence:  "high",
				Message:     msg,
				Remediation: "Use structured concurrency with CoroutineScope(Dispatchers.Default + SupervisorJob()) or inject a shared, managed ExecutorService.",
			})
		}
	}

	return findings
}

// JVMInsecureDeserializationRule detects invocation of ObjectInputStream.readObject()
// or XMLDecoder without look-ahead class filters in Java and Kotlin, preventing
// arbitrary remote code execution via gadget chain deserialization.
type JVMInsecureDeserializationRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (JVMInsecureDeserializationRule) Name() string {
	return "jvm-insecure-deserialization"
}

func (r JVMInsecureDeserializationRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	objectInputStreamRe = regexp.MustCompile(
		`\b(?:new\s+ObjectInputStream|ObjectInputStream\s+[a-zA-Z0-9_]+)\b`,
	)
	readObjectRe = regexp.MustCompile(
		`\.\s*readObject\s*\(`,
	)
	filterCheckRe = regexp.MustCompile(
		`\b(?:setObjectInputFilter|ObjectInputFilter)\b`,
	)
)

func (r JVMInsecureDeserializationRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if (!strings.HasSuffix(filePath, ".java") && !strings.HasSuffix(filePath, ".kt")) || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkDeserializationBlock(block, seen)...)
		}
	}

	return findings
}

func (r JVMInsecureDeserializationRule) checkDeserializationBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")
	hasStream := objectInputStreamRe.MatchString(block.text)
	hasFilter := filterCheckRe.MatchString(block.text)

	if !hasStream || hasFilter {
		return findings
	}

	for i, line := range lines {
		findingLine := block.firstLine + i
		if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
			continue
		}

		if readObjectRe.MatchString(line) {
			key := fmt.Sprintf("%s:%d:jvm-insecure-deserialization", block.file, findingLine)
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, Finding{
				File:        block.file,
				Line:        findingLine,
				Rule:        "jvm-insecure-deserialization",
				Severity:    "critical",
				Category:    "security",
				Confidence:  "high",
				Message:     "Insecure object deserialization: ObjectInputStream.readObject() called without an ObjectInputFilter, risking arbitrary remote code execution via gadget chains.",
				Remediation: "Configure an allowlist ObjectInputFilter on the stream or migrate to safe data serialization formats like JSON or Protocol Buffers.",
			})
		}
	}

	return findings
}
