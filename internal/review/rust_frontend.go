package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// RustSafetyRule requires all unsafe blocks and unsafe functions in Rust code
// to be documented with a preceding "// SAFETY:" comment explaining the invariants
// and proof of soundness, conforming to standard Rust safety guidelines.
type RustSafetyRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (RustSafetyRule) Name() string {
	return "rust-unsafe-safety-rationale"
}

func (r RustSafetyRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	unsafeDeclRe = regexp.MustCompile(
		`\bunsafe\s*(?:\{|fn\b|trait\b|impl\b)`,
	)
	safetyCommentRe = regexp.MustCompile(
		`(?i)//[/!*]?\s*SAFETY\s*:`,
	)
)

func (r RustSafetyRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(filePath, ".rs") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r RustSafetyRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comment lines containing unsafe
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if !unsafeDeclRe.MatchString(line) {
			continue
		}

		findingLine := block.firstLine + i
		if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
			continue
		}

		// Look backwards up to 6 lines for a // SAFETY: rationale
		hasSafetyRationale := false
		start := i - 6
		if start < 0 {
			start = 0
		}
		for j := start; j < i; j++ {
			if safetyCommentRe.MatchString(lines[j]) {
				hasSafetyRationale = true
				break
			}
		}

		if !hasSafetyRationale {
			key := fmt.Sprintf("%s:%d:rust-unsafe-safety-rationale", block.file, findingLine)
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, Finding{
				File:        block.file,
				Line:        findingLine,
				Rule:        "rust-unsafe-safety-rationale",
				Severity:    "medium",
				Category:    "quality",
				Confidence:  "high",
				Message:     "Undocumented unsafe operation: unsafe block or function lacks a preceding '// SAFETY:' rationale explaining why the operation is sound.",
				Remediation: "Add a preceding '// SAFETY: <explanation>' comment detailing the invariants that make this unsafe operation memory-safe and sound.",
			})
		}
	}

	return findings
}

// RustFFIPanicRule detects Rust functions exposed across FFI boundaries (extern "C")
// that invoke potentially panicking operations without wrapping execution in
// std::panic::catch_unwind. Unwinding across foreign function boundaries is undefined
// behavior and results in immediate process termination or memory corruption.
type RustFFIPanicRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (RustFFIPanicRule) Name() string {
	return "rust-ffi-unwind"
}

func (r RustFFIPanicRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	externCRe = regexp.MustCompile(
		`\b(?:pub\s+)?extern\s+"C"\s+fn\s+([a-zA-Z0-9_]+)`,
	)
	panickingOpRe = regexp.MustCompile(
		`(?:\.unwrap\s*\(|\.expect\s*\(|\bpanic!\s*\(|\bunreachable!\s*\(|\btodo!\s*\()`,
	)
	catchUnwindRe = regexp.MustCompile(
		`\b(?:catch_unwind|std::panic::catch_unwind)\b`,
	)
)

func (r RustFFIPanicRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(filePath, ".rs") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkFFIBlock(block, seen)...)
		}
	}

	return findings
}

func (r RustFFIPanicRule) checkFFIBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		m := externCRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}

		findingLine := block.firstLine + i
		if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
			continue
		}

		// Inspect function body
		fnChunk := strings.Join(lines[i:], "\n")
		braceIdx := strings.Index(fnChunk, "{")
		idxClose := findMatchingBrace(fnChunk, braceIdx)

		var fnBody string
		if idxClose > 0 && idxClose <= len(fnChunk) {
			fnBody = fnChunk[:idxClose]
		} else {
			end := i + 35
			if end > len(lines) {
				end = len(lines)
			}
			fnBody = strings.Join(lines[i:end], "\n")
		}

		hasPanicOp := panickingOpRe.MatchString(fnBody)
		hasCatchUnwind := catchUnwindRe.MatchString(fnBody)

		if hasPanicOp && !hasCatchUnwind {
			key := fmt.Sprintf("%s:%d:rust-ffi-unwind", block.file, findingLine)
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, Finding{
				File:        block.file,
				Line:        findingLine,
				Rule:        "rust-ffi-unwind",
				Severity:    "high",
				Category:    "security",
				Confidence:  "high",
				Message:     fmt.Sprintf("FFI panic unwind hazard: extern \"C\" function %q performs panicking operations without std::panic::catch_unwind.", m[1]),
				Remediation: "Wrap the function body in std::panic::catch_unwind(...) and translate panics into an error return code to prevent undefined behavior across FFI boundaries.",
			})
		}
	}

	return findings
}

// RustAsyncLockRule detects synchronous locks (std::sync::Mutex or parking_lot::Mutex)
// acquired inside async functions or blocks that cross .await points, which starves
// async runtime worker threads and can cause deadlocks.
type RustAsyncLockRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (RustAsyncLockRule) Name() string {
	return "rust-async-lock-hazard"
}

func (r RustAsyncLockRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	asyncFnRe = regexp.MustCompile(`\basync\s+(?:unsafe\s+)?fn\s+([a-zA-Z0-9_]+)`)
	syncLockAcquireRe = regexp.MustCompile(`\b(?:std::sync::Mutex|parking_lot::Mutex|[a-zA-Z0-9_]+)\.lock\s*\(\s*\)`)
	awaitCallRe = regexp.MustCompile(`\b[a-zA-Z0-9_().]+?\.await\b`)
)

func (r RustAsyncLockRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(filePath, ".rs") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkAsyncLockBlock(block, seen)...)
		}
	}

	return findings
}

func (r RustAsyncLockRule) checkAsyncLockBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	lines := strings.Split(block.text, "\n")

	for i, line := range lines {
		m := asyncFnRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}

		findingLine := block.firstLine + i
		fnChunk := strings.Join(lines[i:], "\n")
		braceIdx := strings.Index(fnChunk, "{")
		idxClose := findMatchingBrace(fnChunk, braceIdx)

		var fnBody string
		if idxClose > 0 && idxClose <= len(fnChunk) {
			fnBody = fnChunk[:idxClose]
		} else {
			end := i + 40
			if end > len(lines) {
				end = len(lines)
			}
			fnBody = strings.Join(lines[i:end], "\n")
		}

		hasSyncLock := false
		for _, bodyLine := range strings.Split(fnBody, "\n") {
			if strings.Contains(bodyLine, "tokio::sync::Mutex") || strings.Contains(bodyLine, "async_std") {
				continue
			}
			if strings.Contains(bodyLine, ".lock().await") {
				continue
			}
			if syncLockAcquireRe.MatchString(bodyLine) || strings.Contains(bodyLine, "std::sync::Mutex") || strings.Contains(bodyLine, "parking_lot::Mutex") {
				hasSyncLock = true
				break
			}
		}

		// Check if function contains both a synchronous lock acquisition and .await
		if hasSyncLock && awaitCallRe.MatchString(fnBody) {
			key := fmt.Sprintf("%s:%d:rust-async-lock-hazard", block.file, findingLine)
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, Finding{
				File:        block.file,
				Line:        findingLine,
				Rule:        "rust-async-lock-hazard",
				Severity:    "high",
				Category:    "concurrency",
				Confidence:  "high",
				Message:     fmt.Sprintf("Synchronous lock held across .await hazard: async fn %q acquires a synchronous mutex and performs .await, risking executor thread starvation and deadlock.", m[1]),
				Remediation: "Use tokio::sync::Mutex (or async_std::sync::Mutex) instead of std::sync::Mutex / parking_lot, or drop the lock guard before awaiting.",
			})
		}
	}

	return findings
}

