package review

import (
	"context"
	"regexp"
	"strconv"
	"strings"
)

// UnboundedBufferRule detects serial and socket stream accumulators that append incoming
// chunks to an in-memory buffer without enforcing an upper maximum buffer size limit.
// If corrupted streams, loose wires, or mismatched baud rates emit continuous binary noise
// without delimiter characters, unbounded buffers grow indefinitely until browser or app
// memory is exhausted.
type UnboundedBufferRule struct {
	ruleRuntime
}

func (UnboundedBufferRule) Name() string { return "unbounded-serial-buffer" }

var (
	bufferAccumulatorFileRe = regexp.MustCompile(`(?i)(?:serial|transport|socket|decoder|stream_parser).*\.(?:dart|ts|js|go|py|kt|java|cpp)$`)

	// chunkAccumulatorRe detects string or list concatenation of stream chunks
	chunkAccumulatorRe = regexp.MustCompile(`(?i)(?:_buffer\s*\+=\s*\w+|_buffer\.addAll\s*\(\s*\w+\s*\)|\bchunkAccumulator\s*\+=)`)

	// bufferClampCheckRe detects checking length against a maximum size limit
	bufferClampCheckRe = regexp.MustCompile(`(?i)(?:_buffer\.length\s*>\s*(?:maxBuffer|\d{3,})|maxBufferSize|MAX_BUFFER)`)
)

func (r UnboundedBufferRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

func (r UnboundedBufferRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if err := ctx.Err(); err != nil {
			return findings
		}
		if !bufferAccumulatorFileRe.MatchString(block.file) {
			continue
		}

		scanText := block.text
		startLine := block.firstLine
		if fullData, err := readRuleSource(r.repositoryRoot, block.file, r.workingTree); err == nil && len(fullData) > 0 {
			scanText = string(fullData)
			startLine = 1
		}

		// If buffer clamp is already implemented in the file, skip
		if bufferClampCheckRe.MatchString(scanText) {
			continue
		}

		lines := strings.Split(scanText, "\n")
		for i, line := range lines {
			lineNum := startLine + i
			trimmed := strings.TrimSpace(line)

			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/*") {
				continue
			}

			if chunkAccumulatorRe.MatchString(trimmed) {
				if block.addedLines[lineNum] || r.workingTree || len(block.addedLines) > 0 {
					key := block.file + ":" + strconv.Itoa(lineNum)
					if !seen[key] {
						seen[key] = true
						findings = append(findings, Finding{
							Rule:        "unbounded-serial-buffer",
							Severity:    "medium",
							File:        block.file,
							Line:        lineNum,
							Message:     "Serial stream chunk accumulator appends incoming data without enforcing a maximum buffer size clamp",
							Remediation: "Enforce a maximum buffer limit (e.g. 4096-8192 bytes) and drain/reset the buffer if no delimiter is encountered to prevent memory exhaustion.",
						})
					}
				}
			}
		}
	}

	return findings
}
