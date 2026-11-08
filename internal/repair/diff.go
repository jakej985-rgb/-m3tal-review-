package repair

import (
	"fmt"
	"path/filepath"
	"strings"
)

// FileToAddedDiff converts whole-file content into an added-file unified diff.
func FileToAddedDiff(filename, content string) string {
	normPath := filepath.ToSlash(filepath.Clean(filename))
	normPath = strings.TrimPrefix(normPath, "/")
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	newStart := 1
	if len(lines) == 0 {
		newStart = 0
	}
	var b strings.Builder
	fmt.Fprintf(&b, "--- /dev/null\n+++ b/%s\n", normPath)
	fmt.Fprintf(&b, "@@ -0,0 +%d,%d @@\n", newStart, len(lines))
	for _, line := range lines {
		b.WriteByte('+')
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// GenerateUnifiedDiff generates a standard unified diff between original and proposed content.
func GenerateUnifiedDiff(filename, original, proposed string) string {
	if original == proposed {
		return ""
	}

	origLines := splitLines(original)
	propLines := splitLines(proposed)

	// Compute edit operations via LCS
	ops := computeDiffOps(origLines, propLines)

	// Group edits into hunks with context
	hunks := groupHunks(ops, 3)
	if len(hunks) == 0 {
		return ""
	}

	normPath := strings.TrimPrefix(filename, "/")
	var b strings.Builder
	fmt.Fprintf(&b, "--- a/%s\n", normPath)
	fmt.Fprintf(&b, "+++ b/%s\n", normPath)

	for _, h := range hunks {
		fmt.Fprintf(&b, "@@ -%d,%d +%d,%d @@\n", h.oldStart, h.oldCount, h.newStart, h.newCount)
		for _, line := range h.lines {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	return b.String()
}

func splitLines(s string) []string {
	if s == "" {
		return []string{}
	}
	// Normalize \r\n to \n
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

type diffOpType int

const (
	opEqual diffOpType = iota
	opDelete
	opInsert
)

type diffOp struct {
	op   diffOpType
	text string
}

func computeDiffOps(orig, prop []string) []diffOp {
	n := len(orig)
	m := len(prop)

	// Trim common prefix
	prefix := 0
	for prefix < n && prefix < m && orig[prefix] == prop[prefix] {
		prefix++
	}

	// Trim common suffix
	suffix := 0
	for suffix < (n-prefix) && suffix < (m-prefix) && orig[n-1-suffix] == prop[m-1-suffix] {
		suffix++
	}

	var ops []diffOp
	for i := 0; i < prefix; i++ {
		ops = append(ops, diffOp{op: opEqual, text: orig[i]})
	}

	midOrig := orig[prefix : n-suffix]
	midProp := prop[prefix : m-suffix]

	if len(midOrig) > 0 || len(midProp) > 0 {
		midOps := lcsDiffOps(midOrig, midProp)
		ops = append(ops, midOps...)
	}

	for i := n - suffix; i < n; i++ {
		ops = append(ops, diffOp{op: opEqual, text: orig[i]})
	}

	return ops
}

func lcsDiffOps(orig, prop []string) []diffOp {
	n := len(orig)
	m := len(prop)

	if n == 0 {
		ops := make([]diffOp, m)
		for j := 0; j < m; j++ {
			ops[j] = diffOp{op: opInsert, text: prop[j]}
		}
		return ops
	}
	if m == 0 {
		ops := make([]diffOp, n)
		for i := 0; i < n; i++ {
			ops[i] = diffOp{op: opDelete, text: orig[i]}
		}
		return ops
	}

	// DP table for LCS
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}

	for i := 1; i <= n; i++ {
		for j := 1; j <= m; j++ {
			if orig[i-1] == prop[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}

	// Backtrack to build edit sequence
	var ops []diffOp
	i, j := n, m
	for i > 0 || j > 0 {
		if i > 0 && j > 0 && orig[i-1] == prop[j-1] {
			ops = append(ops, diffOp{op: opEqual, text: orig[i-1]})
			i--
			j--
		} else if j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]) {
			ops = append(ops, diffOp{op: opInsert, text: prop[j-1]})
			j--
		} else if i > 0 && (j == 0 || dp[i-1][j] > dp[i][j-1]) {
			ops = append(ops, diffOp{op: opDelete, text: orig[i-1]})
			i--
		}
	}

	// Reverse ops to chronological order
	for left, right := 0, len(ops)-1; left < right; left, right = left+1, right-1 {
		ops[left], ops[right] = ops[right], ops[left]
	}

	return ops
}

type hunk struct {
	oldStart int
	oldCount int
	newStart int
	newCount int
	lines    []string
}

func groupHunks(ops []diffOp, contextLines int) []hunk {
	if len(ops) == 0 {
		return nil
	}

	var hunks []hunk
	var currentHunk *hunk
	origLine := 1
	propLine := 1

	for idx := 0; idx < len(ops); idx++ {
		op := ops[idx]
		switch op.op {
		case opEqual:
			if currentHunk != nil {
				// Count consecutive equal lines ahead
				eqCount := 0
				for k := idx; k < len(ops) && ops[k].op == opEqual; k++ {
					eqCount++
				}
				if eqCount > contextLines*2 {
					// Add trailing context lines
					trailing := contextLines
					if trailing > eqCount {
						trailing = eqCount
					}
					for k := 0; k < trailing; k++ {
						currentHunk.lines = append(currentHunk.lines, " "+ops[idx+k].text)
						currentHunk.oldCount++
						currentHunk.newCount++
					}
					hunks = append(hunks, *currentHunk)
					currentHunk = nil
					idx += trailing - 1
					origLine += trailing
					propLine += trailing
					continue
				} else {
					currentHunk.lines = append(currentHunk.lines, " "+op.text)
					currentHunk.oldCount++
					currentHunk.newCount++
				}
			}
			origLine++
			propLine++

		case opDelete, opInsert:
			if currentHunk == nil {
				// Start a new hunk with leading context lines
				leadStart := idx - contextLines
				if leadStart < 0 {
					leadStart = 0
				}
				leadCount := idx - leadStart
				h := hunk{
					oldStart: origLine - leadCount,
					oldCount: 0,
					newStart: propLine - leadCount,
					newCount: 0,
				}
				if h.oldStart < 1 {
					h.oldStart = 1
				}
				if h.newStart < 1 {
					h.newStart = 1
				}
				for k := leadStart; k < idx; k++ {
					h.lines = append(h.lines, " "+ops[k].text)
					h.oldCount++
					h.newCount++
				}
				currentHunk = &h
			}

			if op.op == opDelete {
				currentHunk.lines = append(currentHunk.lines, "-"+op.text)
				currentHunk.oldCount++
				origLine++
			} else {
				currentHunk.lines = append(currentHunk.lines, "+"+op.text)
				currentHunk.newCount++
				propLine++
			}
		}
	}

	if currentHunk != nil {
		hunks = append(hunks, *currentHunk)
	}

	return hunks
}
