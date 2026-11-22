package review

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// FlutterSemanticsRule verifies that button and interactive Semantics widgets
// provide an activation action (e.g., onTap) when descendant semantics are excluded
// or when wrapping custom pointer gesture handlers. Without an explicit action handler,
// screen readers announce an interactive button to users, but activating it via
// accessibility actions (SemanticsAction.tap) is completely inoperable.
type FlutterSemanticsRule struct {
	RepositoryRoot string
	WorkingTree    bool
}

func (FlutterSemanticsRule) Name() string {
	return "flutter-semantics-action"
}

func (r FlutterSemanticsRule) Check(diff string) []Finding {
	return r.CheckContext(context.Background(), diff)
}

var (
	semanticsButtonRe = regexp.MustCompile(
		`\bSemantics\s*\([^)]*?\b(?:button|link)\s*:\s*true`,
	)
	excludeSemanticsRe = regexp.MustCompile(
		`\bexcludeSemantics\s*:\s*true\b`,
	)
	gestureTapRe = regexp.MustCompile(
		`\b(?:GestureDetector|InkWell|InkResponse)\s*\([^)]*?\bonTap\s*:\s*([a-zA-Z0-9_.]+)`,
	)
)

func (r FlutterSemanticsRule) CheckContext(ctx context.Context, diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, fileDiff := range ParseDiff(diff) {
		if err := ctx.Err(); err != nil {
			return findings
		}

		filePath := fileDiff.Path
		if !strings.HasSuffix(filePath, ".dart") || isTestFile(filePath) {
			continue
		}

		blocks := fileDiffSourceBlocks(fileDiff)
		for _, block := range blocks {
			findings = append(findings, r.checkBlock(block, seen)...)
		}
	}

	return findings
}

func (r FlutterSemanticsRule) checkBlock(block diffSourceBlock, seen map[string]bool) []Finding {
	var findings []Finding
	source := block.text
	lines := strings.Split(source, "\n")

	// Scan for Semantics( calls in the source block
	for i, line := range lines {
		if !strings.Contains(line, "Semantics") {
			continue
		}

		// Look ahead in the block to examine the Semantics invocation
		semanticsChunk := strings.Join(lines[i:], "\n")
		// Find matching parentheses or end of constructor
		idxClose := findMatchingParen(semanticsChunk, strings.Index(semanticsChunk, "("))
		var constructorBody string
		if idxClose > 0 && idxClose <= len(semanticsChunk) {
			constructorBody = semanticsChunk[:idxClose]
		} else {
			// Fallback: look at next 30 lines
			endIdx := i + 30
			if endIdx > len(lines) {
				endIdx = len(lines)
			}
			constructorBody = strings.Join(lines[i:endIdx], "\n")
		}

		// Check if it declares a button or link role
		hasButtonRole := strings.Contains(constructorBody, "button: true") ||
			strings.Contains(constructorBody, "link: true") ||
			semanticsButtonRe.MatchString(constructorBody)

		if !hasButtonRole {
			continue
		}

		// Check if excludeSemantics is set to true
		hasExcludeSemantics := excludeSemanticsRe.MatchString(constructorBody)

		// Check if outer Semantics itself has an onTap handler
		hasOuterOnTap := false
		for _, argLine := range strings.Split(constructorBody, "\n") {
			trimmed := strings.TrimSpace(argLine)
			if strings.HasPrefix(trimmed, "onTap:") || strings.HasPrefix(trimmed, "onTap :") {
				hasOuterOnTap = true
				break
			}
			// Stop if child: parameter begins
			if strings.HasPrefix(trimmed, "child:") || strings.HasPrefix(trimmed, "child :") {
				break
			}
		}

		if hasOuterOnTap {
			continue
		}

		// Look ahead in the full widget subtree for child gestures
		restOfBlock := strings.Join(lines[i:], "\n")
		hasChildGesture := gestureTapRe.MatchString(restOfBlock) ||
			strings.Contains(restOfBlock, "GestureDetector") ||
			strings.Contains(restOfBlock, "InkWell")

		if hasExcludeSemantics || hasChildGesture {
			// Determine best line number to report:
			// If excludeSemantics line exists, report that; otherwise report Semantics( line
			findingLine := block.firstLine + i
			for j := i; j < len(lines) && j < i+25; j++ {
				if strings.Contains(lines[j], "excludeSemantics: true") {
					findingLine = block.firstLine + j
					break
				}
			}

			// Only report if within modified hunk/added lines (or if whole block is added)
			if len(block.addedLines) > 0 && !block.addedLines[findingLine] {
				// Check if any line in the Semantics constructor is added
				anyAdded := false
				for j := i; j < len(lines) && j < i+15; j++ {
					if block.addedLines[block.firstLine+j] {
						anyAdded = true
						break
					}
				}
				if !anyAdded {
					continue
				}
			}

			key := fmt.Sprintf("%s:%d:flutter-semantics-action", block.file, findingLine)
			if seen[key] {
				continue
			}
			seen[key] = true

			findings = append(findings, Finding{
				File:        block.file,
				Line:        findingLine,
				Rule:        "flutter-semantics-action",
				Severity:    "high",
				Category:    "quality",
				Confidence:  "high",
				Message:     "Inoperable button for screen readers: Semantics exposes a button without an activation action. Excluding GestureDetector semantics removes the tap action.",
				Remediation: "Set the outer Semantics.onTap to the tap callback (e.g. widget.onTap) while keeping descendant semantics excluded so assistive technologies can trigger the button.",
			})
		}
	}

	return findings
}

// findMatchingParen finds the index of the matching closing parenthesis.
func findMatchingParen(s string, openIdx int) int {
	if openIdx < 0 || openIdx >= len(s) || s[openIdx] != '(' {
		return -1
	}
	depth := 0
	inString := false
	var quoteChar rune

	for i, r := range s[openIdx:] {
		actualIdx := openIdx + i
		if inString {
			if r == quoteChar && (i == 0 || s[actualIdx-1] != '\\') {
				inString = false
			}
			continue
		}
		if r == '"' || r == '\'' {
			inString = true
			quoteChar = r
			continue
		}
		if r == '(' {
			depth++
		} else if r == ')' {
			depth--
			if depth == 0 {
				return actualIdx
			}
		}
	}
	return -1
}
