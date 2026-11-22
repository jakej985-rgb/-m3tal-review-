package repair

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// SemanticsActionFixer automatically repairs inoperable Semantics buttons by
// providing an explicit onTap activation action (e.g., widget.onTap) on the
// outer Semantics widget while excluding descendant semantics.
type SemanticsActionFixer struct{}

func (SemanticsActionFixer) Name() string {
	return "semantics-action-fixer"
}

func (SemanticsActionFixer) CanFix(f review.Finding) bool {
	return f.Rule == "flutter-semantics-action"
}

var (
	childTapCallbackRe = regexp.MustCompile(
		`\b(?:GestureDetector|InkWell|InkResponse)\s*\([^)]*?\bonTap\s*:\s*([a-zA-Z0-9_.]+)`,
	)
)

func (f SemanticsActionFixer) GenerateProposal(ctx context.Context, repoRoot string, finding review.Finding, fileContent []byte) (*Proposal, error) {
	lines := strings.Split(string(fileContent), "\n")
	targetIdx := -1

	// Attempt to locate around finding.Line
	if finding.Line > 0 && finding.Line <= len(lines) {
		start := finding.Line - 5
		if start < 0 {
			start = 0
		}
		end := finding.Line + 5
		if end > len(lines) {
			end = len(lines)
		}
		for i := start; i < end; i++ {
			if strings.Contains(lines[i], "excludeSemantics: true") {
				targetIdx = i
				break
			}
		}
	}

	// Fallback: search whole file if not found nearby
	if targetIdx == -1 {
		for i, line := range lines {
			if strings.Contains(line, "excludeSemantics: true") {
				targetIdx = i
				break
			}
		}
	}

	// Determine tap callback from descendant GestureDetector or InkWell
	tapHandler := "widget.onTap"
	fullText := string(fileContent)
	if m := childTapCallbackRe.FindStringSubmatch(fullText); len(m) > 1 {
		tapHandler = m[1]
	}

	if targetIdx != -1 {
		line := lines[targetIdx]
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[targetIdx] = fmt.Sprintf("%sexcludeSemantics: true,\n%sonTap: %s,", indent, indent, tapHandler)
	} else {
		// If excludeSemantics: true wasn't yet present, look for button: true
		buttonIdx := -1
		if finding.Line > 0 && finding.Line <= len(lines) {
			start := finding.Line - 10
			if start < 0 {
				start = 0
			}
			end := finding.Line + 10
			if end > len(lines) {
				end = len(lines)
			}
			for i := start; i < end; i++ {
				if strings.Contains(lines[i], "button: true") {
					buttonIdx = i
					break
				}
			}
		}
		if buttonIdx == -1 {
			return nil, fmt.Errorf("could not locate Semantics button target in %s", finding.File)
		}
		line := lines[buttonIdx]
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		lines[buttonIdx] = fmt.Sprintf("%sbutton: true,\n%sexcludeSemantics: true,\n%sonTap: %s,", indent, indent, indent, tapHandler)
	}

	proposed := strings.Join(lines, "\n")
	return NewProposal(
		"",
		finding,
		f.Name(),
		finding.File,
		string(fileContent),
		proposed,
		"Injected onTap activation action and excluded descendant semantics on Semantics button.",
	), nil
}
