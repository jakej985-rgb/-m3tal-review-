package repair

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// AsyncGapFixer automatically inserts 'if (!mounted) return;' or
// 'if (!context.mounted) return;' before unguarded setState/context calls.
type AsyncGapFixer struct{}

func (AsyncGapFixer) Name() string {
	return "async-gap-fixer"
}

func (AsyncGapFixer) CanFix(f review.Finding) bool {
	return f.Rule == "unmounted-async-gap"
}

func (AsyncGapFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	text := string(content)
	lines := strings.Split(text, "\n")
	if f.Line <= 0 || f.Line > len(lines) {
		return nil, nil
	}

	targetIdx := f.Line - 1
	targetLine := lines[targetIdx]

	// Determine indentation
	indent := ""
	for _, r := range targetLine {
		if r == ' ' || r == '\t' {
			indent += string(r)
		} else {
			break
		}
	}

	// Choose appropriate guard: if line uses context or Navigator, use context.mounted
	guard := "if (!mounted) return;"
	if strings.Contains(targetLine, "context") || strings.Contains(targetLine, "Navigator") ||
		strings.Contains(targetLine, "ScaffoldMessenger") || strings.Contains(f.Message, "BuildContext") {
		guard = "if (!context.mounted) return;"
	}

	// Insert guard directly before the target line
	newLines := make([]string, 0, len(lines)+1)
	newLines = append(newLines, lines[:targetIdx]...)
	newLines = append(newLines, indent+guard)
	newLines = append(newLines, lines[targetIdx:]...)

	proposed := strings.Join(newLines, "\n")
	prop := NewProposal(
		"",
		f,
		"async-gap-fixer",
		f.File,
		text,
		proposed,
		fmt.Sprintf("Insert mounted guard '%s' before async boundary call", guard),
	)
	return prop, nil
}

// StaleStateFixer automatically resets cursor/index state inside didUpdateWidget.
type StaleStateFixer struct{}

func (StaleStateFixer) Name() string {
	return "stale-state-fixer"
}

func (StaleStateFixer) CanFix(f review.Finding) bool {
	return f.Rule == "stale-state-invalidation" && strings.Contains(f.Message, "didUpdateWidget")
}

var cursorFromMessageRe = regexp.MustCompile(`cursor\s+(_[a-zA-Z0-9_]+)`)

func (StaleStateFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	m := cursorFromMessageRe.FindStringSubmatch(f.Message)
	if len(m) < 2 {
		return nil, nil
	}
	cursorName := m[1]

	text := string(content)
	lines := strings.Split(text, "\n")
	if f.Line <= 0 || f.Line > len(lines) {
		return nil, nil
	}

	// Find the didUpdateWidget method around f.Line
	start := f.Line - 1
	if start >= len(lines) {
		start = len(lines) - 1
	}

	// Locate the entity change 'if' block: if (oldWidget.id != widget.id) {
	ifIdx := -1
	for i := start; i < len(lines) && i < start+15; i++ {
		if strings.Contains(lines[i], "if ") && strings.Contains(lines[i], "!=") {
			ifIdx = i
			break
		}
	}

	if ifIdx == -1 {
		return nil, nil
	}

	// Find closing brace of that if block
	insertIdx := -1
	indent := ""
	for i := ifIdx; i < len(lines) && i < ifIdx+25; i++ {
		if strings.Contains(lines[i], "}") {
			insertIdx = i
			// Use indentation of the preceding statement inside the if
			if i > ifIdx {
				for _, r := range lines[i-1] {
					if r == ' ' || r == '\t' {
						indent += string(r)
					} else {
						break
					}
				}
			}
			break
		}
	}

	if insertIdx == -1 {
		return nil, nil
	}

	if indent == "" {
		indent = "      "
	}

	resetStmt := indent + cursorName + " = 0;"
	newLines := make([]string, 0, len(lines)+1)
	newLines = append(newLines, lines[:insertIdx]...)
	newLines = append(newLines, resetStmt)
	newLines = append(newLines, lines[insertIdx:]...)

	proposed := strings.Join(newLines, "\n")
	prop := NewProposal(
		"",
		f,
		"stale-state-fixer",
		f.File,
		text,
		proposed,
		fmt.Sprintf("Reset cursor '%s = 0;' inside didUpdateWidget on entity change", cursorName),
	)
	return prop, nil
}

// ResourceLeakFixer automatically injects missing dispose()/cancel() calls into dispose().
type ResourceLeakFixer struct{}

func (ResourceLeakFixer) Name() string {
	return "resource-leak-fixer"
}

func (ResourceLeakFixer) CanFix(f review.Finding) bool {
	return f.Rule == "resource-leak-disposable"
}

var resourceFromMessageRe = regexp.MustCompile(`resource\s+'(_[a-zA-Z0-9_]+)'\s*\(([^)]+)\)`)

func (ResourceLeakFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	m := resourceFromMessageRe.FindStringSubmatch(f.Message)
	if len(m) < 3 {
		return nil, nil
	}
	fieldName := m[1]
	typeName := m[2]

	cleanMethod := "dispose"
	if strings.Contains(typeName, "Timer") || strings.Contains(typeName, "StreamSubscription") {
		cleanMethod = "cancel"
	}

	text := string(content)
	lines := strings.Split(text, "\n")

	// Find super.dispose(); in the file
	superDisposeIdx := -1
	indent := ""
	for i, l := range lines {
		if strings.Contains(l, "super.dispose()") {
			superDisposeIdx = i
			for _, r := range l {
				if r == ' ' || r == '\t' {
					indent += string(r)
				} else {
					break
				}
			}
			break
		}
	}

	if superDisposeIdx == -1 {
		return nil, nil // If dispose() doesn't exist, avoid guessing placement
	}

	cleanStmt := fmt.Sprintf("%s%s?.%s();", indent, fieldName, cleanMethod)
	// Check if already non-nullable field
	if strings.Contains(text, fmt.Sprintf("final %s %s =", typeName, fieldName)) {
		cleanStmt = fmt.Sprintf("%s%s.%s();", indent, fieldName, cleanMethod)
	}

	newLines := make([]string, 0, len(lines)+1)
	newLines = append(newLines, lines[:superDisposeIdx]...)
	newLines = append(newLines, cleanStmt)
	newLines = append(newLines, lines[superDisposeIdx:]...)

	proposed := strings.Join(newLines, "\n")
	prop := NewProposal(
		"",
		f,
		"resource-leak-fixer",
		f.File,
		text,
		proposed,
		fmt.Sprintf("Clean up disposable resource '%s' before super.dispose()", fieldName),
	)
	return prop, nil
}

// TouchTargetFixer removes MaterialTapTargetSize.shrinkWrap and resets minimumSize.
type TouchTargetFixer struct{}

func (TouchTargetFixer) Name() string {
	return "touch-target-fixer"
}

func (TouchTargetFixer) CanFix(f review.Finding) bool {
	return f.Rule == "touch-target-size" && strings.Contains(f.Message, "shrinkWrap")
}

func (TouchTargetFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	text := string(content)
	lines := strings.Split(text, "\n")
	if f.Line <= 0 || f.Line > len(lines) {
		return nil, nil
	}

	start := f.Line - 1
	end := start + 30
	if end > len(lines) {
		end = len(lines)
	}

	hasChanges := false
	for i := start; i < end; i++ {
		l := lines[i]
		if strings.Contains(l, "MaterialTapTargetSize.shrinkWrap") {
			// Remove shrinkWrap line or replace with padded
			lines[i] = strings.Replace(l, "MaterialTapTargetSize.shrinkWrap", "MaterialTapTargetSize.padded", 1)
			hasChanges = true
		}
		if strings.Contains(l, "Size.zero") {
			lines[i] = strings.Replace(l, "Size.zero", "const Size(48, 48)", 1)
			hasChanges = true
		} else if strings.Contains(l, "Size(0, 0)") || strings.Contains(l, "Size(0,0)") {
			lines[i] = strings.Replace(l, "Size(0, 0)", "const Size(48, 48)", 1)
			lines[i] = strings.Replace(lines[i], "Size(0,0)", "const Size(48, 48)", 1)
			hasChanges = true
		}
	}

	if !hasChanges {
		return nil, nil
	}

	proposed := strings.Join(lines, "\n")
	prop := NewProposal(
		"",
		f,
		"touch-target-fixer",
		f.File,
		text,
		proposed,
		"Enforce minimum 48x48 dp touch target and remove MaterialTapTargetSize.shrinkWrap",
	)
	return prop, nil
}
