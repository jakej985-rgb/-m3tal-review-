package repair

import (
	"context"
	"fmt"
	"go/format"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// Fixer represents a deterministic remediation proposal generator for an eligible finding.
type Fixer interface {
	Name() string
	CanFix(finding review.Finding) bool
	GenerateProposal(ctx context.Context, repoRoot string, finding review.Finding, fileContent []byte) (*Proposal, error)
}

// AllowlistedFixers returns all registered, deterministic repair fixers.
func AllowlistedFixers() []Fixer {
	return []Fixer{
		TrailingWhitespaceFixer{},
		RedundantBoolFixer{},
		GoFmtFixer{},
		WorldWritableFileModeFixer{},
		DebugLeftoverFixer{},
	}
}

// IsAllowlistedFixer reports whether the given fixer name belongs to the allowlist.
func IsAllowlistedFixer(name string) bool {
	for _, fixer := range AllowlistedFixers() {
		if fixer.Name() == name {
			return true
		}
	}
	return false
}

// FindFixerForFinding finds an allowlisted fixer eligible to repair the finding.
func FindFixerForFinding(finding review.Finding) Fixer {
	for _, fixer := range AllowlistedFixers() {
		if fixer.CanFix(finding) {
			return fixer
		}
	}
	return nil
}

// TrailingWhitespaceFixer strips trailing whitespace from lines in eligible files.
type TrailingWhitespaceFixer struct{}

func (TrailingWhitespaceFixer) Name() string {
	return "trailing-whitespace-fixer"
}

func (TrailingWhitespaceFixer) CanFix(f review.Finding) bool {
	msg := strings.ToLower(f.Message)
	return strings.Contains(msg, "trailing whitespace") || strings.Contains(msg, "trailing spaces")
}

func (TrailingWhitespaceFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	text := string(content)
	lines := strings.Split(text, "\n")
	hasChanges := false

	for i, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		if trimmed != line {
			lines[i] = trimmed
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
		"trailing-whitespace-fixer",
		f.File,
		text,
		proposed,
		"Strip trailing whitespace characters from lines",
	)
	return prop, nil
}

// RedundantBoolFixer replaces redundant boolean equality comparisons.
type RedundantBoolFixer struct{}

func (RedundantBoolFixer) Name() string {
	return "redundant-bool-fixer"
}

func (RedundantBoolFixer) CanFix(f review.Finding) bool {
	msg := strings.ToLower(f.Message)
	return strings.Contains(msg, "redundant boolean")
}

var redundantBoolRules = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\([^)]*\))?)\s*={2,3}\s*true\b`), "$1"},
	{regexp.MustCompile(`\btrue\s*={2,3}\s*([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\([^)]*\))?)\b`), "$1"},
	{regexp.MustCompile(`\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\([^)]*\))?)\s*={2,3}\s*false\b`), "!$1"},
	{regexp.MustCompile(`\bfalse\s*={2,3}\s*([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\([^)]*\))?)\b`), "!$1"},
	{regexp.MustCompile(`\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\([^)]*\))?)\s*!={1,2}\s*true\b`), "!$1"},
	{regexp.MustCompile(`\btrue\s*!={1,2}\s*([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\([^)]*\))?)\b`), "!$1"},
	{regexp.MustCompile(`\b([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\([^)]*\))?)\s*!={1,2}\s*false\b`), "$1"},
	{regexp.MustCompile(`\bfalse\s*!={1,2}\s*([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*(?:\([^)]*\))?)\b`), "$1"},
}

func applyRedundantBoolFix(line string) string {
	res := line
	for _, r := range redundantBoolRules {
		res = r.pattern.ReplaceAllString(res, r.replacement)
	}
	return res
}

func (RedundantBoolFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	text := string(content)
	lines := strings.Split(text, "\n")
	hasChanges := false

	targetStart := 0
	targetEnd := len(lines)
	if f.Line > 0 && f.Line <= len(lines) {
		targetStart = f.Line - 1
		targetEnd = f.Line
	}

	for i := targetStart; i < targetEnd; i++ {
		orig := lines[i]
		cur := applyRedundantBoolFix(orig)
		if cur != orig {
			lines[i] = cur
			hasChanges = true
		}
	}

	if !hasChanges && f.Line > 0 {
		for i := 0; i < len(lines); i++ {
			orig := lines[i]
			cur := applyRedundantBoolFix(orig)
			if cur != orig {
				lines[i] = cur
				hasChanges = true
				break
			}
		}
	}

	if !hasChanges {
		return nil, nil
	}

	proposed := strings.Join(lines, "\n")
	prop := NewProposal(
		"",
		f,
		"redundant-bool-fixer",
		f.File,
		text,
		proposed,
		"Simplify redundant boolean equality comparisons",
	)
	return prop, nil
}

// GoFmtFixer formats Go source code using standard go/format.
type GoFmtFixer struct{}

func (GoFmtFixer) Name() string {
	return "gofmt-fixer"
}

func (GoFmtFixer) CanFix(f review.Finding) bool {
	if filepath.Ext(f.File) != ".go" {
		return false
	}
	msg := strings.ToLower(f.Message)
	return f.Rule == "confidence-gofmt" || strings.Contains(msg, "gofmt") || strings.Contains(msg, "not formatted")
}

func (GoFmtFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	formatted, err := format.Source(content)
	if err != nil {
		return nil, fmt.Errorf("gofmt format error: %w", err)
	}

	if string(formatted) == string(content) {
		return nil, nil
	}

	prop := NewProposal(
		"",
		f,
		"gofmt-fixer",
		f.File,
		string(content),
		string(formatted),
		"Reformat Go source code according to canonical gofmt style",
	)
	return prop, nil
}

// WorldWritableFileModeFixer restricts permissive file permissions to safe modes.
type WorldWritableFileModeFixer struct{}

func (WorldWritableFileModeFixer) Name() string {
	return "world-writable-file-mode-fixer"
}

func (WorldWritableFileModeFixer) CanFix(f review.Finding) bool {
	return f.Rule == "world-writable-file-mode" || strings.Contains(strings.ToLower(f.Message), "world-write permission")
}

var (
	permDirPattern       = regexp.MustCompile(`(?i)\b(mkdir|mkdirall)\b`)
	modeCandidatePattern = regexp.MustCompile(`\b(0[0-7]{3,4}|0o[0-7]{3,4}|os\.ModePerm)\b`)
)

func isWorldWritablePerm(mode string) bool {
	if mode == "os.ModePerm" {
		return true
	}
	if len(mode) < 2 || mode[0] != '0' {
		return false
	}
	digits := mode[1:]
	if len(mode) > 1 && mode[1] == 'o' {
		digits = mode[2:]
	} else if len(digits) < 3 {
		return false
	}
	value, err := strconv.ParseUint(digits, 8, 32)
	return err == nil && value&0o002 != 0
}

func fixWorldWritableModeInLine(line string) string {
	isDir := permDirPattern.MatchString(line)
	return modeCandidatePattern.ReplaceAllStringFunc(line, func(match string) string {
		if !isWorldWritablePerm(match) {
			return match
		}
		prefix := "0"
		if strings.HasPrefix(match, "0o") {
			prefix = "0o"
		}
		if isDir {
			return prefix + "755"
		}
		return prefix + "644"
	})
}

func (WorldWritableFileModeFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	text := string(content)
	lines := strings.Split(text, "\n")
	hasChanges := false

	targetStart := 0
	targetEnd := len(lines)
	if f.Line > 0 && f.Line <= len(lines) {
		targetStart = f.Line - 1
		targetEnd = f.Line
	}

	for i := targetStart; i < targetEnd; i++ {
		orig := lines[i]
		cur := fixWorldWritableModeInLine(orig)
		if cur != orig {
			lines[i] = cur
			hasChanges = true
		}
	}

	if !hasChanges && f.Line > 0 {
		for i := 0; i < len(lines); i++ {
			orig := lines[i]
			cur := fixWorldWritableModeInLine(orig)
			if cur != orig {
				lines[i] = cur
				hasChanges = true
				break
			}
		}
	}

	if !hasChanges {
		return nil, nil
	}

	proposed := strings.Join(lines, "\n")
	prop := NewProposal(
		"",
		f,
		"world-writable-file-mode-fixer",
		f.File,
		text,
		proposed,
		"Replace overly permissive world-writable file permissions with restrictive modes (0644/0755)",
	)
	return prop, nil
}

// DebugLeftoverFixer comments out stray debug statements.
type DebugLeftoverFixer struct{}

func (DebugLeftoverFixer) Name() string {
	return "debug-leftover-fixer"
}

func (DebugLeftoverFixer) CanFix(f review.Finding) bool {
	return f.Rule == "debug-leftover" || strings.Contains(strings.ToLower(f.Message), "debug print") ||
		strings.Contains(strings.ToLower(f.Message), "console log") ||
		strings.Contains(strings.ToLower(f.Message), "debugger statement")
}

var (
	debugStatementPattern = regexp.MustCompile(`^\s*(?:fmt\.Print(?:ln|f)?\s*\(|console\.log\s*\(|debugger\s*;?|breakpoint\s*\(\)|print\s*\()`)
)

func commentPrefixForFile(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".py", ".rb", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".dockerfile":
		return "# "
	default:
		return "// "
	}
}

func (DebugLeftoverFixer) GenerateProposal(ctx context.Context, repoRoot string, f review.Finding, content []byte) (*Proposal, error) {
	text := string(content)
	lines := strings.Split(text, "\n")
	hasChanges := false

	targetStart := 0
	targetEnd := len(lines)
	if f.Line > 0 && f.Line <= len(lines) {
		targetStart = f.Line - 1
		targetEnd = f.Line
	}

	prefix := commentPrefixForFile(f.File)

	for i := targetStart; i < targetEnd; i++ {
		orig := lines[i]
		if debugStatementPattern.MatchString(orig) {
			indent := ""
			for _, r := range orig {
				if r == ' ' || r == '\t' {
					indent += string(r)
				} else {
					break
				}
			}
			trimmed := strings.TrimLeft(orig, " \t")
			lines[i] = indent + prefix + trimmed
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
		"debug-leftover-fixer",
		f.File,
		text,
		proposed,
		"Comment out leftover debug statement",
	)
	return prop, nil
}
