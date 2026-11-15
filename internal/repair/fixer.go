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

// maskLine blanks string literals and // comments in a single line,
// preserving byte offsets so match indices found in the masked line map
// back onto the original. It also returns the [start,end) spans that are
// executable code (outside strings and comments).
func maskLine(line string) (string, [][2]int) {
	b := []byte(line)
	var segs [][2]int
	segStart := -1
	flush := func(upto int) {
		if segStart >= 0 && segStart < upto {
			segs = append(segs, [2]int{segStart, upto})
		}
		segStart = -1
	}
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == '/' && i+1 < len(b) && b[i+1] == '/' {
			flush(i)
			for j := i; j < len(b); j++ {
				b[j] = 0
			}
			break
		}
		if c == '"' || c == '\'' || c == '`' {
			flush(i)
			q := c
			b[i] = 0
			i++
			for i < len(b) {
				if q != '`' && b[i] == '\\' {
					b[i] = 0
					if i+1 < len(b) {
						b[i+1] = 0
					}
					i += 2
					continue
				}
				ch := b[i]
				b[i] = 0
				i++
				if ch == q {
					break
				}
			}
			i-- // compensate for the loop's i++
			continue
		}
		if segStart < 0 {
			segStart = i
		}
	}
	flush(len(b))
	// Convert NULs back to spaces for a usable masked string.
	for i, c := range b {
		if c == 0 {
			b[i] = ' '
		}
	}
	return string(b), segs
}

// inCodeSpan reports whether pos falls inside one of the code segments.
func inCodeSpan(segs [][2]int, pos int) bool {
	for _, s := range segs {
		if pos >= s[0] && pos < s[1] {
			return true
		}
	}
	return false
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

// applyRedundantBoolFix rewrites redundant boolean comparisons, but only
// within code segments — matches inside string literals or comments are
// never touched.
func applyRedundantBoolFix(line string) string {
	_, segs := maskLine(line)
	if len(segs) == 0 {
		return line
	}
	var b strings.Builder
	prev := 0
	changed := false
	for _, s := range segs {
		b.WriteString(line[prev:s[0]])
		seg := line[s[0]:s[1]]
		fixed := seg
		for _, r := range redundantBoolRules {
			fixed = r.pattern.ReplaceAllString(fixed, r.replacement)
		}
		if fixed != seg {
			changed = true
		}
		b.WriteString(fixed)
		prev = s[1]
	}
	b.WriteString(line[prev:])
	if !changed {
		return line
	}
	return b.String()
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
	// permCallPattern matches the file-permission APIs the review rule
	// flags, mirroring worldWritablePattern in internal/review.
	permCallPattern      = regexp.MustCompile(`\b(?:(?:os\.)?(?:WriteFile|Mkdir|MkdirAll|OpenFile|Chmod)|[A-Za-z_]\w*\.Chmod)\s*\(`)
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

// permCallSpans returns the argument spans [start,end) of every
// permission-call invocation on the line, computed on the masked line so
// calls inside strings or comments are ignored. isDir reports whether the
// call creates directories (Mkdir/MkdirAll) and therefore wants 0755.
func permCallSpans(masked string) [][2]int {
	var spans [][2]int
	for _, m := range permCallPattern.FindAllStringIndex(masked, -1) {
		// m[1] is just past the '('. Walk to the matching close paren.
		depth := 1
		end := len(masked)
		for i := m[1]; i < len(masked); i++ {
			switch masked[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = i
					i = len(masked) // break
				}
			}
		}
		spans = append(spans, [2]int{m[1], end})
	}
	return spans
}

func fixWorldWritableModeInLine(line string) string {
	masked, _ := maskLine(line)
	spans := permCallSpans(masked)
	if len(spans) == 0 {
		return line
	}

	type repl struct{ start, end int }
	var targets []repl
	var replacements []string
	seen := make(map[int]bool)

	for _, span := range spans {
		// Determine dir-ness from the call name preceding the span.
		name := callNameBefore(masked, span[0])
		for _, m := range modeCandidatePattern.FindAllStringIndex(masked[span[0]:span[1]], -1) {
			abs := [2]int{span[0] + m[0], span[0] + m[1]}
			if seen[abs[0]] {
				continue
			}
			match := line[abs[0]:abs[1]]
			// Use the masked text for classification; it is identical to
			// the original for code (masking only blanks strings/comments).
			if !isWorldWritablePerm(masked[abs[0]:abs[1]]) {
				continue
			}
			seen[abs[0]] = true
			prefix := "0"
			if strings.HasPrefix(match, "0o") {
				prefix = "0o"
			}
			target := "644"
			if strings.Contains(name, "Mkdir") {
				target = "755"
			}
			targets = append(targets, repl{abs[0], abs[1]})
			replacements = append(replacements, prefix+target)
		}
	}

	if len(targets) == 0 {
		return line
	}
	// Apply right-to-left so indices stay valid.
	for i := len(targets) - 1; i >= 0; i-- {
		line = line[:targets[i].start] + replacements[i] + line[targets[i].end:]
	}
	return line
}

// callNameBefore returns the identifier immediately preceding the '('
// that opens the argument span ending the match at pos.
func callNameBefore(masked string, pos int) string {
	// Walk back over whitespace to the '(', then collect the identifier.
	i := pos - 1
	for i >= 0 && (masked[i] == ' ' || masked[i] == '\t') {
		i--
	}
	if i < 0 || masked[i] != '(' {
		return ""
	}
	i--
	end := i + 1
	for i >= 0 && (masked[i] == '_' || masked[i] >= 'a' && masked[i] <= 'z' || masked[i] >= 'A' && masked[i] <= 'Z' || masked[i] >= '0' && masked[i] <= '9' || masked[i] == '.') {
		i--
	}
	return masked[i+1 : end]
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
