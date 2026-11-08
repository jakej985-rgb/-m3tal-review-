package review

import (
	"fmt"
	"html"
	"path"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
)

// SnippetLineKind describes the diff context of a source line.
type SnippetLineKind string

const (
	SnippetLineAdded   SnippetLineKind = "added"
	SnippetLineDeleted SnippetLineKind = "deleted"
	SnippetLineContext SnippetLineKind = "context"
)

// SnippetLine represents a single line in a contextual snippet.
type SnippetLine struct {
	LineNumber    int             `json:"line_number,omitempty"`
	OldLineNumber int             `json:"old_line_number,omitempty"`
	Kind          SnippetLineKind `json:"kind"`
	Content       string          `json:"content"`
	IsFinding     bool            `json:"is_finding"`
}

// Snippet represents a diff-aware contextual code snippet around a finding.
type Snippet struct {
	File              string        `json:"file"`
	Line              int           `json:"line"`
	Language          string        `json:"language"`
	StartLine         int           `json:"start_line"`
	EndLine           int           `json:"end_line"`
	Lines             []SnippetLine `json:"lines"`
	FormattedText     string        `json:"formatted_text"`
	FormattedMarkdown string        `json:"formatted_markdown"`
	FormattedHTML     string        `json:"formatted_html"`
}

// SnippetGenerator produces contextual snippets for findings.
type SnippetGenerator struct {
	diff        string
	fileDiffs   []FileDiff
	repoRoot    string
	workingTree bool
	radius      int
	fileSources map[string]string
}

// SnippetOption configures a SnippetGenerator.
type SnippetOption func(*SnippetGenerator)

// WithRepoRoot sets the repository root for reading file contents on disk.
func WithRepoRoot(root string) SnippetOption {
	return func(g *SnippetGenerator) { g.repoRoot = root }
}

// WithWorkingTree indicates whether to read files from working-tree or git staged.
func WithWorkingTree(workingTree bool) SnippetOption {
	return func(g *SnippetGenerator) { g.workingTree = workingTree }
}

// WithContextRadius sets the number of context lines to include before and after the finding.
func WithContextRadius(radius int) SnippetOption {
	return func(g *SnippetGenerator) {
		if radius >= 0 {
			g.radius = radius
		}
	}
}

// WithFileSource injects a file's content directly (useful for tests and memory buffers).
func WithFileSource(file, content string) SnippetOption {
	return func(g *SnippetGenerator) {
		if g.fileSources == nil {
			g.fileSources = make(map[string]string)
		}
		g.fileSources[file] = content
	}
}

// NewSnippetGenerator creates a diff-aware snippet generator with options.
func NewSnippetGenerator(diff string, opts ...SnippetOption) *SnippetGenerator {
	g := &SnippetGenerator{
		diff:   diff,
		radius: 3,
	}
	if diff != "" {
		g.fileDiffs = ParseDiff(diff)
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// DetectLanguage maps file extensions and naming patterns to known language names.
func DetectLanguage(file string) string {
	file = filepath.ToSlash(file)
	base := strings.ToLower(path.Base(file))
	if base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") {
		return "dockerfile"
	}
	if base == "makefile" || base == "gnumakefile" {
		return "makefile"
	}
	if base == "go.mod" || base == "go.sum" {
		return "go"
	}
	if base == "cargo.toml" || base == "cargo.lock" {
		return "toml"
	}
	if base == ".gitignore" || base == ".gitattributes" {
		return "git"
	}
	if strings.HasPrefix(base, ".env") {
		return "shell"
	}
	ext := strings.ToLower(path.Ext(file))
	switch ext {
	case ".go":
		return "go"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".ts", ".tsx", ".mts", ".cts":
		return "typescript"
	case ".py":
		return "python"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx":
		return "cpp"
	case ".cs", ".csx":
		return "csharp"
	case ".rs":
		return "rust"
	case ".swift":
		return "swift"
	case ".php", ".phtml":
		return "php"
	case ".rb":
		return "ruby"
	case ".lua":
		return "lua"
	case ".sh", ".bash", ".zsh":
		return "shell"
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".sql":
		return "sql"
	case ".html", ".htm":
		return "html"
	case ".css":
		return "css"
	case ".xml":
		return "xml"
	case ".md", ".markdown":
		return "markdown"
	case ".tf", ".hcl":
		return "hcl"
	case ".proto":
		return "protobuf"
	case ".graphql", ".gql":
		return "graphql"
	default:
		checker := language.CodeChecker{}
		lang := checker.Language(file)
		if lang != language.LanguageUnknown {
			return string(lang)
		}
		return "text"
	}
}

// GenerateSnippet generates a diff-aware contextual snippet for a finding.
func (g *SnippetGenerator) GenerateSnippet(f Finding) *Snippet {
	if f.File == "" {
		return nil
	}

	targetLine := f.Line
	fileDiff := g.findFileDiff(f.File)

	// If no line number given, attempt to find first line from diff
	if targetLine <= 0 {
		if fileDiff != nil && len(fileDiff.AddedLines) > 0 {
			targetLine = fileDiff.AddedLines[0]
		} else if fileDiff != nil && len(fileDiff.Lines) > 0 {
			for _, dl := range fileDiff.Lines {
				if dl.NewLineNumber > 0 {
					targetLine = dl.NewLineNumber
					break
				}
				if dl.OldLineNumber > 0 && targetLine <= 0 {
					targetLine = dl.OldLineNumber
				}
			}
		}
		if targetLine <= 0 {
			targetLine = 1
		}
	}

	minLine := targetLine - g.radius
	if minLine < 1 {
		minLine = 1
	}
	maxLine := targetLine + g.radius

	var lines []SnippetLine
	foundInDiff := false

	// Step 1: Check diff lines if available
	if fileDiff != nil && len(fileDiff.Lines) > 0 {
		for _, dl := range fileDiff.Lines {
			inRange := false
			if dl.NewLineNumber > 0 && dl.NewLineNumber >= minLine && dl.NewLineNumber <= maxLine {
				inRange = true
			} else if dl.Type == "-" && dl.OldLineNumber > 0 {
				if (dl.NewLineNumber >= minLine && dl.NewLineNumber <= maxLine) ||
					(dl.OldLineNumber >= minLine && dl.OldLineNumber <= maxLine) {
					inRange = true
				}
			}

			if inRange {
				foundInDiff = true
				kind := SnippetLineContext
				isTarget := false
				lineNum := dl.NewLineNumber
				oldLineNum := dl.OldLineNumber

				switch dl.Type {
				case "+":
					kind = SnippetLineAdded
					isTarget = (dl.NewLineNumber == targetLine)
				case "-":
					kind = SnippetLineDeleted
					lineNum = 0 // Line does not exist in new file; use OldLineNumber
					hasAddedTarget := false
					for _, other := range fileDiff.Lines {
						if other.Type == "+" && other.NewLineNumber == targetLine {
							hasAddedTarget = true
							break
						}
					}
					isTarget = (!hasAddedTarget && targetLine > 0 && (dl.OldLineNumber == targetLine || dl.NewLineNumber == targetLine))
				case " ":
					kind = SnippetLineContext
					isTarget = (dl.NewLineNumber == targetLine)
				}

				lines = append(lines, SnippetLine{
					LineNumber:    lineNum,
					OldLineNumber: oldLineNum,
					Kind:          kind,
					Content:       dl.Content,
					IsFinding:     isTarget,
				})
			}
		}
	}

	// Step 2: If diff did not provide lines or provided only partial context, fallback/supplement with file content
	sourceContent, sourceErr := g.readFileSource(f.File)
	if sourceErr == nil && len(sourceContent) > 0 {
		fileLines := strings.Split(sourceContent, "\n")
		// Trim optional trailing empty line from trailing newline
		if len(fileLines) > 0 && fileLines[len(fileLines)-1] == "" {
			fileLines = fileLines[:len(fileLines)-1]
		}

		if len(lines) == 0 {
			// Complete extract from file content; require targetLine within file bounds
			if targetLine <= len(fileLines) {
				fileMin := minLine
				if fileMin < 1 {
					fileMin = 1
				}
				fileMax := maxLine
				if fileMax > len(fileLines) {
					fileMax = len(fileLines)
				}
				for l := fileMin; l <= fileMax; l++ {
					isTarget := (l == targetLine)
					lines = append(lines, SnippetLine{
						LineNumber: l,
						Kind:       SnippetLineContext,
						Content:    fileLines[l-1],
						IsFinding:  isTarget,
					})
				}
			}
		} else {
			// Diff had lines; check if we can pad missing context lines before min or after max
			existingLines := make(map[int]bool)
			for _, l := range lines {
				if l.LineNumber > 0 {
					existingLines[l.LineNumber] = true
				}
			}

			// Prepend missing context lines before diff hunk
			var prepended []SnippetLine
			for l := minLine; l < targetLine; l++ {
				if !existingLines[l] && l > 0 && l <= len(fileLines) {
					prepended = append(prepended, SnippetLine{
						LineNumber: l,
						Kind:       SnippetLineContext,
						Content:    fileLines[l-1],
						IsFinding:  false,
					})
				}
			}

			// Append missing context lines after diff hunk
			var appended []SnippetLine
			for l := targetLine + 1; l <= maxLine; l++ {
				if !existingLines[l] && l > 0 && l <= len(fileLines) {
					appended = append(appended, SnippetLine{
						LineNumber: l,
						Kind:       SnippetLineContext,
						Content:    fileLines[l-1],
						IsFinding:  false,
					})
				}
			}

			if len(prepended) > 0 {
				lines = append(prepended, lines...)
			}
			if len(appended) > 0 {
				lines = append(lines, appended...)
			}
		}
	}

	if len(lines) == 0 {
		if !foundInDiff && f.Line <= 0 {
			return nil
		}
		return nil
	}

	// Determine actual start and end lines
	startLine := 0
	endLine := 0
	for _, l := range lines {
		ln := l.LineNumber
		if ln <= 0 {
			ln = l.OldLineNumber
		}
		if ln > 0 {
			if startLine == 0 || ln < startLine {
				startLine = ln
			}
			if ln > endLine {
				endLine = ln
			}
		}
	}

	lang := DetectLanguage(f.File)
	snip := &Snippet{
		File:      f.File,
		Line:      targetLine,
		Language:  lang,
		StartLine: startLine,
		EndLine:   endLine,
		Lines:     lines,
	}

	snip.FormattedText = FormatSnippetText(snip)
	snip.FormattedMarkdown = FormatSnippetMarkdown(snip)
	snip.FormattedHTML = FormatSnippetHTML(snip)

	return snip
}

func (g *SnippetGenerator) findFileDiff(file string) *FileDiff {
	norm := strings.TrimPrefix(file, "./")
	for i := range g.fileDiffs {
		p := strings.TrimPrefix(g.fileDiffs[i].Path, "./")
		if p == norm || g.fileDiffs[i].NewPath == norm || g.fileDiffs[i].OldPath == norm {
			return &g.fileDiffs[i]
		}
	}
	return nil
}

func (g *SnippetGenerator) readFileSource(file string) (string, error) {
	if g.fileSources != nil {
		if content, ok := g.fileSources[file]; ok {
			return content, nil
		}
	}
	if g.repoRoot != "" {
		data, err := readRuleSource(g.repoRoot, file, g.workingTree)
		if err == nil {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("source not available")
}

// AttachSnippets attaches contextual snippets to findings.
func (g *SnippetGenerator) AttachSnippets(findings []Finding) []Finding {
	result := make([]Finding, len(findings))
	for i, f := range findings {
		result[i] = f
		if snip := g.GenerateSnippet(f); snip != nil {
			result[i].Snippet = snip.FormattedText
		}
	}
	return result
}

// AttachSnippetsToReport attaches contextual snippets directly to report findings.
func (g *SnippetGenerator) AttachSnippetsToReport(report *Report) {
	if report == nil || len(report.Findings) == 0 {
		return
	}
	report.Findings = g.AttachSnippets(report.Findings)
}

// GenerateFindingSnippet is a convenience helper for generating a single snippet.
func GenerateFindingSnippet(diff string, finding Finding, radius int, repoRoot ...string) *Snippet {
	var opts []SnippetOption
	if radius > 0 {
		opts = append(opts, WithContextRadius(radius))
	}
	if len(repoRoot) > 0 && repoRoot[0] != "" {
		opts = append(opts, WithRepoRoot(repoRoot[0]))
	}
	gen := NewSnippetGenerator(diff, opts...)
	return gen.GenerateSnippet(finding)
}

// AttachSnippets attaches contextual snippets to a slice of findings.
func AttachSnippets(findings []Finding, diff string, repositoryRoot string, workingTree bool) []Finding {
	if len(findings) == 0 {
		return findings
	}
	gen := NewSnippetGenerator(diff, WithRepoRoot(repositoryRoot), WithWorkingTree(workingTree))
	return gen.AttachSnippets(findings)
}

// AttachSnippetsToReport attaches contextual snippets to all findings in a report.
func AttachSnippetsToReport(report *Report, diff string, repositoryRoot string, workingTree bool) {
	if report == nil || len(report.Findings) == 0 {
		return
	}
	gen := NewSnippetGenerator(diff, WithRepoRoot(repositoryRoot), WithWorkingTree(workingTree))
	report.Findings = gen.AttachSnippets(report.Findings)
}

// FormatSnippetText formats a snippet with padded line numbers and diff/finding markers.
func FormatSnippetText(s *Snippet) string {
	if s == nil || len(s.Lines) == 0 {
		return ""
	}

	maxLine := s.EndLine
	if maxLine < 10 {
		maxLine = 10
	}
	width := len(fmt.Sprintf("%d", maxLine))
	if width < 3 {
		width = 3
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[%s:%d] (%s)\n", s.File, s.Line, s.Language)

	for _, l := range s.Lines {
		marker := "  "
		if l.IsFinding {
			marker = "> "
		}

		lineNumStr := fmt.Sprintf("%*s", width, "-")
		if l.LineNumber > 0 {
			lineNumStr = fmt.Sprintf("%*d", width, l.LineNumber)
		} else if l.OldLineNumber > 0 {
			lineNumStr = fmt.Sprintf("%*d", width, l.OldLineNumber)
		}

		diffSign := " "
		switch l.Kind {
		case SnippetLineAdded:
			diffSign = "+"
		case SnippetLineDeleted:
			diffSign = "-"
		}

		fmt.Fprintf(&b, "%s%s | %s %s\n", marker, lineNumStr, diffSign, l.Content)
	}

	return b.String()
}

// FormatSnippetMarkdown formats a snippet inside a syntax-highlighted markdown code block.
func FormatSnippetMarkdown(s *Snippet) string {
	if s == nil || len(s.Lines) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, "```%s\n", s.Language)
	fmt.Fprintf(&b, "// %s:%d\n", s.File, s.Line)

	maxLine := s.EndLine
	if maxLine < 10 {
		maxLine = 10
	}
	width := len(fmt.Sprintf("%d", maxLine))
	if width < 3 {
		width = 3
	}

	for _, l := range s.Lines {
		marker := "  "
		if l.IsFinding {
			marker = "> "
		}

		lineNumStr := fmt.Sprintf("%*s", width, "-")
		if l.LineNumber > 0 {
			lineNumStr = fmt.Sprintf("%*d", width, l.LineNumber)
		} else if l.OldLineNumber > 0 {
			lineNumStr = fmt.Sprintf("%*d", width, l.OldLineNumber)
		}

		diffSign := " "
		switch l.Kind {
		case SnippetLineAdded:
			diffSign = "+"
		case SnippetLineDeleted:
			diffSign = "-"
		}

		fmt.Fprintf(&b, "%s%s | %s %s\n", marker, lineNumStr, diffSign, l.Content)
	}

	b.WriteString("```\n")
	return b.String()
}

// FormatSnippetHTML formats a snippet into semantic HTML with CSS classes for styling.
func FormatSnippetHTML(s *Snippet) string {
	if s == nil || len(s.Lines) == 0 {
		return ""
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<div class="snippet" data-language="%s">`+"\n", html.EscapeString(s.Language))
	fmt.Fprintf(&b, `  <div class="snippet-header"><span class="snippet-file">%s:%d</span><span class="snippet-lang">%s</span></div>`+"\n",
		html.EscapeString(s.File), s.Line, html.EscapeString(s.Language))
	b.WriteString(`  <div class="snippet-body">` + "\n")
	b.WriteString(`    <table class="snippet-table">` + "\n")
	b.WriteString(`      <tbody>` + "\n")

	for _, l := range s.Lines {
		rowClass := "snippet-line snippet-" + string(l.Kind)
		markerChar := "&nbsp;"
		if l.IsFinding {
			rowClass += " snippet-finding"
			markerChar = "&gt;"
		}

		lineNumStr := "&nbsp;"
		if l.LineNumber > 0 {
			lineNumStr = fmt.Sprintf("%d", l.LineNumber)
		} else if l.OldLineNumber > 0 {
			lineNumStr = fmt.Sprintf("-%d", l.OldLineNumber)
		}

		signChar := "&nbsp;"
		switch l.Kind {
		case SnippetLineAdded:
			signChar = "+"
		case SnippetLineDeleted:
			signChar = "-"
		}

		fmt.Fprintf(&b, `        <tr class="%s"><td class="marker">%s</td><td class="line-num">%s</td><td class="diff-sign">%s</td><td class="line-code"><code>%s</code></td></tr>`+"\n",
			rowClass, markerChar, lineNumStr, signChar, html.EscapeString(l.Content))
	}

	b.WriteString(`      </tbody>` + "\n")
	b.WriteString(`    </table>` + "\n")
	b.WriteString(`  </div>` + "\n")
	b.WriteString(`</div>` + "\n")

	return b.String()
}
