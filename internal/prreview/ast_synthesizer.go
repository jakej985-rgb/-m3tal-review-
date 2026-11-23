package prreview

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// TaxonomyCategory defines the architectural classification for a changed file.
type TaxonomyCategory string

const (
	TaxonomyArchAndAPI      TaxonomyCategory = "Architecture & APIs"
	TaxonomyCoreLogic       TaxonomyCategory = "Core Logic"
	TaxonomySecurityAndAuth TaxonomyCategory = "Security & Auth"
	TaxonomyDepsAndConfig   TaxonomyCategory = "Dependencies & Config"
	TaxonomyTestsAndTooling TaxonomyCategory = "Tests & Tooling"
)

// FileSummary summarizes changes for a single file.
type FileSummary struct {
	Path        string
	Category    TaxonomyCategory
	Symbols     []string
	Risk        string // "Low", "Moderate", "High"
	RiskReason  string
	SummaryText string
	Additions   int
	Deletions   int
	IsNew       bool
	IsDeleted   bool
}

// PRSynthesis encapsulates the deterministic synthesis of changes across an entire PR.
type PRSynthesis struct {
	TotalFiles     int
	TotalAdditions int
	TotalDeletions int
	Overview       string
	TaxonomyGroups map[TaxonomyCategory][]*FileSummary
	Files          []*FileSummary
}

// SynthesizeChanges analyzes the git diff and file contents to produce a deterministic PR overview.
func SynthesizeChanges(fileDiffs []*FileDiff, readFileFunc func(path string) ([]byte, error)) *PRSynthesis {
	synthesis := &PRSynthesis{
		TaxonomyGroups: make(map[TaxonomyCategory][]*FileSummary),
	}

	for _, diff := range fileDiffs {
		path := diff.NewPath
		if path == "" {
			path = diff.OldPath
		}
		if path == "" {
			continue
		}

		synthesis.TotalFiles++
		synthesis.TotalAdditions += diff.Additions
		synthesis.TotalDeletions += diff.Deletions

		var fileContent []byte
		if readFileFunc != nil && !diff.IsDeleted {
			fileContent, _ = readFileFunc(path)
		}

		fs := analyzeSingleFile(diff, fileContent)
		synthesis.Files = append(synthesis.Files, fs)
		synthesis.TaxonomyGroups[fs.Category] = append(synthesis.TaxonomyGroups[fs.Category], fs)
	}

	synthesis.Overview = generateExecutiveOverview(synthesis)
	return synthesis
}

func analyzeSingleFile(diff *FileDiff, content []byte) *FileSummary {
	path := diff.NewPath
	if path == "" {
		path = diff.OldPath
	}

	cat := classifyTaxonomy(path)
	symbols := extractModifiedSymbols(path, diff, content)

	// Determine risk and rationale
	risk := "Low"
	riskReason := "Localized low-impact change"

	isSecurity := cat == TaxonomySecurityAndAuth
	linesChanged := diff.Additions + diff.Deletions

	if isSecurity {
		risk = "High"
		riskReason = "Security/Auth sensitive code path modified"
	} else if diff.Deletions > 100 || linesChanged > 300 {
		risk = "High"
		riskReason = fmt.Sprintf("High change volume (+%d/-%d lines)", diff.Additions, diff.Deletions)
	} else if cat == TaxonomyArchAndAPI {
		risk = "Moderate"
		riskReason = "Public API or interface boundaries updated"
	} else if linesChanged > 50 {
		risk = "Moderate"
		riskReason = fmt.Sprintf("Moderate logic change (+%d/-%d lines)", diff.Additions, diff.Deletions)
	} else if cat == TaxonomyTestsAndTooling {
		risk = "Low"
		riskReason = "Test or tooling change"
	}

	summaryText := formatFileSummaryText(diff, cat, symbols)

	return &FileSummary{
		Path:        path,
		Category:    cat,
		Symbols:     symbols,
		Risk:        risk,
		RiskReason:  riskReason,
		SummaryText: summaryText,
		Additions:   diff.Additions,
		Deletions:   diff.Deletions,
		IsNew:       diff.IsNew,
		IsDeleted:   diff.IsDeleted,
	}
}

func classifyTaxonomy(path string) TaxonomyCategory {
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))

	// 1. Tests & Tooling
	if strings.HasSuffix(lower, "_test.go") ||
		strings.Contains(lower, "/test/") ||
		strings.Contains(lower, "/testdata/") ||
		strings.Contains(lower, "/tests/") ||
		strings.HasPrefix(lower, ".github/") ||
		base == "makefile" ||
		base == "dockerfile" ||
		strings.HasPrefix(lower, "scripts/") ||
		strings.HasSuffix(lower, ".spec.ts") ||
		strings.HasSuffix(lower, ".test.js") ||
		strings.HasSuffix(lower, ".test.py") {
		return TaxonomyTestsAndTooling
	}

	// 2. Dependencies & Config
	if base == "go.mod" || base == "go.sum" ||
		base == "package.json" || base == "package-lock.json" ||
		base == "cargo.toml" || base == "cargo.lock" ||
		base == "requirements.txt" || base == "gemfile" ||
		strings.HasSuffix(lower, ".yaml") ||
		strings.HasSuffix(lower, ".yml") ||
		strings.HasSuffix(lower, ".json") ||
		strings.HasSuffix(lower, ".toml") ||
		strings.HasPrefix(base, ".env") {
		return TaxonomyDepsAndConfig
	}

	// 3. Security & Auth
	secKeywords := []string{"auth", "token", "secret", "crypto", "permission", "session", "password", "login", "cert", "jwt", "oauth", "rbac", "sanitize", "policy"}
	for _, kw := range secKeywords {
		if strings.Contains(lower, kw) {
			return TaxonomySecurityAndAuth
		}
	}

	// 4. Architecture & APIs
	if strings.HasPrefix(lower, "api/") ||
		strings.Contains(lower, "/api/") ||
		strings.HasPrefix(lower, "proto/") ||
		strings.Contains(lower, "/proto/") ||
		strings.Contains(lower, "router") ||
		strings.Contains(lower, "route") ||
		strings.Contains(lower, "controller") ||
		strings.Contains(lower, "schema") ||
		strings.Contains(lower, "rpc") ||
		strings.Contains(lower, "graphql") ||
		strings.Contains(lower, "interface") {
		return TaxonomyArchAndAPI
	}

	// 5. Default: Core Logic
	return TaxonomyCoreLogic
}

func extractModifiedSymbols(path string, diff *FileDiff, content []byte) []string {
	if len(content) == 0 {
		return nil
	}

	changedLines := diff.ChangedLines()
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".go":
		return extractGoSymbols(content, changedLines)
	case ".py":
		return extractPythonSymbols(content, changedLines)
	case ".js", ".ts", ".jsx", ".tsx":
		return extractJSTSSymbols(content, changedLines)
	case ".rs":
		return extractRustSymbols(content, changedLines)
	case ".java":
		return extractJavaSymbols(content, changedLines)
	case ".kt", ".kts":
		return extractKotlinSymbols(content, changedLines)
	case ".cs":
		return extractCSharpSymbols(content, changedLines)
	case ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx":
		return extractCPPSymbols(content, changedLines)
	case ".swift":
		return extractSwiftSymbols(content, changedLines)
	case ".dart":
		return extractDartSymbols(content, changedLines)
	case ".php":
		return extractPHPSymbols(content, changedLines)
	case ".sh", ".bash", ".zsh":
		return extractShellSymbols(content, changedLines)
	default:
		return extractGenericSymbols(content, changedLines)
	}
}

func extractGoSymbols(content []byte, changedLines map[int]bool) []string {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "", content, parser.ParseComments)
	if err != nil {
		return nil
	}

	symbolSet := make(map[string]bool)
	var symbols []string

	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return true
		}

		pos := fset.Position(n.Pos())
		end := fset.Position(n.End())

		// Check if node overlaps with changed lines
		overlaps := false
		for line := pos.Line; line <= end.Line; line++ {
			if changedLines[line] {
				overlaps = true
				break
			}
		}

		if !overlaps {
			return true
		}

		switch fn := n.(type) {
		case *ast.FuncDecl:
			name := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				recvType := ""
				switch t := fn.Recv.List[0].Type.(type) {
				case *ast.StarExpr:
					if ident, ok := t.X.(*ast.Ident); ok {
						recvType = "*" + ident.Name
					}
				case *ast.Ident:
					recvType = t.Name
				}
				if recvType != "" {
					name = fmt.Sprintf("(%s).%s", recvType, name)
				}
			}
			if !symbolSet[name] {
				symbolSet[name] = true
				symbols = append(symbols, name)
			}
		case *ast.TypeSpec:
			name := fn.Name.Name
			if !symbolSet[name] {
				symbolSet[name] = true
				symbols = append(symbols, name)
			}
		}

		return true
	})

	return symbols
}

var (
	pySymbolRe      = regexp.MustCompile(`^\s*(?:async\s+def|def|class)\s+([a-zA-Z0-9_]+)`)
	pyRouteRe       = regexp.MustCompile(`@(?:app|router|bp|api_router)\.(get|post|put|delete|patch|route)\s*\(\s*['"]([^'"]+)['"]`)
	jsSymbolRe      = regexp.MustCompile(`^\s*(?:export\s+)?(?:async\s+)?(?:function|class|const|let|var|interface|type|enum)\s+([a-zA-Z0-9_]+)`)
	jsRouteRe       = regexp.MustCompile(`\b(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*['"]([^'"]+)['"]`)
	rustSymbolRe    = regexp.MustCompile(`^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+|const\s+|unsafe\s+|extern\s+(?:"[^"]+"\s+)?)?(?:fn|struct|enum|trait|type|mod)\s+([a-zA-Z0-9_]+)`)
	rustRouteRe     = regexp.MustCompile(`#\[\s*(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	javaSymbolRe    = regexp.MustCompile(`^\s*(?:public|protected|private|static|final|abstract|\s)*\b(?:class|interface|enum|record)\s+([a-zA-Z0-9_]+)|(?:public|protected|private|static|final|abstract|\s)+(?:[a-zA-Z0-9_<>[\]]+)\s+([a-zA-Z0-9_]+)\s*\([^)]*\)\s*(?:throws\s+[^{]+)?\s*\{?`)
	javaRouteRe     = regexp.MustCompile(`@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']`)
	ktSymbolRe      = regexp.MustCompile(`^\s*(?:data\s+|sealed\s+|enum\s+|inner\s+|open\s+|abstract\s+)?(?:class|interface|object)\s+([a-zA-Z0-9_]+)|(?:suspend\s+|override\s+|private\s+|public\s+|internal\s+)*fun\s+(?:<[^>]+>\s+)?([a-zA-Z0-9_]+)\s*\(`)
	ktRouteRe       = regexp.MustCompile(`\b(get|post|put|delete|patch|route)\s*\(\s*["']([^"']+)["']`)
	csharpSymbolRe  = regexp.MustCompile(`\b(?:class|record(?:\s+struct)?|struct|interface|enum)\s+([A-Za-z0-9_]+)|(?:public|protected|private|internal|static|async|virtual|override|abstract|sealed|partial|\s+)+[A-Za-z0-9_<>[\]?]+\s+([A-Za-z0-9_]+)\s*\([^)]*\)\s*(?:=>|{)`)
	csharpRouteRe   = regexp.MustCompile(`\b(?:app|routes|group)\.(MapGet|MapPost|MapPut|MapDelete|MapPatch)\s*\(\s*"([^"]+)"|\[Http(Get|Post|Put|Delete|Patch)\s*\(\s*"([^"]+)"`)
	cppSymbolRe     = regexp.MustCompile(`\b(?:class|struct|enum(?:\s+class)?|namespace)\s+([a-zA-Z0-9_]+)|(?:[\w:*&<>\s]+?\s+)?(?:([a-zA-Z0-9_]+::)*[a-zA-Z0-9_~]+)\s*\([^;]*\)\s*(?:const)?\s*[{;]?`)
	swiftSymbolRe   = regexp.MustCompile(`\b(?:struct|class|actor|protocol|enum|extension|func)\s+([a-zA-Z0-9_]+)`)
	dartSymbolRe    = regexp.MustCompile(`\b(?:class|mixin|enum|extension)\s+([a-zA-Z0-9_]+)|(?:void|[A-Z]\w*(?:<[^>]+>)?)\s+([a-zA-Z0-9_]+)\s*\(`)
	dartRouteRe     = regexp.MustCompile(`\bGoRoute\s*\(\s*path:\s*['"]([^'"]+)['"]`)
	phpSymbolRe     = regexp.MustCompile(`\b(?:class|trait|interface|enum)\s+([a-zA-Z0-9_]+)|\bfunction\s+([a-zA-Z0-9_]+)`)
	phpRouteRe      = regexp.MustCompile(`Route::(get|post|put|patch|delete|any)\s*\(\s*['"]([^'"]+)['"]|#\[Route\s*\(\s*['"]([^'"]+)['"]`)
	shellSymbolRe   = regexp.MustCompile(`^\s*(?:function\s+)?([a-zA-Z_][a-zA-Z0-9_-]*)\s*\(\s*\)|^\s*function\s+([a-zA-Z_][a-zA-Z0-9_-]*)`)
	genericSymbolRe = regexp.MustCompile(`^\s*(?:public|private|protected|static|class|interface|func|fn|function|def)\s+([a-zA-Z0-9_]+)`)
)

func extractPythonSymbols(content []byte, changedLines map[int]bool) []string {
	lines := strings.Split(string(content), "\n")
	symbolSet := make(map[string]bool)
	var symbols []string

	addSym := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" && !symbolSet[name] {
			symbolSet[name] = true
			symbols = append(symbols, name)
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		lineNum := i + 1

		if changedLines[lineNum] {
			if m := pyRouteRe.FindStringSubmatch(line); len(m) >= 3 {
				addSym(strings.ToUpper(m[1]) + " " + m[2])
			}
		}

		m := pySymbolRe.FindStringSubmatch(line)
		if len(m) > 1 {
			name := m[1]
			if changedLines[lineNum] {
				addSym(name)
			}

			declIndent := len(line) - len(strings.TrimLeft(line, " \t"))
			suiteEndLine := lineNum

			for scanIdx := i + 1; scanIdx < len(lines); scanIdx++ {
				scanLine := lines[scanIdx]
				trimmed := strings.TrimSpace(scanLine)
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				curIndent := len(scanLine) - len(strings.TrimLeft(scanLine, " \t"))
				if curIndent <= declIndent {
					break
				}
				suiteEndLine = scanIdx + 1
			}

			for cl := lineNum; cl <= suiteEndLine; cl++ {
				if changedLines[cl] {
					addSym(name)
					break
				}
			}
		}
	}
	return symbols
}

func extractJSTSSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, jsSymbolRe, jsRouteRe)
}

func extractRustSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, rustSymbolRe, rustRouteRe)
}

func extractJavaSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, javaSymbolRe, javaRouteRe)
}

func extractKotlinSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, ktSymbolRe, ktRouteRe)
}

func extractCSharpSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, csharpSymbolRe, csharpRouteRe)
}

func extractCPPSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, cppSymbolRe, nil)
}

func extractSwiftSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, swiftSymbolRe, nil)
}

func extractDartSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, dartSymbolRe, dartRouteRe)
}

func extractPHPSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, phpSymbolRe, phpRouteRe)
}

func extractShellSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, shellSymbolRe, nil)
}

func extractGenericSymbols(content []byte, changedLines map[int]bool) []string {
	return extractBraceSpanSymbols(content, changedLines, genericSymbolRe, nil)
}

func extractBraceSpanSymbols(content []byte, changedLines map[int]bool, declRe *regexp.Regexp, routeRe *regexp.Regexp) []string {
	lines := strings.Split(string(content), "\n")
	symbolSet := make(map[string]bool)
	var symbols []string

	addSym := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" && !symbolSet[name] {
			symbolSet[name] = true
			symbols = append(symbols, name)
		}
	}

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		lineNum := i + 1

		if routeRe != nil && changedLines[lineNum] {
			if m := routeRe.FindStringSubmatch(line); len(m) > 1 {
				if len(m) >= 3 && m[2] != "" {
					addSym(strings.ToUpper(m[1]) + " " + m[2])
				} else {
					addSym(m[1])
				}
			}
		}

		if declRe == nil {
			continue
		}

		m := declRe.FindStringSubmatch(line)
		if len(m) > 1 {
			name := ""
			for j := len(m) - 1; j >= 1; j-- {
				if m[j] != "" {
					name = m[j]
					break
				}
			}
			if name == "" {
				continue
			}

			if changedLines[lineNum] {
				addSym(name)
			}

			braceStartLine := -1
			for scanIdx := i; scanIdx < len(lines); scanIdx++ {
				l := lines[scanIdx]
				if strings.Contains(l, "{") {
					braceStartLine = scanIdx
					break
				}
				if strings.Contains(l, ";") || scanIdx > i+3 {
					break
				}
			}

			if braceStartLine != -1 {
				openCount := 0
				endLine := -1
				for scanIdx := braceStartLine; scanIdx < len(lines); scanIdx++ {
					for _, ch := range lines[scanIdx] {
						if ch == '{' {
							openCount++
						} else if ch == '}' {
							openCount--
							if openCount == 0 {
								endLine = scanIdx + 1
								break
							}
						}
					}
					if openCount == 0 && endLine != -1 {
						break
					}
				}

				if endLine != -1 {
					for cl := lineNum; cl <= endLine; cl++ {
						if changedLines[cl] {
							addSym(name)
							break
						}
					}
				}
			}
		}
	}

	return symbols
}

func formatFileSummaryText(diff *FileDiff, cat TaxonomyCategory, symbols []string) string {
	if diff.IsNew {
		if len(symbols) > 0 {
			return fmt.Sprintf("Introduced new file declaring `%s`", strings.Join(symbols, "`, `"))
		}
		return "Added new file"
	}
	if diff.IsDeleted {
		return "Deleted file"
	}
	if diff.IsRenamed {
		return fmt.Sprintf("Renamed from `%s`", diff.OldPath)
	}

	if len(symbols) > 0 {
		return fmt.Sprintf("Updated `%s`", strings.Join(symbols, "`, `"))
	}

	return fmt.Sprintf("Updated %s with +%d/-%d line changes", strings.ToLower(string(cat)), diff.Additions, diff.Deletions)
}

func generateExecutiveOverview(synth *PRSynthesis) string {
	var cats []string
	for cat, files := range synth.TaxonomyGroups {
		if len(files) > 0 {
			cats = append(cats, fmt.Sprintf("%s (%d files)", cat, len(files)))
		}
	}
	sort.Strings(cats)

	var b strings.Builder
	fmt.Fprintf(&b, "Deterministically reviewed **%d modified file(s)** with **+%d / -%d** line changes across %d architectural domains.\n\n",
		synth.TotalFiles, synth.TotalAdditions, synth.TotalDeletions, len(cats))

	if len(cats) > 0 {
		b.WriteString("**Active Components:**\n")
		for _, cat := range cats {
			fmt.Fprintf(&b, "- %s\n", cat)
		}
	}

	return b.String()
}
