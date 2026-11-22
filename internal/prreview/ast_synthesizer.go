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

var pySymbolRe = regexp.MustCompile(`^\s*(?:def|class)\s+([a-zA-Z0-9_]+)`)

func extractPythonSymbols(content []byte, changedLines map[int]bool) []string {
	return extractRegexSymbols(content, changedLines, pySymbolRe)
}

var jsSymbolRe = regexp.MustCompile(`^\s*(?:export\s+)?(?:async\s+)?(?:function|class|const|let|var)\s+([a-zA-Z0-9_]+)`)

func extractJSTSSymbols(content []byte, changedLines map[int]bool) []string {
	return extractRegexSymbols(content, changedLines, jsSymbolRe)
}

var rustSymbolRe = regexp.MustCompile(`^\s*(?:pub\s+)?(?:fn|struct|enum|trait|impl)\s+([a-zA-Z0-9_]+)`)

func extractRustSymbols(content []byte, changedLines map[int]bool) []string {
	return extractRegexSymbols(content, changedLines, rustSymbolRe)
}

var genericSymbolRe = regexp.MustCompile(`^\s*(?:public|private|protected|static|class|interface|func|fn|function|def)\s+([a-zA-Z0-9_]+)`)

func extractGenericSymbols(content []byte, changedLines map[int]bool) []string {
	return extractRegexSymbols(content, changedLines, genericSymbolRe)
}

func extractRegexSymbols(content []byte, changedLines map[int]bool, re *regexp.Regexp) []string {
	lines := strings.Split(string(content), "\n")
	symbolSet := make(map[string]bool)
	var symbols []string

	for idx, line := range lines {
		lineNum := idx + 1
		if !changedLines[lineNum] {
			continue
		}
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			sym := matches[1]
			if !symbolSet[sym] {
				symbolSet[sym] = true
				symbols = append(symbols, sym)
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
