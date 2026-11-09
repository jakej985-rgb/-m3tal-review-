package deps

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

var (
	singleRequireRe  = regexp.MustCompile(`^require\s+([^\s]+)\s+([^\s]+)(?:\s+//\s*(indirect))?`)
	blockRequireRe   = regexp.MustCompile(`^([^\s]+)\s+([^\s]+)(?:\s+//\s*(indirect))?`)
	replaceRe        = regexp.MustCompile(`^(?:replace\s+)?([^\s=>]+)(?:\s+([^\s=>]+))?\s*=>\s*([^\s=>]+)(?:\s+([^\s=>]+))?`)
	importFallbackRe = regexp.MustCompile(`"(?P<import>[^"\r\n]+)"`)
)

// ParseGoMod parses the content of a go.mod file.
func ParseGoMod(content string) (*GoMod, []review.Finding) {
	var findings []review.Finding
	mod := &GoMod{
		Requires: make([]RequireEntry, 0),
		Replaces: make([]ReplaceEntry, 0),
	}

	lines := strings.Split(content, "\n")
	inRequireBlock := false
	inReplaceBlock := false
	requireBlockStart := 0
	replaceBlockStart := 0

	for i, rawLine := range lines {
		lineNum := i + 1
		line := strings.TrimSpace(rawLine)

		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		if line == "module" || strings.HasPrefix(line, "module ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				mod.ModulePath = parts[1]
			} else {
				findings = append(findings, review.Finding{
					Category:    "confidence",
					Rule:        "go-module-malformed",
					Severity:    "high",
					File:        "go.mod",
					Line:        lineNum,
					Message:     "Malformed module directive in go.mod: missing module path",
					Remediation: "Specify a valid module path: module <path>",
				})
			}
			continue
		}

		if strings.HasPrefix(line, "go ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				mod.GoVersion = parts[1]
			}
			continue
		}

		// Handle block starts
		if line == "require (" || strings.HasPrefix(line, "require (") {
			if inRequireBlock {
				findings = append(findings, review.Finding{
					Category:    "confidence",
					Rule:        "go-module-malformed",
					Severity:    "high",
					File:        "go.mod",
					Line:        lineNum,
					Message:     "Nested require block in go.mod",
					Remediation: "Fix syntax error: close previous require block with ')'",
				})
			}
			inRequireBlock = true
			requireBlockStart = lineNum
			continue
		}

		if line == "replace (" || strings.HasPrefix(line, "replace (") {
			inReplaceBlock = true
			replaceBlockStart = lineNum
			continue
		}

		// Handle block ends
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}
		if inReplaceBlock && line == ")" {
			inReplaceBlock = false
			continue
		}

		// Inside require block
		if inRequireBlock {
			m := blockRequireRe.FindStringSubmatch(line)
			if m != nil {
				mod.Requires = append(mod.Requires, RequireEntry{
					Path:     m[1],
					Version:  m[2],
					Indirect: m[3] == "indirect",
					Line:     lineNum,
				})
			} else {
				findings = append(findings, review.Finding{
					Category:    "confidence",
					Rule:        "go-module-malformed",
					Severity:    "medium",
					File:        "go.mod",
					Line:        lineNum,
					Message:     fmt.Sprintf("Unrecognized require directive in go.mod: %q", line),
					Remediation: "Ensure require statements follow the format: <module> <version>",
				})
			}
			continue
		}

		// Inside replace block
		if inReplaceBlock {
			m := replaceRe.FindStringSubmatch(line)
			if m != nil {
				mod.Replaces = append(mod.Replaces, ReplaceEntry{
					OldPath:    m[1],
					OldVersion: m[2],
					NewPath:    m[3],
					NewVersion: m[4],
					Line:       lineNum,
				})
			}
			continue
		}

		// Single-line require
		if strings.HasPrefix(line, "require ") {
			m := singleRequireRe.FindStringSubmatch(line)
			if m != nil {
				mod.Requires = append(mod.Requires, RequireEntry{
					Path:     m[1],
					Version:  m[2],
					Indirect: m[3] == "indirect",
					Line:     lineNum,
				})
			} else {
				findings = append(findings, review.Finding{
					Category:    "confidence",
					Rule:        "go-module-malformed",
					Severity:    "medium",
					File:        "go.mod",
					Line:        lineNum,
					Message:     fmt.Sprintf("Malformed single-line require directive in go.mod: %q", line),
					Remediation: "Ensure require statements follow the format: require <module> <version>",
				})
			}
			continue
		}

		// Single-line replace
		if strings.HasPrefix(line, "replace ") {
			m := replaceRe.FindStringSubmatch(line)
			if m != nil {
				mod.Replaces = append(mod.Replaces, ReplaceEntry{
					OldPath:    m[1],
					OldVersion: m[2],
					NewPath:    m[3],
					NewVersion: m[4],
					Line:       lineNum,
				})
			}
			continue
		}
	}

	if inRequireBlock {
		findings = append(findings, review.Finding{
			Category:    "confidence",
			Rule:        "go-module-malformed",
			Severity:    "high",
			File:        "go.mod",
			Line:        requireBlockStart,
			Message:     "Unclosed require block in go.mod (missing closing ')')",
			Remediation: "Add closing parenthesis ')' to complete the require block",
		})
	}
	if inReplaceBlock {
		findings = append(findings, review.Finding{
			Category:    "confidence",
			Rule:        "go-module-malformed",
			Severity:    "high",
			File:        "go.mod",
			Line:        replaceBlockStart,
			Message:     "Unclosed replace block in go.mod (missing closing ')')",
			Remediation: "Add closing parenthesis ')' to complete the replace block",
		})
	}

	return mod, findings
}

// ParseGoSum parses the content of a go.sum file.
func ParseGoSum(content string) (*GoSum, []review.Finding) {
	var findings []review.Finding
	sum := &GoSum{
		Entries: make([]SumEntry, 0),
	}

	lines := strings.Split(content, "\n")
	for i, rawLine := range lines {
		lineNum := i + 1
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 3 {
			findings = append(findings, review.Finding{
				Category:    "confidence",
				Rule:        "go-sum-malformed",
				Severity:    "medium",
				File:        "go.sum",
				Line:        lineNum,
				Message:     fmt.Sprintf("Invalid go.sum line format (%d fields expected, got %d)", 3, len(fields)),
				Remediation: "Regenerate go.sum using 'go mod tidy' or 'go mod download'",
			})
			continue
		}

		modPath := fields[0]
		version := fields[1]
		hash := fields[2]

		isGoMod := false
		if strings.HasSuffix(version, "/go.mod") {
			isGoMod = true
			version = strings.TrimSuffix(version, "/go.mod")
		}

		if !strings.HasPrefix(hash, "h1:") {
			findings = append(findings, review.Finding{
				Category:    "confidence",
				Rule:        "go-sum-malformed",
				Severity:    "medium",
				File:        "go.sum",
				Line:        lineNum,
				Message:     fmt.Sprintf("Unexpected checksum algorithm in go.sum: %q (expected h1: prefix)", hash),
				Remediation: "Verify the checksum hash in go.sum or re-download the module",
			})
		}

		sum.Entries = append(sum.Entries, SumEntry{
			Path:    modPath,
			Version: version,
			IsGoMod: isGoMod,
			Hash:    hash,
			Line:    lineNum,
		})
	}

	return sum, findings
}

// collectImportPaths scans all Go source files in repoRoot and returns a set of imported package paths.
func collectImportPaths(repoRoot string) (map[string]bool, int, error) {
	imports := make(map[string]bool)
	totalGoFiles := 0
	fset := token.NewFileSet()

	err := filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}

		totalGoFiles++
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return nil
		}

		fileAst, parseErr := parser.ParseFile(fset, p, data, parser.ImportsOnly)
		if parseErr == nil && fileAst != nil {
			for _, imp := range fileAst.Imports {
				if imp != nil && imp.Path != nil {
					cleanPath := strings.Trim(imp.Path.Value, `"`)
					imports[cleanPath] = true
				}
			}
		} else {
			// Fallback: extract via regex if AST parsing hits syntax/build constraint errors
			matches := importFallbackRe.FindAllStringSubmatch(string(data), -1)
			for _, m := range matches {
				if len(m) >= 2 {
					imports[m[1]] = true
				}
			}
		}

		return nil
	})

	return imports, totalGoFiles, err
}

// AnalyzeGoModules performs hygiene checks on go.mod and go.sum.
func AnalyzeGoModules(repoRoot string) (*DepReport, []review.Finding, error) {
	report := &DepReport{
		IsGoModule: false,
		Licenses:   make(map[string]LicenseInfo),
	}

	modPath := filepath.Join(repoRoot, "go.mod")
	modData, err := os.ReadFile(modPath)
	if os.IsNotExist(err) {
		// Graceful handling of non-Go repos: return cleanly with 0 findings
		return report, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read go.mod: %w", err)
	}

	report.IsGoModule = true
	var findings []review.Finding

	// Parse go.mod
	parsedMod, modFindings := ParseGoMod(string(modData))
	findings = append(findings, modFindings...)
	report.ModulePath = parsedMod.ModulePath
	report.GoVersion = parsedMod.GoVersion

	// Parse go.sum if present
	sumPath := filepath.Join(repoRoot, "go.sum")
	if sumData, sumErr := os.ReadFile(sumPath); sumErr == nil {
		parsedSum, sumFindings := ParseGoSum(string(sumData))
		findings = append(findings, sumFindings...)

		// Check for duplicate / conflicting checksums in go.sum
		type sumKey struct {
			path    string
			version string
			isGoMod bool
		}
		seenSums := make(map[sumKey]SumEntry)
		for _, entry := range parsedSum.Entries {
			key := sumKey{path: entry.Path, version: entry.Version, isGoMod: entry.IsGoMod}
			if prev, exists := seenSums[key]; exists {
				if prev.Hash != entry.Hash {
					findings = append(findings, review.Finding{
						Category:    "security",
						Rule:        "go-sum-checksum-conflict",
						Severity:    "high",
						File:        "go.sum",
						Line:        entry.Line,
						Message:     fmt.Sprintf("Conflicting checksums in go.sum for %s %s (line %d has %s, line %d has %s)", entry.Path, entry.Version, prev.Line, prev.Hash, entry.Line, entry.Hash),
						Remediation: "Investigate possible cache tampering or repository corruption, then run 'go mod tidy'",
					})
				}
			} else {
				seenSums[key] = entry
			}
		}
	}

	// Check for duplicate/conflicting module requirements in go.mod
	seenRequires := make(map[string][]RequireEntry)
	for _, req := range parsedMod.Requires {
		seenRequires[req.Path] = append(seenRequires[req.Path], req)
		if req.Indirect {
			report.IndirectDeps++
		} else {
			report.DirectDeps++
		}
	}

	var duplicateMods []string
	for path, entries := range seenRequires {
		if len(entries) > 1 {
			duplicateMods = append(duplicateMods, path)
			for i := 1; i < len(entries); i++ {
				findings = append(findings, review.Finding{
					Category:    "drift",
					Rule:        "go-module-duplicate-dependency",
					Severity:    "medium",
					File:        "go.mod",
					Line:        entries[i].Line,
					Message:     fmt.Sprintf("Duplicate requirement for module %q (%s at line %d, %s at line %d)", path, entries[0].Version, entries[0].Line, entries[i].Version, entries[i].Line),
					Remediation: "Remove duplicate requirement and consolidate versions using 'go mod tidy'",
				})
			}
		}
	}
	sort.Strings(duplicateMods)
	report.Duplicates = duplicateMods

	// Scan repository source files for unused direct dependencies
	allImports, totalFiles, _ := collectImportPaths(repoRoot)
	report.TotalGoFiles = totalFiles

	var unusedDirect []string
	for _, req := range parsedMod.Requires {
		if req.Indirect {
			continue
		}
		// Check if any import in the repo starts with req.Path
		isUsed := false
		for imp := range allImports {
			if imp == req.Path || strings.HasPrefix(imp, req.Path+"/") {
				isUsed = true
				break
			}
		}

		if !isUsed {
			unusedDirect = append(unusedDirect, req.Path)
			findings = append(findings, review.Finding{
				Category:     "drift",
				Rule:         "go-module-unused-dependency",
				Severity:     "medium",
				File:         "go.mod",
				Line:         req.Line,
				Message:      fmt.Sprintf("Direct dependency %q is required in go.mod but not imported in any Go source file", req.Path),
				Remediation:  "Remove the unused direct dependency or run 'go mod tidy'",
				Reachability: string(ReachabilityUnreachable),
				Metadata: map[string]string{
					"reachability":           string(ReachabilityUnreachable),
					"reachability_rationale": "Direct dependency is required in go.mod but not imported in any Go source file",
					"dependency_type":        string(DependencyTypeDirect),
					"package":                req.Path,
				},
			})
		}
	}
	sort.Strings(unusedDirect)
	report.UnusedDeps = unusedDirect

	// Deterministic ordering of findings: File, Line, Rule, Message
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		if findings[i].Rule != findings[j].Rule {
			return findings[i].Rule < findings[j].Rule
		}
		return findings[i].Message < findings[j].Message
	})

	report.FindingsCount = len(findings)
	report.Findings = findings

	return report, findings, nil
}
