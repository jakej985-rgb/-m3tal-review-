package language

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
)

var extToLang = map[string]struct {
	lang string
	tier int
}{
	".go":     {"Go", 1},
	".py":     {"Python", 1},
	".pyi":    {"Python", 1},
	".js":     {"JavaScript", 1},
	".mjs":    {"JavaScript", 1},
	".cjs":    {"JavaScript", 1},
	".jsx":    {"JavaScript", 1},
	".ts":     {"TypeScript", 1},
	".mts":    {"TypeScript", 1},
	".cts":    {"TypeScript", 1},
	".tsx":    {"TypeScript", 1},
	".dart":   {"Dart", 1},
	".rs":     {"Rust", 1},
	".java":   {"Java", 1},
	".c":      {"C", 1},
	".cpp":    {"C++", 1},
	".cc":     {"C++", 1},
	".cxx":    {"C++", 1},
	".hpp":    {"C++", 1},
	".hxx":    {"C++", 1},
	".cs":     {"C#", 2},
	".kt":     {"Kotlin", 2},
	".kts":    {"Kotlin", 2},
	".swift":  {"Swift", 2},
	".php":    {"PHP", 2},
	".rb":     {"Ruby", 2},
	".sh":     {"Shell", 2},
	".bash":   {"Shell", 2},
	".zsh":    {"Shell", 2},
	".ps1":    {"PowerShell", 2},
	".sql":    {"SQL", 2},
	".lua":    {"Lua", 2},
	".scala":  {"Scala", 2},
	".ex":     {"Elixir", 2},
	".exs":    {"Elixir", 2},
	".hs":     {"Haskell", 2},
	".zig":    {"Zig", 2},
	".yml":    {"YAML", 2},
	".yaml":   {"YAML", 2},
	".tf":     {"Terraform", 2},
	".tfvars": {"Terraform", 2},
	".html":   {"HTML", 2},
	".vue":    {"Vue", 2},
}

var filenameToLang = map[string]struct {
	lang string
	tier int
}{
	"Dockerfile":   {"Dockerfile", 2},
	"Makefile":     {"Makefile", 2},
	"Jenkinsfile":  {"Groovy", 2},
	"go.mod":       {"Go", 1},
	"Cargo.toml":   {"Rust", 1},
	"pubspec.yaml": {"Dart", 1},
}

// Detect classifies all files in a scanned repository using multi-source evidence.
func Detect(inv scanner.RepositoryInventory, cfg DetectConfig) RepositoryDetection {
	var res RepositoryDetection
	langStats := make(map[string]*LanguageInfo)
	langEvidenceSet := make(map[string]map[string]bool)

	hasCppDir := false
	hasCDir := false
	for _, f := range inv.Files {
		if f.Ext == ".cpp" || f.Ext == ".cc" || f.Ext == ".cxx" || f.Ext == ".hpp" {
			hasCppDir = true
		}
		if f.Ext == ".c" {
			hasCDir = true
		}
	}

	recordLang := func(lang string, tier int, conf float64, ev []string) {
		info, ok := langStats[lang]
		if !ok {
			info = &LanguageInfo{Name: lang, Tier: tier, Confidence: conf}
			langStats[lang] = info
			langEvidenceSet[lang] = make(map[string]bool)
		}
		info.FileCount++
		if conf > info.Confidence {
			info.Confidence = conf
		}
		for _, e := range ev {
			if !langEvidenceSet[lang][e] {
				langEvidenceSet[lang][e] = true
				info.Evidence = append(info.Evidence, e)
			}
		}
	}

	for _, f := range inv.Files {
		if f.Excluded {
			res.Files = append(res.Files, FileDetection{
				Path:     f.Path,
				Status:   Excluded,
				Evidence: []string{f.ExclWhy},
			})
			res.Excluded = append(res.Excluded, f.Path)
			continue
		}

		fd := classifyFile(f, inv, cfg, hasCDir, hasCppDir)
		res.Files = append(res.Files, fd)
		switch fd.Status {
		case Detected:
			tier := lookupTier(fd.Language)
			recordLang(fd.Language, tier, fd.Confidence, fd.Evidence)
		case Ambiguous:
			res.Ambiguous = append(res.Ambiguous, f.Path)
		case Unknown:
			res.Unknown = append(res.Unknown, f.Path)
		}
	}

	for _, info := range langStats {
		sort.Strings(info.Evidence)
		res.Languages = append(res.Languages, *info)
	}
	sort.Slice(res.Languages, func(i, j int) bool {
		if res.Languages[i].FileCount != res.Languages[j].FileCount {
			return res.Languages[i].FileCount > res.Languages[j].FileCount
		}
		return res.Languages[i].Name < res.Languages[j].Name
	})
	return res
}

func classifyFile(f scanner.FileEntry, inv scanner.RepositoryInventory, cfg DetectConfig, hasCDir, hasCppDir bool) FileDetection {
	// 1. Explicit configuration override (Highest priority)
	for pat, lang := range cfg.Overrides {
		if pat == f.Ext || pat == f.Path {
			return FileDetection{
				Path:       f.Path,
				Language:   lang,
				Confidence: 1.0,
				Status:     Detected,
				Evidence:   []string{"explicit config override: " + pat},
			}
		}
		if ok, _ := filepath.Match(pat, f.Path); ok {
			return FileDetection{
				Path:       f.Path,
				Language:   lang,
				Confidence: 1.0,
				Status:     Detected,
				Evidence:   []string{"explicit config override: " + pat},
			}
		}
	}

	// 2. Known filenames & project manifests (High priority)
	if known, ok := filenameToLang[f.Base]; ok {
		return FileDetection{
			Path:       f.Path,
			Language:   known.lang,
			Confidence: 0.98,
			Status:     Detected,
			Evidence:   []string{"known filename/manifest: " + f.Base},
		}
	}
	if strings.HasPrefix(f.Base, "Dockerfile.") {
		return FileDetection{
			Path:       f.Path,
			Language:   "Dockerfile",
			Confidence: 0.95,
			Status:     Detected,
			Evidence:   []string{"filename prefix: Dockerfile."},
		}
	}

	// 3. Ambiguous extensions resolved via content or directory context
	if f.Ext == ".h" {
		if hasCppSyntax(f.Header) {
			return FileDetection{
				Path:       f.Path,
				Language:   "C++",
				Confidence: 0.85,
				Status:     Detected,
				Evidence:   []string{"extension .h", "content inspection: C++ syntax"},
			}
		}
		if hasCppDir && !hasCDir {
			return FileDetection{
				Path:       f.Path,
				Language:   "C++",
				Confidence: 0.75,
				Status:     Detected,
				Evidence:   []string{"extension .h", "directory context: C++ sources present"},
			}
		}
		if hasCDir && !hasCppDir {
			return FileDetection{
				Path:       f.Path,
				Language:   "C",
				Confidence: 0.75,
				Status:     Detected,
				Evidence:   []string{"extension .h", "directory context: C sources present"},
			}
		}
		return FileDetection{
			Path:       f.Path,
			Status:     Ambiguous,
			Confidence: 0.5,
			Evidence:   []string{"ambiguous .h header (C vs C++)"},
		}
	}

	// 4. File extensions (Medium priority)
	if entry, ok := extToLang[f.Ext]; ok {
		ev := []string{"extension: " + f.Ext}
		conf := 0.90
		if manifestEv := manifestContextForLang(entry.lang, inv); manifestEv != "" {
			ev = append(ev, manifestEv)
			conf = 0.98
		}
		var sec []string
		if f.Ext == ".html" && strings.Contains(f.Header, "<script") {
			sec = append(sec, "JavaScript")
		}
		if (f.Ext == ".yml" || f.Ext == ".yaml") && strings.Contains(f.Path, ".github/workflows/") && strings.Contains(f.Header, "run:") {
			sec = append(sec, "Shell")
		}
		return FileDetection{
			Path:               f.Path,
			Language:           entry.lang,
			SecondaryLanguages: sec,
			Confidence:         conf,
			Status:             Detected,
			Evidence:           ev,
		}
	}

	// 5. Shebang inspection (Medium priority)
	if lang, shebang := detectShebang(f.Header); lang != "" {
		return FileDetection{
			Path:       f.Path,
			Language:   lang,
			Confidence: 0.90,
			Status:     Detected,
			Evidence:   []string{"shebang: " + shebang},
		}
	}

	return FileDetection{
		Path:     f.Path,
		Status:   Unknown,
		Evidence: []string{"no matching manifest, extension, or shebang"},
	}
}

func hasCppSyntax(header string) bool {
	return strings.Contains(header, "namespace ") ||
		strings.Contains(header, "std::") ||
		strings.Contains(header, "class ") ||
		strings.Contains(header, "#include <iostream>")
}

func manifestContextForLang(lang string, inv scanner.RepositoryInventory) string {
	switch lang {
	case "Go":
		if len(inv.Manifests["go.mod"]) > 0 {
			return "manifest: go.mod"
		}
	case "Rust":
		if len(inv.Manifests["Cargo.toml"]) > 0 {
			return "manifest: Cargo.toml"
		}
	case "Dart":
		if len(inv.Manifests["pubspec.yaml"]) > 0 {
			return "manifest: pubspec.yaml"
		}
	case "Python":
		if len(inv.Manifests["pyproject.toml"]) > 0 || len(inv.Manifests["requirements.txt"]) > 0 {
			return "manifest: python"
		}
	case "TypeScript", "JavaScript":
		if len(inv.Manifests["package.json"]) > 0 {
			return "manifest: package.json"
		}
	}
	return ""
}

func detectShebang(header string) (string, string) {
	if !strings.HasPrefix(header, "#!") {
		return "", ""
	}
	firstLine, _, _ := strings.Cut(header, "\n")
	lower := strings.ToLower(firstLine)
	switch {
	case strings.Contains(lower, "python"):
		return "Python", firstLine
	case strings.Contains(lower, "bash"), strings.Contains(lower, "zsh"), strings.Contains(lower, "/sh"):
		return "Shell", firstLine
	case strings.Contains(lower, "node"):
		return "JavaScript", firstLine
	case strings.Contains(lower, "ruby"):
		return "Ruby", firstLine
	}
	return "", ""
}

func lookupTier(lang string) int {
	for _, c := range SupportedLanguages() {
		if c.Name == lang || (c.Name == "C/C++" && (lang == "C" || lang == "C++")) {
			return c.Tier
		}
	}
	return 2
}
