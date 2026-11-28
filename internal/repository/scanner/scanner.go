package scanner

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const headerReadBytes = 2048

// FileEntry represents a discovered file in the repository.
type FileEntry struct {
	Path      string
	Ext       string
	Base      string
	Size      int64
	Excluded  bool
	ExclWhy   string
	Generated bool
	Header    string
}

// RepositoryInventory is the deterministic output of scanning a repository root.
type RepositoryInventory struct {
	Root      string
	Files     []FileEntry
	Manifests map[string][]string // manifest filename -> relative paths
}

// ScanOptions configures repository scanning.
type ScanOptions struct {
	MaxFiles int
	Exclude  []string
}

var defaultSkipDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"__pycache__":  true,
	".venv":        true,
	"venv":         true,
	"target":       true,
	"dist":         true,
	"build":        true,
	".dart_tool":   true,
}

var knownManifests = map[string]bool{
	"go.mod":           true,
	"Cargo.toml":       true,
	"package.json":     true,
	"pnpm-lock.yaml":   true,
	"yarn.lock":        true,
	"pubspec.yaml":     true,
	"pyproject.toml":   true,
	"requirements.txt": true,
	"pom.xml":          true,
	"build.gradle":     true,
	"build.gradle.kts": true,
	"composer.json":    true,
	"Gemfile":          true,
}

// Scan walks root deterministically and returns a RepositoryInventory.
func Scan(root string, opts ScanOptions) (RepositoryInventory, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return RepositoryInventory{}, err
	}
	inv := RepositoryInventory{
		Root:      absRoot,
		Manifests: make(map[string][]string),
	}

	err = filepath.WalkDir(absRoot, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(absRoot, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		slashRel := filepath.ToSlash(rel)

		if d.IsDir() {
			if defaultSkipDirs[d.Name()] {
				inv.Files = append(inv.Files, FileEntry{
					Path:     slashRel,
					Base:     d.Name(),
					Excluded: true,
					ExclWhy:  "vendored/ignored directory",
				})
				return filepath.SkipDir
			}
			return nil
		}

		if opts.MaxFiles > 0 && len(inv.Files) >= opts.MaxFiles {
			return nil
		}

		info, err := d.Info()
		var size int64
		if err == nil {
			size = info.Size()
		}

		base := d.Name()
		ext := strings.ToLower(filepath.Ext(base))
		if knownManifests[base] || ext == ".csproj" || ext == ".sln" {
			inv.Manifests[base] = append(inv.Manifests[base], slashRel)
		}

		header := readHeader(p)
		generated := isGeneratedContent(base, header)
		excluded := generated
		exclWhy := ""
		if generated {
			exclWhy = "generated file"
		}
		for _, pat := range opts.Exclude {
			if ok, _ := filepath.Match(pat, slashRel); ok {
				excluded = true
				exclWhy = "excluded by pattern"
				break
			}
		}

		inv.Files = append(inv.Files, FileEntry{
			Path:      slashRel,
			Ext:       ext,
			Base:      base,
			Size:      size,
			Excluded:  excluded,
			ExclWhy:   exclWhy,
			Generated: generated,
			Header:    header,
		})
		return nil
	})
	if err != nil {
		return RepositoryInventory{}, err
	}

	sort.Slice(inv.Files, func(i, j int) bool {
		return inv.Files[i].Path < inv.Files[j].Path
	})
	for k := range inv.Manifests {
		sort.Strings(inv.Manifests[k])
	}
	return inv, nil
}

func readHeader(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	var buf [headerReadBytes]byte
	n, err := io.ReadFull(f, buf[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return ""
	}
	slice := buf[:n]
	if bytes.IndexByte(slice, 0) >= 0 {
		return "" // binary file
	}
	return string(slice)
}

func isGeneratedContent(base, header string) bool {
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".pb.go") || strings.HasSuffix(lower, ".g.dart") || strings.HasSuffix(lower, ".min.js") {
		return true
	}
	return strings.Contains(header, "Code generated") && strings.Contains(header, "DO NOT EDIT")
}
