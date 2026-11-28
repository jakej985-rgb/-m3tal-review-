package buildsystem

import (
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
)

// BuildSystemInfo describes a detected build system or package manager.
type BuildSystemInfo struct {
	Name     string   `json:"name"`
	Manifest string   `json:"manifest"`
	Paths    []string `json:"paths"`
}

var manifestToBuildSystem = map[string]string{
	"go.mod":           "Go Modules",
	"Cargo.toml":       "Cargo",
	"package.json":     "npm",
	"pnpm-lock.yaml":   "pnpm",
	"yarn.lock":        "Yarn",
	"pubspec.yaml":     "Pub",
	"pyproject.toml":   "Poetry/PEP517",
	"requirements.txt": "pip",
	"pom.xml":          "Maven",
	"build.gradle":     "Gradle",
	"build.gradle.kts": "Gradle",
	"composer.json":    "Composer",
	"Gemfile":          "Bundler",
}

// Detect identifies build systems from discovered repository manifests.
func Detect(inv scanner.RepositoryInventory) []BuildSystemInfo {
	var out []BuildSystemInfo
	for manifest, paths := range inv.Manifests {
		name, ok := manifestToBuildSystem[manifest]
		if !ok {
			lower := strings.ToLower(manifest)
			if strings.HasSuffix(lower, ".csproj") || strings.HasSuffix(lower, ".sln") {
				name = "NuGet/MSBuild"
			} else {
				continue
			}
		}
		out = append(out, BuildSystemInfo{
			Name:     name,
			Manifest: manifest,
			Paths:    paths,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Manifest < out[j].Manifest
	})
	return out
}
