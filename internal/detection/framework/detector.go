package framework

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/repository/scanner"
)

// FrameworkInfo describes a detected framework or infrastructure platform.
type FrameworkInfo struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"` // "framework" | "infrastructure"
	Confidence float64  `json:"confidence"`
	Evidence   []string `json:"evidence"`
}

// Detect identifies frameworks and infrastructure platforms from repository inventory.
func Detect(inv scanner.RepositoryInventory) []FrameworkInfo {
	found := make(map[string]*FrameworkInfo)
	add := func(name, kind string, conf float64, ev string) {
		f, ok := found[name]
		if !ok {
			f = &FrameworkInfo{Name: name, Kind: kind, Confidence: conf}
			found[name] = f
		}
		if conf > f.Confidence {
			f.Confidence = conf
		}
		for _, existing := range f.Evidence {
			if existing == ev {
				return
			}
		}
		f.Evidence = append(f.Evidence, ev)
	}

	// Inspect pubspec.yaml -> Flutter
	for _, rel := range inv.Manifests["pubspec.yaml"] {
		if data, err := os.ReadFile(filepath.Join(inv.Root, filepath.FromSlash(rel))); err == nil {
			if strings.Contains(string(data), "flutter:") || strings.Contains(string(data), "sdk: flutter") {
				add("Flutter", "framework", 0.98, "manifest "+rel+" declares flutter SDK")
			}
		}
	}

	// Inspect package.json -> React, Next.js, Vue, Angular
	for _, rel := range inv.Manifests["package.json"] {
		if data, err := os.ReadFile(filepath.Join(inv.Root, filepath.FromSlash(rel))); err == nil {
			text := string(data)
			if strings.Contains(text, `"react"`) {
				add("React", "framework", 0.95, "manifest "+rel+" depends on react")
			}
			if strings.Contains(text, `"next"`) {
				add("Next.js", "framework", 0.95, "manifest "+rel+" depends on next")
			}
			if strings.Contains(text, `"vue"`) {
				add("Vue", "framework", 0.95, "manifest "+rel+" depends on vue")
			}
			if strings.Contains(text, `"@angular/core"`) {
				add("Angular", "framework", 0.95, "manifest "+rel+" depends on @angular/core")
			}
		}
	}

	// Inspect Python manifests -> Django, FastAPI
	for _, key := range []string{"pyproject.toml", "requirements.txt"} {
		for _, rel := range inv.Manifests[key] {
			if data, err := os.ReadFile(filepath.Join(inv.Root, filepath.FromSlash(rel))); err == nil {
				lower := strings.ToLower(string(data))
				if strings.Contains(lower, "django") {
					add("Django", "framework", 0.90, "manifest "+rel+" references django")
				}
				if strings.Contains(lower, "fastapi") {
					add("FastAPI", "framework", 0.90, "manifest "+rel+" references fastapi")
				}
			}
		}
	}

	// Inspect Gradle/Maven -> Android, Spring
	for _, key := range []string{"build.gradle", "build.gradle.kts", "pom.xml"} {
		for _, rel := range inv.Manifests[key] {
			if data, err := os.ReadFile(filepath.Join(inv.Root, filepath.FromSlash(rel))); err == nil {
				text := string(data)
				if strings.Contains(text, "com.android.") {
					add("Android", "framework", 0.95, "manifest "+rel+" uses Android Gradle plugin")
				}
				if strings.Contains(text, "spring-boot") {
					add("Spring", "framework", 0.95, "manifest "+rel+" uses spring-boot")
				}
			}
		}
	}

	// Inspect files for .NET, Vue, Docker, Terraform, GitHub Actions, AndroidManifest
	for _, f := range inv.Files {
		if f.Excluded {
			continue
		}
		switch {
		case f.Ext == ".csproj" || f.Ext == ".sln":
			add(".NET", "framework", 0.95, "file "+f.Path)
		case f.Ext == ".vue":
			add("Vue", "framework", 0.95, "file "+f.Path)
		case f.Base == "AndroidManifest.xml":
			add("Android", "framework", 0.95, "file "+f.Path)
		case f.Base == "Dockerfile" || strings.HasPrefix(f.Base, "Dockerfile.") || f.Base == "compose.yaml" || f.Base == "docker-compose.yml":
			add("Docker", "infrastructure", 0.98, "file "+f.Path)
		case f.Ext == ".tf" || f.Ext == ".tfvars":
			add("Terraform", "infrastructure", 0.98, "file "+f.Path)
		case strings.HasPrefix(f.Path, ".github/workflows/") && (f.Ext == ".yml" || f.Ext == ".yaml"):
			add("GitHub Actions", "infrastructure", 0.98, "workflow "+f.Path)
		}
	}

	out := make([]FrameworkInfo, 0, len(found))
	for _, v := range found {
		sort.Strings(v.Evidence)
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}
