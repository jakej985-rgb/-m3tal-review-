package apps

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// RoutePlan maps each app to the files routed to it, plus any unclaimed registry extensions.
type RoutePlan struct {
	ByApp         map[string][]protocol.File
	AppOrder      []App
	ClaimedExts   map[string]string // ext -> app.Name
	MissingClaims []MissingClaim
	Diagnostics   []protocol.Diagnostic
}

// Route assigns files to discovered apps by extension or file pattern, checking registry claims.
func Route(apps []App, reg Registry, files []protocol.File) RoutePlan {
	plan := RoutePlan{
		ByApp:       make(map[string][]protocol.File),
		ClaimedExts: make(map[string]string),
	}

	appByName := make(map[string]App, len(apps))
	for _, a := range apps {
		appByName[a.Name] = a
		for _, ext := range a.Extensions {
			ext = strings.ToLower(ext)
			if prev, exists := plan.ClaimedExts[ext]; exists {
				plan.Diagnostics = append(plan.Diagnostics, protocol.Diagnostic{
					Level:   "warning",
					Message: fmt.Sprintf("extension %s claimed by both %s and %s (keeping %s)", ext, prev, a.Name, prev),
				})
				continue
			}
			plan.ClaimedExts[ext] = a.Name
		}
	}

	filesByExt := make(map[string][]string)
	for _, f := range files {
		routedApps := make(map[string]bool)
		ext := strings.ToLower(filepath.Ext(f.Path))
		if ext != "" {
			filesByExt[ext] = append(filesByExt[ext], f.Path)
			if appName, ok := plan.ClaimedExts[ext]; ok {
				routedApps[appName] = true
			}
		}

		for _, a := range apps {
			if routedApps[a.Name] || len(a.FilePatterns) == 0 {
				continue
			}
			if matchesAnyPattern(f.Path, a.FilePatterns) {
				routedApps[a.Name] = true
			}
		}

		for _, a := range apps {
			if !routedApps[a.Name] {
				continue
			}
			if _, seen := plan.ByApp[a.Name]; !seen {
				plan.AppOrder = append(plan.AppOrder, appByName[a.Name])
			}
			plan.ByApp[a.Name] = append(plan.ByApp[a.Name], f)
		}
	}

	for _, entry := range reg.Apps {
		if entry.Optional {
			continue
		}
		var missingFiles []string
		for _, ext := range entry.Extensions {
			ext = strings.ToLower(ext)
			if _, ok := plan.ClaimedExts[ext]; !ok {
				if matched := filesByExt[ext]; len(matched) > 0 {
					missingFiles = append(missingFiles, matched...)
				}
			}
		}
		if len(missingFiles) > 0 {
			plan.MissingClaims = append(plan.MissingClaims, MissingClaim{
				App:        entry.Name,
				Extensions: entry.Extensions,
				Files:      missingFiles,
			})
		}
	}

	return plan
}

func matchesAnyPattern(filePath string, patterns []string) bool {
	base := path.Base(filePath)
	for _, pat := range patterns {
		if ok, _ := path.Match(pat, filePath); ok {
			return true
		}
		if ok, _ := path.Match(pat, base); ok {
			return true
		}
	}
	return false
}
