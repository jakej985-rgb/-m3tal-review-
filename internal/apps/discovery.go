package apps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// Discover finds, validates, and describes available language apps.
func Discover(ctx context.Context, cfg RunConfig) ([]App, []protocol.Diagnostic, error) {
	var diags []protocol.Diagnostic
	var searchDirs []string

	explicit := len(cfg.AppPaths) > 0
	if explicit {
		searchDirs = append(searchDirs, cfg.AppPaths...)
	} else {
		searchDirs = append(searchDirs, cfg.ConfigApps...)
		if envPaths := os.Getenv("REVIEW_APPS_PATH"); envPaths != "" {
			searchDirs = append(searchDirs, filepath.SplitList(envPaths)...)
		}
		if pathEnv := os.Getenv("PATH"); pathEnv != "" {
			for _, p := range filepath.SplitList(pathEnv) {
				if p == "" || !filepath.IsAbs(p) || filepath.Clean(p) == "." {
					continue
				}
				searchDirs = append(searchDirs, p)
			}
		}
		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			searchDirs = append(searchDirs, exeDir, filepath.Join(exeDir, "review-apps"))
		}
	}

	absRoot := ""
	if cfg.Root != "" {
		if r, err := filepath.Abs(cfg.Root); err == nil {
			if eval, err := filepath.EvalSymlinks(r); err == nil {
				absRoot = eval
			} else {
				absRoot = r
			}
		}
	}

	seenPaths := make(map[string]struct{})
	seenNames := make(map[string]string)
	var discovered []App

	for _, dir := range searchDirs {
		if dir == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if explicit {
				return nil, diags, &Error{Code: protocol.ExitError, Err: fmt.Errorf("app-path %q: %w", dir, err)}
			}
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !isAppBinaryName(name) {
				continue
			}
			fullPath, absErr := filepath.Abs(filepath.Join(dir, name))
			if absErr != nil {
				diags = append(diags, protocol.Diagnostic{
					Level:   "warning",
					Message: fmt.Sprintf("refused unresolvable app %s: %v", name, absErr),
				})
				continue
			}
			resolved, err := filepath.EvalSymlinks(fullPath)
			if err != nil {
				resolved = fullPath
			}
			if _, ok := seenPaths[resolved]; ok {
				continue
			}
			seenPaths[resolved] = struct{}{}

			info, err := os.Stat(resolved)
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			if runtime.GOOS != "windows" && info.Mode().Perm()&0111 == 0 {
				continue
			}
			if absRoot != "" && isInsideDir(resolved, absRoot) {
				diags = append(diags, protocol.Diagnostic{
					Level:   "warning",
					Message: fmt.Sprintf("refused repo-local app %s", resolved),
				})
				continue
			}
			if runtime.GOOS == "windows" && !hasWindowsExecExt(resolved) {
				continue
			}

			app, err := Describe(ctx, resolved)
			if err != nil {
				if explicit {
					return nil, diags, err
				}
				diags = append(diags, protocol.Diagnostic{
					Level:   "warning",
					Message: fmt.Sprintf("skipped app %s: %v", resolved, err),
				})
				continue
			}
			if prev, dup := seenNames[app.Name]; dup {
				diags = append(diags, protocol.Diagnostic{
					Level:   "warning",
					Message: fmt.Sprintf("duplicate app %q at %s (keeping %s)", app.Name, resolved, prev),
				})
				continue
			}
			seenNames[app.Name] = resolved
			discovered = append(discovered, app)
		}
	}

	return discovered, diags, nil
}

func hasWindowsExecExt(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".exe", ".bat", ".cmd", ".com":
		return true
	}
	return false
}

func isAppBinaryName(name string) bool {
	if strings.HasPrefix(name, "m3tal-review-plugin-") {
		return false
	}
	if strings.HasSuffix(name, ".json") {
		return false
	}
	return strings.HasPrefix(name, "m3tal-review-") || strings.HasPrefix(name, "review-")
}

func isInsideDir(target, dir string) bool {
	if filepath.IsAbs(target) && filepath.IsAbs(dir) &&
		!strings.EqualFold(filepath.VolumeName(target), filepath.VolumeName(dir)) {
		return false
	}
	rel, err := filepath.Rel(dir, target)
	if err != nil {
		return true
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}
