package plugin

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// Registry manages the set of available analyzer plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]AnalyzerPlugin
}

// NewRegistry constructs an empty plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]AnalyzerPlugin),
	}
}

// Register adds an analyzer plugin to the registry after validating it.
func (r *Registry) Register(p AnalyzerPlugin) error {
	if err := ValidatePlugin(p); err != nil {
		return fmt.Errorf("plugin validation failed: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := p.Metadata().Name
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %q is already registered", name)
	}
	r.plugins[name] = p
	return nil
}

// Get returns the plugin registered under the given name.
func (r *Registry) Get(name string) (AnalyzerPlugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[name]
	return p, ok
}

// List returns all registered plugins sorted by name.
func (r *Registry) List() []AnalyzerPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]AnalyzerPlugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Metadata().Name < list[j].Metadata().Name
	})
	return list
}

// MatchesScope checks if a plugin capability matches the target scope.
func MatchesScope(caps PluginCapabilities, scope string) bool {
	if len(caps.Scopes) == 0 {
		return true
	}
	for _, s := range caps.Scopes {
		if s == scope || s == "*" || s == "" {
			return true
		}
	}
	return false
}

// MatchesFiles checks if a plugin capability matches any of the target files.
func MatchesFiles(caps PluginCapabilities, files []string) bool {
	if len(caps.FilePatterns) == 0 && len(caps.Languages) == 0 {
		return true
	}
	if len(files) == 0 {
		return true
	}

	for _, file := range files {
		base := filepath.Base(file)
		for _, pat := range caps.FilePatterns {
			if ok, _ := filepath.Match(pat, base); ok {
				return true
			}
			if ok, _ := filepath.Match(pat, file); ok {
				return true
			}
		}
		ext := strings.ToLower(filepath.Ext(file))
		for _, lang := range caps.Languages {
			switch strings.ToLower(lang) {
			case "*", "all":
				return true
			case "go":
				if ext == ".go" {
					return true
				}
			case "js", "javascript":
				if ext == ".js" || ext == ".jsx" || ext == ".mjs" || ext == ".cjs" {
					return true
				}
			case "ts", "typescript":
				if ext == ".ts" || ext == ".tsx" {
					return true
				}
			case "py", "python":
				if ext == ".py" {
					return true
				}
			}
		}
	}
	return false
}

// RunPlugins executes all registered plugins matching input scope and target files.
func (r *Registry) RunPlugins(ctx context.Context, in PluginInput) ([]review.Finding, []review.CheckResult) {
	plugins := r.List()
	if len(plugins) == 0 {
		return nil, nil
	}

	var allFindings []review.Finding
	var allChecks []review.CheckResult

	for _, p := range plugins {
		caps := p.Capabilities()
		if !MatchesScope(caps, in.Scope) {
			continue
		}
		if len(in.Files) > 0 && !MatchesFiles(caps, in.Files) {
			continue
		}

		out := ExecutePlugin(ctx, p, in)
		allFindings = append(allFindings, out.Findings...)
		allChecks = append(allChecks, out.Checks...)
	}

	return allFindings, allChecks
}
