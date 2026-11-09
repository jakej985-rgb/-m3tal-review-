package plugin

import (
	"context"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// PluginMetadata provides identification and provenance metadata for an analyzer plugin.
type PluginMetadata struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Description      string `json:"description,omitempty"`
	Author           string `json:"author,omitempty"`
	License          string `json:"license,omitempty"`
	MinRunnerVersion string `json:"min_runner_version,omitempty"`
}

// PluginCapabilities defines the analytical scopes, languages, and features supported by a plugin.
type PluginCapabilities struct {
	Scopes             []string `json:"scopes,omitempty"`        // "staged", "working-tree", or empty (all)
	Languages          []string `json:"languages,omitempty"`     // "go", "javascript", "python", or "*"
	FilePatterns       []string `json:"file_patterns,omitempty"` // globs e.g. ["*.go", "*.py"]
	Categories         []string `json:"categories,omitempty"`    // "security", "slop", "drift", etc.
	Rules              []string `json:"rules,omitempty"`         // list of rule IDs produced
	RequiresNetwork    bool     `json:"requires_network"`
	RequiresFileSystem bool     `json:"requires_file_system"`
}

// PluginInput contains execution context and target files passed to an analyzer plugin.
type PluginInput struct {
	RepositoryRoot string            `json:"repository_root"`
	Scope          string            `json:"scope"` // "staged" or "working-tree"
	Files          []string          `json:"files,omitempty"`
	Diff           string            `json:"diff,omitempty"`
	Timeout        time.Duration     `json:"timeout,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
}

// PluginOutput contains structured results returned by an analyzer plugin.
type PluginOutput struct {
	Success   bool                 `json:"success"`
	Findings  []review.Finding     `json:"findings,omitempty"`
	Checks    []review.CheckResult `json:"checks,omitempty"`
	RawOutput []byte               `json:"raw_output,omitempty"`
	ExitCode  int                  `json:"exit_code,omitempty"`
	Duration  time.Duration        `json:"duration,omitempty"`
	Message   string               `json:"message,omitempty"`
	Error     string               `json:"error,omitempty"`
}

// AnalyzerPlugin is the formal interface for external or in-process analyzer plugins.
type AnalyzerPlugin interface {
	Metadata() PluginMetadata
	Capabilities() PluginCapabilities
	Analyze(ctx context.Context, in PluginInput) (PluginOutput, error)
}
