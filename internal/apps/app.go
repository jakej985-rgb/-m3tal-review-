package apps

import (
	"time"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

const (
	// DefaultTimeout is the per-app execution timeout.
	DefaultTimeout = 5 * time.Minute
	// MaxTimeout is the maximum allowed per-app execution timeout.
	MaxTimeout = 15 * time.Minute
	// DescribeTimeout is the timeout for the --describe handshake.
	DescribeTimeout = 5 * time.Second
)

// App represents a discovered and described language app.
type App struct {
	Name             string
	Version          string
	Path             string
	Extensions       []string
	FilePatterns     []string
	Inputs           []string
	Capabilities     []string
	Rules            []protocol.RuleInfo
	DescribeDuration time.Duration
}

// AppResult records the outcome of running a single app.
type AppResult struct {
	App        App
	Status     string // "ok", "failed", "timeout", "protocol"
	ExitCode   int
	Duration   time.Duration
	Output     protocol.Output
	StderrTail string
	Err        error
}

// RunConfig configures an orchestrated multi-app run.
type RunConfig struct {
	Root              string
	Scope             string
	Mode              string
	AppPaths          []string
	ConfigApps        []string
	PerAppConfig      map[string]map[string]any
	Timeout           time.Duration
	DiagnosticsWanted bool
}

// RunReport aggregates results from all apps in a run.
type RunReport struct {
	Apps            []AppResult
	Findings        []protocol.Finding
	Diagnostics     []protocol.Diagnostic
	UnanalyzedFiles []string
	MissingClaims   []MissingClaim
	RoutedFiles     map[string]bool
	ExitCode        int
}
