package protocol

// Version is the wire protocol version spoken by the orchestrator and language apps.
const Version = "review-app/1"

// Kind is the expected kind value in a describe response.
const Kind = "review-app"

// MaxStdoutBytes caps a language app's stdout response (8 MiB).
const MaxStdoutBytes = 8 * 1024 * 1024

// MaxInputBytes caps the total stdin payload sent to an app (64 MiB).
const MaxInputBytes = 64 * 1024 * 1024

// MaxFileBytes caps a single file's inline content (4 MiB).
const MaxFileBytes = 4 * 1024 * 1024

// Categories supported by the uniform review-app contract.
const (
	CategoryBug      = "bug"
	CategorySecurity = "security"
	CategorySlop     = "slop"
)

// Severities supported by the uniform review-app contract.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Confidences supported by the uniform review-app contract.
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// InputModes declared by an app in its manifest and describe response.
const (
	InputContent  = "content"
	InputWorktree = "worktree"
)

// AppInfo identifies a language app.
type AppInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RuleInfo describes a single rule exposed by an app.
type RuleInfo struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Summary  string `json:"summary,omitempty"`
}

// DescribeResult is returned on stdout by `<app> --describe`.
type DescribeResult struct {
	Protocol     string         `json:"protocol"`
	Kind         string         `json:"kind"`
	App          AppInfo        `json:"app"`
	Extensions   []string       `json:"extensions"`
	FilePatterns []string       `json:"file_patterns,omitempty"`
	Inputs       []string       `json:"inputs"`
	Capabilities []string       `json:"capabilities,omitempty"`
	Rules        []RuleInfo     `json:"rules,omitempty"`
	ConfigSchema map[string]any `json:"config_schema,omitempty"`
}

// RunInfo provides execution context from the orchestrator to the app.
type RunInfo struct {
	Root  string `json:"root"`
	Scope string `json:"scope"`
	Mode  string `json:"mode"`
}

// File represents a single file sent to a language app over stdin.
type File struct {
	Path       string `json:"path"`
	Status     string `json:"status"`
	AddedLines []int  `json:"added_lines,omitempty"`
	Content    string `json:"content,omitempty"`
}

// Input is the stdin JSON request sent by the orchestrator to a language app.
type Input struct {
	Protocol          string         `json:"protocol"`
	Run               RunInfo        `json:"run"`
	Config            map[string]any `json:"config,omitempty"`
	Files             []File         `json:"files"`
	DiagnosticsWanted bool           `json:"diagnostics_wanted,omitempty"`
}

// Finding represents a single issue detected by a language app.
type Finding struct {
	Rule        string `json:"rule"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence,omitempty"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	EndLine     int    `json:"end_line,omitempty"`
	StartCol    int    `json:"start_col,omitempty"`
	EndCol      int    `json:"end_col,omitempty"`
	Message     string `json:"message"`
	Evidence    string `json:"evidence,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Diagnostic is an operational message emitted by an app.
type Diagnostic struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// UnanalyzedFile records a file the app could not analyze.
type UnanalyzedFile struct {
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// Stats summarizes the app's execution.
type Stats struct {
	Files      int   `json:"files"`
	Rules      int   `json:"rules"`
	DurationMs int64 `json:"duration_ms,omitempty"`
}

// Output is the stdout JSON response returned by a language app.
type Output struct {
	Protocol    string           `json:"protocol"`
	App         AppInfo          `json:"app"`
	Findings    []Finding        `json:"findings"`
	Diagnostics []Diagnostic     `json:"diagnostics,omitempty"`
	Unanalyzed  []UnanalyzedFile `json:"unanalyzed,omitempty"`
	Stats       Stats            `json:"stats"`
}
