package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// ProgressReporter defines the interface for emitting concise progress updates.
type ProgressReporter interface {
	Stage(current, total int, stageName string)
	Tick(message string)
	FileTick(current, total int, file string)
	Done(message string)
	IsEnabled() bool
	Writer() io.Writer
}

// ProgressTracker implements ProgressReporter for review and audit phases.
type ProgressTracker struct {
	mu           sync.Mutex
	w            io.Writer
	enabled      bool
	lastFileTick int
}

// NewProgressTracker constructs a ProgressTracker writing to w (defaults to os.Stderr).
func NewProgressTracker(w io.Writer, enabled bool) *ProgressTracker {
	if w == nil {
		w = os.Stderr
	}
	return &ProgressTracker{
		w:       w,
		enabled: enabled,
	}
}

func (p *ProgressTracker) IsEnabled() bool {
	if p == nil {
		return false
	}
	return p.enabled
}

func (p *ProgressTracker) Writer() io.Writer {
	if p == nil {
		return io.Discard
	}
	return p.w
}

// Stage outputs an indicator for the current high-level stage, e.g. "[1/4] Inspecting files...".
func (p *ProgressTracker) Stage(current, total int, stageName string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "[%d/%d] %s...\n", current, total, stageName)
}

// Tick outputs a concise progress sub-phase message.
func (p *ProgressTracker) Tick(message string) {
	if p == nil || !p.enabled || strings.TrimSpace(message) == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	fmt.Fprintf(p.w, "  -> %s\n", strings.TrimSpace(message))
}

// FileTick outputs file progress ticks periodically (e.g. every 50 files or on completion).
func (p *ProgressTracker) FileTick(current, total int, file string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	// Throttle ticks to avoid flooding: emit every 50 files, or when current == total
	if total > 0 && (current%50 == 0 || current == total || current == 1) {
		if current != p.lastFileTick {
			p.lastFileTick = current
			fmt.Fprintf(p.w, "  -> Scanned %d/%d files\n", current, total)
		}
	}
}

// Done signals completion of the progress lifecycle.
func (p *ProgressTracker) Done(message string) {
	if p == nil || !p.enabled {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if strings.TrimSpace(message) == "" {
		message = "Operation complete"
	}
	fmt.Fprintf(p.w, "[progress] %s\n", strings.TrimSpace(message))
}

// stdoutIsTTY checks whether standard output is connected to a terminal.
// It is declared as a variable to allow overrides in unit tests.
var stdoutIsTTY = func() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// IsMachineReadableFormat reports whether format produces structured machine-readable output.
func IsMachineReadableFormat(format string) bool {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "sarif", "json", "jsonl", "junit", "codeclimate":
		return true
	default:
		return false
	}
}

// IsProgressEnabled resolves whether progress reporting is enabled.
//
// Rules:
// 1. Explicit --progress or --no-progress flags take highest priority.
// 2. Otherwise, progress is automatically disabled when stdout is not a TTY.
// 3. Progress is also automatically disabled when machine-readable formats (JSON, JSONL, SARIF, etc.) are requested.
// 4. In interactive TTY human-readable sessions, progress defaults to enabled.
func IsProgressEnabled(explicit *bool, format string, isTTY bool) bool {
	if explicit != nil {
		return *explicit
	}
	if !isTTY {
		return false
	}
	if IsMachineReadableFormat(format) {
		return false
	}
	return true
}
