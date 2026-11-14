package pipeline

import (
	"context"
	"path/filepath"
	"sync"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic/golang"
)

// Loader caches semantic.Program loads so repeated pipeline runs in
// one process (tests, watch-style drivers, embedded use) do not
// repeat the expensive go/packages + SSA frontend work. The cache is
// keyed by the full load-relevant option set; entries live for the
// Loader's lifetime and are never invalidated — create a new Loader
// (or call Invalidate) when the analyzed tree may have changed.
//
// Load calls are serialized: the frontend load dominates runtime, so
// concurrent duplicate loads are prevented by holding the mutex for
// the duration of a miss.
type Loader struct {
	mu      sync.Mutex
	entries map[loadKey]*loadEntry
	loads   int
}

type loadKey struct {
	dir       string
	pattern   string
	tests     bool
	callGraph golang.CallGraphMode
	maxPkgs   int
	maxDiags  int
}

type loadEntry struct {
	prog *semantic.Program
	err  error
}

// NewLoader returns an empty program cache.
func NewLoader() *Loader {
	return &Loader{entries: make(map[loadKey]*loadEntry)}
}

// Loads returns the number of frontend loads actually performed
// (cache misses). Useful for verifying the shared-frontend-once
// property.
func (l *Loader) Loads() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loads
}

// Invalidate drops all cached programs.
func (l *Loader) Invalidate() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = make(map[loadKey]*loadEntry)
}

// Load returns the cached program for the option set, loading it via
// golang.Load on a miss. Both successes and failures are cached;
// context cancellation/deadline errors are not cached so a timed-out
// caller can retry.
func (l *Loader) Load(ctx context.Context, opts Options) (*semantic.Program, error) {
	dir, _ := filepath.Abs(opts.Dir)
	key := loadKey{
		dir:       dir,
		pattern:   opts.Pattern,
		tests:     opts.Tests,
		callGraph: opts.CallGraph,
		maxPkgs:   opts.MaxPackages,
		maxDiags:  opts.MaxDiagnostics,
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.entries[key]; ok {
		return e.prog, e.err
	}

	prog, err := golang.Load(ctx, golang.Options{
		Dir:            opts.Dir,
		Pattern:        opts.Pattern,
		Tests:          opts.Tests,
		CallGraph:      opts.CallGraph,
		MaxPackages:    opts.MaxPackages,
		MaxDiagnostics: opts.MaxDiagnostics,
	})
	if err != nil && (ctx.Err() != nil || err == context.Canceled || err == context.DeadlineExceeded) {
		// Do not cache cancellation: the tree may be fine and the
		// caller may retry with a fresh context.
		return prog, err
	}
	l.entries[key] = &loadEntry{prog: prog, err: err}
	l.loads++
	return prog, err
}

// loadProgram performs the shared frontend load for one Run, applying
// Options.LoadTimeout and routing through Options.Loader when set.
func loadProgram(ctx context.Context, opts Options) (*semantic.Program, error) {
	lctx := ctx
	cancel := func() {}
	if opts.LoadTimeout > 0 {
		lctx, cancel = context.WithTimeout(ctx, opts.LoadTimeout)
	}
	defer cancel()

	if opts.Loader != nil {
		return opts.Loader.Load(lctx, opts)
	}
	return golang.Load(lctx, golang.Options{
		Dir:            opts.Dir,
		Pattern:        opts.Pattern,
		Tests:          opts.Tests,
		CallGraph:      opts.CallGraph,
		MaxPackages:    opts.MaxPackages,
		MaxDiagnostics: opts.MaxDiagnostics,
	})
}
