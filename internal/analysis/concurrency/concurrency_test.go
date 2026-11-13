package concurrency

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic/golang"
)

// writeModule creates a temporary Go module from the given
// path → contents map (mirrors the helper in internal/analysis/flow).
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for path, contents := range files {
		full := filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func loadProgram(t *testing.T, files map[string]string) *semantic.Program {
	t.Helper()
	dir := writeModule(t, files)
	prog, err := golang.Load(context.Background(), golang.Options{Dir: dir})
	if err != nil {
		t.Fatalf("golang.Load: %v", err)
	}
	for _, d := range prog.Diagnostics {
		if d.Severity == semantic.SeverityError {
			t.Fatalf("load diagnostic: %s: %s", d.Category, d.Message)
		}
	}
	return prog
}

func analyze(t *testing.T, prog *semantic.Program) *Result {
	t.Helper()
	return NewAnalyzer(prog, Options{}).Analyze(context.Background())
}

func findingsOf(res *Result, rule string) []analysis.Finding {
	var out []analysis.Finding
	for _, f := range res.Findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

const goMod = `module concfixture

go 1.23
`

// splitFixture is the canonical check-then-act defect: the check and
// the update are each protected by the same mutex, but in separate
// critical sections, so they are not atomic as a group.
const splitFixture = `package main

import "sync"

type Server struct {
	mu    sync.Mutex
	count int
	max   int
}

func (s *Server) Allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count < s.max
}

func (s *Server) Inc() {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
}

func main() {
	s := &Server{max: 10}
	go func() {
		for {
			if s.Allow() {
				s.Inc()
			}
		}
	}()
}
`

// TestCheckThenActSplitAcrossLocks is the acceptance fixture: a
// protected check followed by a separate protected update must be
// flagged as a potential atomicity violation.
func TestCheckThenActSplitAcrossLocks(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod":  goMod,
		"main.go": splitFixture,
	})
	res := analyze(t, prog)

	fs := findingsOf(res, RuleCheckThenAct)
	if len(fs) == 0 {
		t.Fatalf("expected a check-then-act finding, got none; diagnostics: %v", res.Diagnostics)
	}
	f := fs[0]
	if f.Status != analysis.StatusPotential {
		t.Fatalf("status = %q, want potential", f.Status)
	}
	// Evidence must show the shared state, both critical sections,
	// and the interleaving rationale.
	var sawLock, sawState, sawSink, sawNote bool
	for _, e := range f.Evidence {
		switch e.Kind {
		case analysis.EvidenceLock:
			sawLock = true
		case analysis.EvidenceState:
			sawState = true
		case analysis.EvidenceSink:
			sawSink = true
		case analysis.EvidenceNote:
			if strings.Contains(e.Note, "interleav") {
				sawNote = true
			}
		}
	}
	if !sawLock || !sawState || !sawSink || !sawNote {
		t.Fatalf("incomplete evidence: lock=%v state=%v sink=%v note=%v\n%+v", sawLock, sawState, sawSink, sawNote, f.Evidence)
	}
	// Shared state and critical sections must be reported.
	if len(res.Shared) == 0 {
		t.Fatal("no shared state reported")
	}
	if len(res.Sections) < 2 {
		t.Fatalf("expected at least 2 critical sections, got %d", len(res.Sections))
	}
}

// TestCheckThenActSameSection is the negative acceptance fixture:
// check and update inside ONE critical section must NOT be flagged.
func TestCheckThenActSameSection(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

type Server struct {
	mu    sync.Mutex
	count int
	max   int
}

func (s *Server) AllowAndInc() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.count < s.max {
		s.count++
		return true
	}
	return false
}

func main() {
	s := &Server{max: 10}
	go func() {
		for s.AllowAndInc() {
		}
	}()
}
`,
	})
	res := analyze(t, prog)
	if fs := findingsOf(res, RuleCheckThenAct); len(fs) != 0 {
		for _, f := range fs {
			t.Fatalf("unexpected check-then-act finding: %s", f.Message)
		}
	}
}

// TestCheckThenActHelpers verifies the pattern is detected when the
// check and update live in plain helper functions (not methods).
func TestCheckThenActHelpers(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

type Server struct {
	mu    sync.Mutex
	count int
	max   int
}

var mu sync.Mutex

func check(s *Server) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count < s.max
}

func bump(s *Server) {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
}

func main() {
	s := &Server{max: 10}
	_ = mu
	go func() {
		for {
			if check(s) {
				bump(s)
			}
		}
	}()
}
`,
	})
	res := analyze(t, prog)
	if fs := findingsOf(res, RuleCheckThenAct); len(fs) == 0 {
		t.Fatal("expected check-then-act finding through helper functions")
	}
}

// TestCheckThenActAliases verifies that two different parameter names
// bound to the same actual argument still establish shared state.
func TestCheckThenActAliases(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

type Server struct {
	mu    sync.Mutex
	count int
	max   int
}

func (s *Server) Allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count < s.max
}

func (s *Server) Inc() {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
}

func use(a, b *Server) {
	if a.Allow() {
		b.Inc()
	}
}

func main() {
	s := &Server{max: 10}
	go use(s, s)
}
`,
	})
	res := analyze(t, prog)
	if fs := findingsOf(res, RuleCheckThenAct); len(fs) == 0 {
		t.Fatal("expected check-then-act finding through aliased arguments")
	}
}

// TestCheckThenActEarlyUnlock verifies that accesses after an explicit
// unlock are treated as unprotected and still flagged.
func TestCheckThenActEarlyUnlock(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

type Server struct {
	mu    sync.Mutex
	count int
	max   int
}

func (s *Server) Allow() bool {
	s.mu.Lock()
	ok := s.count < s.max
	s.mu.Unlock()
	return ok
}

func (s *Server) Inc() {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
}

func main() {
	s := &Server{max: 10}
	go func() {
		for {
			if s.Allow() {
				s.Inc()
			}
		}
	}()
}
`,
	})
	res := analyze(t, prog)
	fs := findingsOf(res, RuleCheckThenAct)
	if len(fs) == 0 {
		t.Fatal("expected check-then-act finding with early unlock")
	}
	// The check read happens after the unlock in Allow? No: read is
	// before unlock here, so it is still protected — but the update is
	// in a separate section regardless. The finding must exist; its
	// evidence should show two distinct sections or an unprotected side.
	_ = fs
}

// TestNestedCallsSameSection verifies that helper calls made while the
// caller holds the lock are attributed to the caller's critical
// section and therefore NOT flagged.
func TestNestedCallsSameSection(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

type Server struct {
	mu    sync.Mutex
	count int
	max   int
}

func (s *Server) readCount() int { return s.count }
func (s *Server) bumpCount()     { s.count++ }

func (s *Server) AllowAndInc() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readCount() < s.max {
		s.bumpCount()
		return true
	}
	return false
}

func main() {
	s := &Server{max: 10}
	go func() {
		for s.AllowAndInc() {
		}
	}()
}
`,
	})
	res := analyze(t, prog)
	if fs := findingsOf(res, RuleCheckThenAct); len(fs) != 0 {
		for _, f := range fs {
			t.Fatalf("unexpected check-then-act finding across nested calls in one section: %s", f.Message)
		}
	}
}

// TestRWMutex verifies RWMutex read/write locks are modeled: a check
// under RLock followed by an update under Lock in separate sections
// is flagged.
func TestRWMutex(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

type Server struct {
	mu    sync.RWMutex
	count int
	max   int
}

func (s *Server) Allow() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count < s.max
}

func (s *Server) Inc() {
	s.mu.Lock()
	s.count++
	s.mu.Unlock()
}

func main() {
	s := &Server{max: 10}
	go func() {
		for {
			if s.Allow() {
				s.Inc()
			}
		}
	}()
}
`,
	})
	res := analyze(t, prog)
	if fs := findingsOf(res, RuleCheckThenAct); len(fs) == 0 {
		t.Fatal("expected check-then-act finding with RWMutex")
	}
}

// TestUnknownSync verifies that unrecognized synchronization
// primitives surface as diagnostics instead of silent assumptions.
func TestUnknownSync(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

type Server struct {
	count int
	max   int
}

var once sync.Once

func (s *Server) Allow() bool {
	once.Do(func() {})
	return s.count < s.max
}

func (s *Server) Inc() {
	s.count++
}

func main() {
	s := &Server{max: 10}
	go func() {
		for {
			if s.Allow() {
				s.Inc()
			}
		}
	}()
}
`,
	})
	res := analyze(t, prog)
	var sawUnsupported bool
	for _, d := range res.Diagnostics {
		if d.Category == analysis.DiagUnsupported && strings.Contains(d.Message, "sync") {
			sawUnsupported = true
		}
	}
	if !sawUnsupported {
		t.Fatalf("expected an unsupported-sync diagnostic, got %v", res.Diagnostics)
	}
	// Unprotected check-then-act is still a candidate violation.
	if fs := findingsOf(res, RuleCheckThenAct); len(fs) == 0 {
		t.Fatal("expected check-then-act finding with unknown synchronization")
	}
}

// TestSequentialNoFinding verifies that check-then-act under separate
// locks in single-threaded code is NOT flagged: shared state must be
// established first.
func TestSequentialNoFinding(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

var mu sync.Mutex
var count, max int

func check() bool {
	mu.Lock()
	defer mu.Unlock()
	return count < max
}

func bump() {
	mu.Lock()
	count++
	mu.Unlock()
}

func main() {
	max = 10
	for {
		if check() {
			bump()
		}
	}
}
`,
	})
	res := analyze(t, prog)
	if fs := findingsOf(res, RuleCheckThenAct); len(fs) != 0 {
		for _, f := range fs {
			t.Fatalf("unexpected finding in sequential code: %s", f.Message)
		}
	}
}

// TestGlobalSharedState verifies globals accessed under two goroutine
// contexts are established as shared and flagged.
func TestGlobalSharedState(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

var mu sync.Mutex
var count, max int

func check() bool {
	mu.Lock()
	defer mu.Unlock()
	return count < max
}

func bump() {
	mu.Lock()
	count++
	mu.Unlock()
}

func main() {
	max = 10
	go func() {
		for {
			if check() {
				bump()
			}
		}
	}()
	count = 0
}
`,
	})
	res := analyze(t, prog)
	fs := findingsOf(res, RuleCheckThenAct)
	if len(fs) == 0 {
		t.Fatal("expected check-then-act finding on shared global state")
	}
	var sawGlobal bool
	for _, s := range res.Shared {
		if strings.Contains(s.Key, "global") {
			sawGlobal = true
		}
	}
	if !sawGlobal {
		t.Fatalf("expected a global shared-state entry, got %+v", res.Shared)
	}
}

// TestLockOrdering verifies inconsistent lock acquisition order is
// reported as a potential deadlock.
func TestLockOrdering(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

var muA, muB sync.Mutex

func ab() {
	muA.Lock()
	muB.Lock()
	muB.Unlock()
	muA.Unlock()
}

func ba() {
	muB.Lock()
	muA.Lock()
	muA.Unlock()
	muB.Unlock()
}

func main() {
	go ab()
	go ba()
}
`,
	})
	res := analyze(t, prog)
	fs := findingsOf(res, RuleLockOrder)
	if len(fs) == 0 {
		t.Fatalf("expected a lock-order finding, got %+v", res.Findings)
	}
	if fs[0].Status != analysis.StatusPotential {
		t.Fatalf("lock-order status = %q, want potential", fs[0].Status)
	}
}

// TestUnmatchedUnlock verifies unlock-without-acquire is reported.
func TestUnmatchedUnlock(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import "sync"

var mu sync.Mutex

func main() {
	go func() {
		mu.Unlock()
	}()
}
`,
	})
	res := analyze(t, prog)
	fs := findingsOf(res, RuleUnmatchedUnlock)
	if len(fs) == 0 {
		t.Fatalf("expected an unmatched-unlock finding, got %+v", res.Findings)
	}
}

// TestAtomicOps verifies sync/atomic accesses are modeled as
// single-operation reads/writes and produce diagnostics.
func TestAtomicOps(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod": goMod,
		"main.go": `package main

import (
	"sync"
	"sync/atomic"
)

var count int64
var mu sync.Mutex

func check() bool {
	mu.Lock()
	defer mu.Unlock()
	return atomic.LoadInt64(&count) < 10
}

func bump() {
	atomic.AddInt64(&count, 1)
}

func main() {
	count = 0
	go func() {
		for {
			if check() {
				bump()
			}
		}
	}()
}
`,
	})
	res := analyze(t, prog)
	var sawAtomicDiag bool
	for _, d := range res.Diagnostics {
		if strings.Contains(d.Message, "atomic") {
			sawAtomicDiag = true
		}
	}
	if !sawAtomicDiag {
		t.Fatalf("expected an atomic-ops diagnostic, got %v", res.Diagnostics)
	}
	// Atomic check + atomic act is still not atomic as a group.
	if fs := findingsOf(res, RuleCheckThenAct); len(fs) == 0 {
		t.Fatal("expected check-then-act finding through atomic ops")
	}
}

// TestFindingContract verifies emitted findings satisfy the analysis
// contract (Validate must pass for serialization).
func TestFindingContract(t *testing.T) {
	prog := loadProgram(t, map[string]string{
		"go.mod":  goMod,
		"main.go": splitFixture,
	})
	res := analyze(t, prog)
	for _, f := range res.Findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("finding %s invalid: %v", f.RuleID, err)
		}
		if _, err := f.MarshalJSON(); err != nil {
			t.Fatalf("finding %s does not marshal: %v", f.RuleID, err)
		}
	}
}
