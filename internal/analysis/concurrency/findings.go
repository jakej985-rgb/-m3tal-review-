package concurrency

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// Rule IDs emitted by this analyzer.
const (
	RuleCheckThenAct    = "concurrency-check-then-act"
	RuleLockOrder       = "concurrency-lock-order"
	RuleUnmatchedUnlock = "concurrency-unmatched-unlock"
)

// ---------------------------------------------------------------------
// Violation detection
// ---------------------------------------------------------------------

// violations scans a trace for check-then-act candidates: a shared,
// check-influencing read followed by a shared write to compatible
// state where the two accesses are not co-protected by a common
// critical-section instance.
func (a *Analyzer) violations(tr *traceResult) []analysis.Finding {
	var out []analysis.Finding
	pairChecks := 0
	for i := range tr.accesses {
		read := &tr.accesses[i]
		if read.kind != accRead || !read.shared || !read.check {
			continue
		}
		for j := i + 1; j < len(tr.accesses); j++ {
			write := &tr.accesses[j]
			if write.kind != accWrite || !write.shared {
				continue
			}
			pairChecks++
			if pairChecks > a.opts.MaxPairChecks {
				a.truncated = true
				a.note("pair-check budget exceeded in trace of " + tr.fn.ID)
				return out
			}
			if !keysConflict(read.keys, write.keys) {
				continue
			}
			if heldIntersect(read.held, write.held) {
				// Co-protected by at least one common critical
				// section: the pair is atomic with respect to that
				// lock.
				continue
			}
			// Deduplicate on the underlying instruction pair: the
			// same defect surfaces in every trace that inlines it.
			dk := accessID(read) + "|" + accessID(write)
			if a.seenViolations[dk] {
				continue
			}
			a.seenViolations[dk] = true
			out = append(out, a.checkThenActFinding(tr, read, write))
		}
	}
	return out
}

func accessID(acc *traceAccess) string {
	return acc.owner.ID + "#" + itoa(acc.instr.ID)
}

// heldIntersect reports whether two held-section ID sets share an
// instance.
func heldIntersect(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := make(map[string]bool, len(a))
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if set[y] {
			return true
		}
	}
	return false
}

// unheldUnlockFindings reports releases of mutex slots that were not
// held in the replayed event order.
func (a *Analyzer) unheldUnlockFindings(tr *traceResult) []analysis.Finding {
	var out []analysis.Finding
	for _, u := range tr.unheld {
		// Only report when the mutex is identifiable; unknown-mutex
		// releases were already noted as limitations.
		if len(u.keys) == 0 {
			continue
		}
		dk := "unlock|" + accessID(&traceAccess{owner: u.owner, instr: u.instr})
		if a.seenViolations[dk] {
			continue
		}
		a.seenViolations[dk] = true
		out = append(out, analysis.NewFinding(analysis.Finding{
			RuleID:     RuleUnmatchedUnlock,
			RuleName:   "Unlock of a mutex not held on this path",
			Analyzer:   "concurrency",
			Message:    fmt.Sprintf("unlock at %s:%d releases a mutex that the replayed event order does not show as held; on some paths this panics or releases the wrong critical section", baseName(u.instr.Position.File), u.instr.Position.Line),
			Category:   "risk",
			Severity:   "medium",
			Confidence: analysis.ConfidenceMedium,
			Status:     analysis.StatusPotential,
			Trace:      analysis.TraceLockSequence,
			Spans:      []analysis.Span{posToSpan(u.instr.Position)},
			Evidence: []analysis.EvidenceStep{
				{Kind: analysis.EvidenceLock, Span: posToSpan(u.instr.Position), Note: "unlock with no matching acquire on this event path"},
				noteStep(fmt.Sprintf("mutex identity: %s", describeKeys(u.keys))),
			},
			Remediation: "Verify the lock is acquired on every path reaching this unlock, and that lock/unlock calls are balanced (prefer defer for the unlock).",
		}))
	}
	return out
}

// ---------------------------------------------------------------------
// Lock ordering
// ---------------------------------------------------------------------

// observeLockOrder records acquisition-order observations from a
// trace: for every pair of distinct mutexes acquired in sequence, the
// order (first -> second) is evidence for potential deadlock when the
// opposite order is also observed.
func (a *Analyzer) observeLockOrder(tr *traceResult) {
	for i := 0; i < len(tr.lockSeq); i++ {
		for j := i + 1; j < len(tr.lockSeq); j++ {
			if a.lockPairs >= a.opts.MaxLockPairs {
				a.truncated = true
				return
			}
			first, second := tr.lockSeq[i], tr.lockSeq[j]
			if first.base == "" || second.base == "" || first.base == second.base {
				continue
			}
			a.lockPairs++
			m := a.lockOrder[first.base]
			if m == nil {
				m = make(map[string]*lockOrderObs)
				a.lockOrder[first.base] = m
			}
			if _, ok := m[second.base]; !ok {
				m[second.base] = &lockOrderObs{
					traceFnID: tr.fn.ID,
					instr:     second.instr,
					owner:     second.owner,
					second:    second.base,
				}
			}
		}
	}
}

// lockOrderFindings emits a potential-deadlock finding for every
// mutex pair observed in both acquisition orders.
func (a *Analyzer) lockOrderFindings() []analysis.Finding {
	var out []analysis.Finding
	var bases []string
	for b := range a.lockOrder {
		bases = append(bases, b)
	}
	sort.Strings(bases)
	for _, x := range bases {
		for y, obsXY := range a.lockOrder[x] {
			if x >= y {
				continue
			}
			obsYX := a.lockOrder[y][x]
			if obsXY == nil || obsYX == nil {
				continue
			}
			key := x + "|" + y
			if a.seenViolations["lockorder|"+key] {
				continue
			}
			a.seenViolations["lockorder|"+key] = true
			_ = obsXY
			out = append(out, analysis.NewFinding(analysis.Finding{
				RuleID:     RuleLockOrder,
				RuleName:   "Inconsistent lock ordering (potential deadlock)",
				Analyzer:   "concurrency",
				Message:    fmt.Sprintf("mutexes acquired in opposite orders (%s before %s in one trace, %s before %s in another); concurrent execution can deadlock", describeBase(x), describeBase(y), describeBase(y), describeBase(x)),
				Category:   "risk",
				Severity:   "low",
				Confidence: analysis.ConfidenceLow,
				Status:     analysis.StatusPotential,
				Trace:      analysis.TraceLockSequence,
				Spans: []analysis.Span{
					posToSpan(obsXY.instr.Position),
					posToSpan(obsYX.instr.Position),
				},
				Evidence: []analysis.EvidenceStep{
					{Kind: analysis.EvidenceLock, Span: posToSpan(obsXY.instr.Position), Note: "acquires " + describeBase(y) + " while holding " + describeBase(x)},
					{Kind: analysis.EvidenceLock, Span: posToSpan(obsYX.instr.Position), Note: "acquires " + describeBase(x) + " while holding " + describeBase(y)},
					noteStep("opposite acquisition orders observed; a consistent global lock order would rule out this deadlock pattern"),
				},
				Remediation: "Establish and document a single global lock ordering and acquire locks in that order everywhere, or restructure to avoid holding multiple locks.",
				Metadata: map[string]string{
					"lock_a": x,
					"lock_b": y,
				},
			}))
		}
	}
	return out
}

// ---------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------

// checkThenActFinding builds the atomicity-violation finding for one
// read/write pair.
func (a *Analyzer) checkThenActFinding(tr *traceResult, read, write *traceAccess) analysis.Finding {
	conflictKey := firstConflict(read.keys, write.keys)
	var evidence []analysis.EvidenceStep

	evidence = append(evidence, noteStep(fmt.Sprintf("shared state candidate: %s", describeKey(conflictKey))))

	// Check side.
	if len(read.held) > 0 {
		for _, id := range read.held {
			if sec := tr.sections[id]; sec != nil {
				evidence = append(evidence, analysis.EvidenceStep{
					Kind:   analysis.EvidenceLock,
					Span:   posToSpan(sec.acquire.Position),
					Entity: entityInstr(sec.owner, sec.acquire),
					Note:   "check read protected by critical section " + shortID(id),
				})
				break
			}
		}
	} else {
		evidence = append(evidence, noteStep("check read is not protected by any observed lock"))
	}
	evidence = append(evidence, analysis.EvidenceStep{
		Kind:   analysis.EvidenceState,
		Span:   posToSpan(read.instr.Position),
		Entity: entityInstr(read.owner, read.instr),
		Note:   "reads shared state (value may influence a branch)",
	})

	// Act side.
	if len(write.held) > 0 {
		for _, id := range write.held {
			if sec := tr.sections[id]; sec != nil {
				evidence = append(evidence, analysis.EvidenceStep{
					Kind:   analysis.EvidenceLock,
					Span:   posToSpan(sec.acquire.Position),
					Entity: entityInstr(sec.owner, sec.acquire),
					Note:   "update protected by a different critical section " + shortID(id),
				})
				break
			}
		}
	} else {
		evidence = append(evidence, noteStep("update is not protected by any observed lock"))
	}
	evidence = append(evidence, analysis.EvidenceStep{
		Kind:   analysis.EvidenceSink,
		Span:   posToSpan(write.instr.Position),
		Entity: entityInstr(write.owner, write.instr),
		Note:   "writes shared state",
	})

	interleave := "possible interleaving: another goroutine can modify the shared state between the check and the update because they execute under different critical sections (or none); the check's result may be stale when the update runs"
	if len(read.held) == 0 && len(write.held) == 0 {
		interleave = "possible interleaving: neither access is protected by an observed lock, so the check and update can interleave with any concurrent access"
	}
	evidence = append(evidence, noteStep(interleave))

	finding := analysis.NewFinding(analysis.Finding{
		RuleID:   RuleCheckThenAct,
		RuleName: "Check-then-act across separate critical sections",
		Analyzer: "concurrency",
		Message: fmt.Sprintf("potential atomicity violation: a check of shared state at %s:%d is not atomic with a later update at %s:%d (separate critical sections or no mutual exclusion)",
			baseName(read.instr.Position.File), read.instr.Position.Line,
			baseName(write.instr.Position.File), write.instr.Position.Line),
		Category:   "risk",
		Severity:   "medium",
		Confidence: analysis.ConfidenceMedium,
		Status:     analysis.StatusPotential,
		Trace:      analysis.TraceLockSequence,
		Spans: []analysis.Span{
			posToSpan(write.instr.Position),
			posToSpan(read.instr.Position),
		},
		Evidence: evidence,
		Remediation: "Combine the check and the update into a single critical section, use one atomic operation (e.g. sync/atomic CAS), or document why the interleaving is safe. " +
			"Confirm dynamically with `go test -race ./...`.",
		Metadata: map[string]string{
			"shared_state":   conflictKey.String(),
			"read_function":  read.owner.ID,
			"write_function": write.owner.ID,
		},
	})
	if tr.sawDynamic {
		finding.Truncation = analysis.Truncation{
			Truncated: true,
			Reasons:   []string{"unresolved dynamic call(s) in the analyzed trace may hide shared-state accesses"},
		}
	}
	if tr.accessTruncated {
		finding.Truncation.Truncated = true
		finding.Truncation.Reasons = append(finding.Truncation.Reasons, "access budget exhausted in the analyzed trace")
	}
	return finding
}

// ---------------------------------------------------------------------
// Diagnostics and helpers
// ---------------------------------------------------------------------

// diagnostics assembles the result's diagnostic list.
func (a *Analyzer) diagnostics() []analysis.Diagnostic {
	var out []analysis.Diagnostic

	// Flow-analysis diagnostics map across directly.
	for _, d := range a.flowRes.Diagnostics {
		out = append(out, analysis.Diagnostic{
			Severity: analysis.DiagnosticSeverity(d.Severity),
			Category: analysis.DiagnosticCategory(d.Category),
			Message:  "flow: " + d.Message,
		})
	}

	// Unsupported synchronization primitives.
	var uns []string
	for name := range a.unsupported {
		uns = append(uns, name)
	}
	sort.Strings(uns)
	for _, name := range uns {
		out = append(out, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagUnsupported,
			Message:  "synchronization primitive " + name + " is not modeled as mutual exclusion; accesses around it are treated as unprotected",
		})
	}
	if a.channelOps > 0 {
		out = append(out, analysis.Diagnostic{
			Severity: analysis.DiagSeverityInfo,
			Category: analysis.DiagUnsupported,
			Message:  fmt.Sprintf("%d channel operation(s) observed; channel happens-before edges are not modeled as mutual exclusion", a.channelOps),
		})
	}
	if a.atomicOps > 0 {
		out = append(out, analysis.Diagnostic{
			Severity: analysis.DiagSeverityInfo,
			Category: analysis.DiagNote,
			Message:  fmt.Sprintf("%d sync/atomic operation(s) modeled as single-operation accesses; sequences of atomic operations are not treated as atomic groups", a.atomicOps),
		})
	}
	if a.dynamicCalls > 0 {
		out = append(out, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagLimit,
			Message:  fmt.Sprintf("%d unresolved dynamic call site(s); shared-state accesses through them are not modeled", a.dynamicCalls),
		})
	}
	if a.opaqueCalls > 0 {
		out = append(out, analysis.Diagnostic{
			Severity: analysis.DiagSeverityInfo,
			Category: analysis.DiagNote,
			Message:  fmt.Sprintf("%d external or unmodeled call site(s); their shared-state effects are opaque to the analysis", a.opaqueCalls),
		})
	}
	for _, n := range a.notes {
		out = append(out, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagLimit,
			Message:  n,
		})
	}
	if a.flowQueriesHit {
		out = append(out, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning,
			Category: analysis.DiagLimit,
			Message:  "flow-query budget exhausted; some reads could not be classified as checks",
		})
	}
	return out
}

// dedupFindings removes duplicate findings by rule + primary span +
// evidence identity (pre-ID assignment).
func dedupFindings(fs []analysis.Finding) []analysis.Finding {
	seen := make(map[string]bool)
	out := fs[:0]
	for _, f := range fs {
		// Same rule + same primary location + same message is the
		// same defect even when reached through different traces.
		key := f.RuleID + "\x00" + f.PrimarySpan().Key() + "\x00" + f.Message
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------

func posToSpan(p semantic.Position) analysis.Span {
	return analysis.Span{
		File:        p.File,
		StartOffset: p.Offset,
		StartLine:   p.Line,
		StartColumn: p.Column,
		EndOffset:   p.EndOffset,
		EndLine:     p.EndLine,
		EndColumn:   p.EndColumn,
	}
}

func entityFn(fn *semantic.Function) *analysis.EntityRef {
	if fn == nil {
		return nil
	}
	return &analysis.EntityRef{Kind: analysis.EntityFunction, ID: fn.ID, Name: fn.Name, Span: posToSpan(fn.Position)}
}

func entityInstr(owner *semantic.Function, ins *semantic.Instruction) *analysis.EntityRef {
	if owner == nil || ins == nil {
		return nil
	}
	return &analysis.EntityRef{
		Kind: analysis.EntityInstruction,
		ID:   owner.ID + "#" + itoa(ins.ID),
		Name: ins.Detail,
		Span: posToSpan(ins.Position),
	}
}

func noteStep(note string) analysis.EvidenceStep {
	return analysis.EvidenceStep{Kind: analysis.EvidenceNote, Note: note}
}

func baseName(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[i+1:]
	}
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		return path[i+1:]
	}
	return path
}

func shortID(id string) string {
	if len(id) > 24 {
		return id[:24] + "…"
	}
	return id
}

func firstConflict(a, b []stateKey) stateKey {
	for _, ka := range a {
		for _, kb := range b {
			if ka.conflicts(kb) {
				return ka
			}
		}
	}
	if len(a) > 0 {
		return a[0]
	}
	return stateKey{}
}

// describeKey renders a state key for humans.
func describeKey(k stateKey) string {
	if k.isPlaceKey() {
		var parts []string
		for _, at := range k.places {
			parts = append(parts, describeAtom(at))
		}
		return "place: " + strings.Join(parts, " or ")
	}
	var parts []string
	for _, at := range k.origins {
		parts = append(parts, describeAtom(at))
	}
	return "derived from: " + strings.Join(parts, ", ")
}

func describeKeys(keys []stateKey) string {
	var parts []string
	for _, k := range keys {
		parts = append(parts, k.String())
	}
	return strings.Join(parts, "; ")
}

func describeBase(base string) string {
	// base is a join of canonical key strings; show the first key's
	// description for readability.
	if i := strings.IndexByte(base, ','); i >= 0 {
		base = base[:i]
	}
	return base
}

func describeAtom(at atom) string {
	switch at.kind {
	case atomPlaceGlobal:
		return "global " + at.id
	case atomPlaceParam:
		return fmt.Sprintf("parameter %d of %s", at.index, at.scope)
	case atomPlaceLocal:
		return "local " + at.id
	case atomPlaceUnknown:
		return "unknown place in " + at.scope
	case atomOriginGlobal:
		return "global " + at.id
	case atomOriginParam:
		return fmt.Sprintf("parameter %d of %s", at.index, at.scope)
	case atomOriginFreeVar:
		return fmt.Sprintf("captured variable %d of %s", at.index, at.scope)
	case atomOriginUnknown:
		return "unknown provenance"
	}
	return "?"
}
