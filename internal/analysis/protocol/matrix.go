package protocol

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

// Snapshot binds a parsed contract to the deployed version label it
// represents and the source it was loaded from. Snapshots are the
// comparison inputs: checked-in contract documents for deployed
// versions. A single checkout only knows the snapshots it contains —
// EvaluateMatrix reports expected versions that have no snapshot
// instead of pretending coverage.
type Snapshot struct {
	// Version is the deployed version label (contract `version:` or,
	// when absent, the snapshot file's base name).
	Version string
	// Contract is the parsed, validated contract.
	Contract *Contract
	// Source is the file the snapshot was loaded from ("" for
	// in-memory snapshots).
	Source string
}

// SnapshotSet is a collection of contract snapshots for one
// protocol, keyed by version label.
type SnapshotSet struct {
	// Protocol is the contract ID shared by the snapshots
	// (typically "protocol" or a project-specific ID).
	Protocol string
	// ByVersion maps version labels to snapshots.
	ByVersion map[string]*Snapshot
	// Diagnostics records load and validation problems.
	Diagnostics []analysis.Diagnostic
}

// LoadSnapshot parses a single contract file into a Snapshot. The
// version label comes from the contract's `version:` field, falling
// back to the file's base name.
func LoadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read protocol snapshot: %w", err)
	}
	c, err := ParseContract(data)
	if err != nil {
		return nil, err
	}
	c.Source = path
	version := c.Version
	if version == "" {
		base := filepath.Base(path)
		version = strings.TrimSuffix(base, filepath.Ext(base))
	}
	return &Snapshot{Version: version, Contract: c, Source: path}, nil
}

// LoadSnapshotSet loads every *.yaml/*.yml contract file in dir
// (non-recursive, sorted for determinism) into a SnapshotSet. Files
// that fail to parse or validate are reported through the returned
// diagnostics; parsing errors are also returned as the error value
// only when NO file could be loaded.
func LoadSnapshotSet(dir string) (*SnapshotSet, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read snapshot dir: %w", err)
	}
	set := &SnapshotSet{ByVersion: make(map[string]*Snapshot)}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".yaml" || ext == ".yml" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	loaded := 0
	for _, name := range names {
		path := filepath.Join(dir, name)
		snap, err := LoadSnapshot(path)
		if err != nil {
			set.Diagnostics = append(set.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityError, Category: analysis.DiagParseError,
				Message: fmt.Sprintf("snapshot %s: %v", name, err),
			})
			continue
		}
		loaded++
		for _, d := range snap.Contract.Check() {
			set.Diagnostics = append(set.Diagnostics, d)
		}
		if set.Protocol == "" {
			set.Protocol = snap.Contract.ID
		} else if snap.Contract.ID != set.Protocol {
			set.Diagnostics = append(set.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityWarning, Category: analysis.DiagNote,
				Message: fmt.Sprintf("snapshot %s: contract id %q differs from set protocol %q",
					name, snap.Contract.ID, set.Protocol),
			})
		}
		if prev, dup := set.ByVersion[snap.Version]; dup {
			set.Diagnostics = append(set.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityError, Category: analysis.DiagParseError,
				Message: fmt.Sprintf("duplicate snapshot version %q (%s and %s)",
					snap.Version, prev.Source, snap.Source),
			})
			continue
		}
		set.ByVersion[snap.Version] = snap
	}
	if loaded == 0 && len(names) > 0 {
		return set, fmt.Errorf("no protocol snapshots could be loaded from %s", dir)
	}
	return set, nil
}

// Snapshot returns the snapshot for a version label, or nil.
func (s *SnapshotSet) Snapshot(version string) *Snapshot {
	if s == nil {
		return nil
	}
	return s.ByVersion[version]
}

// MatrixCell is the evaluated compatibility of one
// (client version, server version) pairing.
type MatrixCell struct {
	Client, Server string
	// Compatible is true when no unsuppressed finding has breaking
	// severity (medium or higher). Informational and low-severity
	// changes are listed but do not break compatibility.
	Compatible bool
	// Breaking lists findings with breaking severity.
	Breaking []analysis.Finding
	// Informational lists non-breaking findings (low/info severity).
	Informational []analysis.Finding
	// Changes lists the underlying unsuppressed changes.
	Changes []Change
	// Missing is true when either side has no snapshot; the cell is
	// then unevaluated and Compatible is false.
	Missing bool
}

// MatrixResult is a client-version x server-version compatibility
// matrix over a set of deployed-version snapshots.
type MatrixResult struct {
	// Versions lists the evaluated version labels in sorted order.
	Versions []string
	// Cells maps client version -> server version -> cell. Diagonal
	// cells (same version both sides) are trivially compatible.
	Cells map[string]map[string]MatrixCell
	// Diagnostics records missing snapshots, load problems, and
	// contract validation issues.
	Diagnostics []analysis.Diagnostic
	// Findings is the union of all unsuppressed findings across
	// evaluated pairs (for report-level consumers).
	Findings []analysis.Finding
}

// EvaluateMatrix builds the compatibility matrix for the expected
// deployed versions. versions is the authoritative list of deployed
// versions the caller believes exist; any version without a snapshot
// in set is reported as a diagnostic and its cells are marked
// Missing — the analyzer never pretends a single checkout knows
// deployed versions it cannot see.
//
// Versions are ordered lexically to define "older" vs "newer" for
// direction attribution; deploy order should therefore use
// zero-padded or semver-sortable labels. Each unordered pair is
// compared once and evaluated for both directions.
func EvaluateMatrix(set *SnapshotSet, versions []string) *MatrixResult {
	res := &MatrixResult{
		Cells: make(map[string]map[string]MatrixCell),
	}
	vers := append([]string(nil), versions...)
	sort.Strings(vers)
	// Deduplicate while preserving sorted order.
	dedup := vers[:0]
	for i, v := range vers {
		if i == 0 || v != vers[i-1] {
			dedup = append(dedup, v)
		}
	}
	vers = dedup
	res.Versions = vers

	if set != nil {
		res.Diagnostics = append(res.Diagnostics, set.Diagnostics...)
	}

	present := make(map[string]bool)
	for _, v := range vers {
		if set != nil && set.Snapshot(v) != nil {
			present[v] = true
			continue
		}
		res.Diagnostics = append(res.Diagnostics, analysis.Diagnostic{
			Severity: analysis.DiagSeverityWarning, Category: analysis.DiagLoadError,
			Message: fmt.Sprintf("missing protocol snapshot for deployed version %q; compatibility involving it cannot be evaluated", v),
		})
	}

	// Diagonal cells: same version on both sides is trivially
	// compatible when the snapshot exists.
	for _, v := range vers {
		res.Cells[v] = make(map[string]MatrixCell)
		if present[v] {
			res.Cells[v][v] = MatrixCell{Client: v, Server: v, Compatible: true}
		} else {
			res.Cells[v][v] = MatrixCell{Client: v, Server: v, Missing: true}
		}
	}

	// Off-diagonal: compare each unordered pair once (lexically
	// earlier = "old" role), then attribute directional findings to
	// the matching (client, server) cells.
	for i := 0; i < len(vers); i++ {
		for j := i + 1; j < len(vers); j++ {
			va, vb := vers[i], vers[j]
			sa, sb := set.Snapshot(va), set.Snapshot(vb)
			if sa == nil || sb == nil {
				continue
			}
			cmp := Compare(sa.Contract, sb.Contract)
			res.Diagnostics = append(res.Diagnostics, cmp.Diagnostics...)

			// cellA: client=va (older), server=vb (newer)
			// cellB: client=vb (newer), server=va (older)
			cellA := res.cell(va, vb)
			cellB := res.cell(vb, va)
			for _, ch := range cmp.Changes {
				if ch.Directions.Intersects(DirOldClientNewServer) {
					addToCell(&cellA, ch, cmp)
				}
				if ch.Directions.Intersects(DirNewClientOldServer) {
					addToCell(&cellB, ch, cmp)
				}
			}
			res.Cells[va][vb] = cellA
			res.Cells[vb][va] = cellB
		}
	}

	analysis.SortDiagnostics(res.Diagnostics)
	var all []analysis.Finding
	for _, row := range res.Cells {
		for _, cell := range row {
			all = append(all, cell.Breaking...)
			all = append(all, cell.Informational...)
		}
	}
	res.Findings = analysis.AssignFindingIDs(all)
	analysis.SortFindings(res.Findings)
	return res
}

func (r *MatrixResult) cell(client, server string) MatrixCell {
	if r.Cells[client] == nil {
		r.Cells[client] = make(map[string]MatrixCell)
	}
	if c, ok := r.Cells[client][server]; ok {
		return c
	}
	return MatrixCell{Client: client, Server: server, Compatible: true}
}

func addToCell(cell *MatrixCell, ch Change, cmp *Comparison) {
	cell.Changes = append(cell.Changes, ch)
	f := ch.Finding
	if breakingSeverity(ch.Severity) {
		cell.Compatible = false
		cell.Breaking = append(cell.Breaking, f)
	} else {
		cell.Informational = append(cell.Informational, f)
	}
	_ = cmp
}
