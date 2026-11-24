package lifecycle

import (
	"fmt"
	"sort"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// HistoryRecord tracks historical findings from past commits or runs.
type HistoryRecord struct {
	ID        string `json:"id"`
	Rule      string `json:"rule"`
	File      string `json:"file"`
	Signature string `json:"signature,omitempty"`
}

func wasPreviouslyResolved(f review.Finding, history []HistoryRecord) bool {
	sig := ComputeSignature(f.Rule, f.File, f.Snippet, f.Message)
	for _, h := range history {
		if h.ID == f.ID || (h.Signature != "" && h.Signature == sig) {
			return true
		}
	}
	return false
}

func determineMatchedState(f review.Finding, match *BaselineEntry, kind MatchKind) (State, string) {
	if f.Severity != match.Severity {
		note := fmt.Sprintf("Severity shifted from %s to %s", match.Severity, f.Severity)
		return StateSeverityChanged, note
	}
	if kind == MatchHeuristic || f.Line != match.Line {
		note := fmt.Sprintf("Correlated via %s match (baseline line %d vs current %d)", kind, match.Line, f.Line)
		return StateChanged, note
	}
	return StateUnchanged, "Exact match with baseline record"
}

func countResultStates(res *LifecycleResult) {
	for _, lf := range res.ActiveFindings {
		switch lf.State {
		case StateNew:
			res.NewCount++
		case StateUnchanged:
			res.UnchangedCount++
		case StateChanged:
			res.ChangedCount++
		case StateSeverityChanged:
			res.SeverityChangeCount++
		case StateReintroduced:
			res.ReintroducedCount++
		}
	}
	res.ResolvedCount = len(res.ResolvedFindings)
}

func newLifecycleFinding(
	f review.Finding,
	state State,
	match MatchKind,
	baselineID, note string,
) LifecycleFinding {
	return LifecycleFinding{
		Finding:        f,
		State:          state,
		Match:          match,
		BaselineID:     baselineID,
		TransitionNote: note,
	}
}

// AdjudicateLifecycle compares current review findings against a baseline manifest and history.
func AdjudicateLifecycle(
	current []review.Finding,
	baseline *BaselineManifest,
	history []HistoryRecord,
) LifecycleResult {
	var res LifecycleResult
	if baseline == nil || len(baseline.Findings) == 0 {
		for _, f := range current {
			if wasPreviouslyResolved(f, history) {
				lf := newLifecycleFinding(f, StateReintroduced, MatchExact, "", "Resurfaced from history")
				res.ActiveFindings = append(res.ActiveFindings, lf)
			} else {
				lf := newLifecycleFinding(f, StateNew, MatchExact, "", "Initial discovery; no prior baseline")
				res.ActiveFindings = append(res.ActiveFindings, lf)
			}
		}
		countResultStates(&res)
		return res
	}

	seenBaseline := make(map[string]bool)

	for _, f := range current {
		match, kind, found := FindMatchingBaseline(f, baseline.Findings)
		if found {
			seenBaseline[match.ID] = true
			state, note := determineMatchedState(f, match, kind)
			res.ActiveFindings = append(res.ActiveFindings, newLifecycleFinding(f, state, kind, match.ID, note))
			continue
		}

		if wasPreviouslyResolved(f, history) {
			lf := newLifecycleFinding(f, StateReintroduced, MatchExact, "", "Defect resurfaced from history")
			res.ActiveFindings = append(res.ActiveFindings, lf)
		} else {
			lf := newLifecycleFinding(f, StateNew, MatchExact, "", "New defect introduced since baseline")
			res.ActiveFindings = append(res.ActiveFindings, lf)
		}
	}

	for _, b := range baseline.Findings {
		if !seenBaseline[b.ID] {
			res.ResolvedFindings = append(res.ResolvedFindings, b)
		}
	}

	sort.Slice(res.ResolvedFindings, func(i, j int) bool {
		return res.ResolvedFindings[i].ID < res.ResolvedFindings[j].ID
	})

	countResultStates(&res)
	return res
}
