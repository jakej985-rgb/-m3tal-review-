package typestate

import (
	"context"
	"fmt"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/statemachine"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// Analyze runs typestate analysis for each spec against prog. Each
// spec is validated (Check), derived into a statemachine contract
// (BuildContract), and evaluated by the bounded statemachine
// evaluator; resulting findings are retagged as typestate findings
// with operation-kind-specific rule IDs and messages.
//
// opts are the statemachine evaluator budgets; pass statemachine.Options{}
// for defaults.
func Analyze(ctx context.Context, prog *semantic.Program, specs []*Spec, opts statemachine.Options) (*statemachine.Result, error) {
	if prog == nil {
		return nil, fmt.Errorf("typestate: nil program")
	}

	var contracts []*statemachine.Contract
	var diags []analysis.Diagnostic
	// specByContract maps derived contract ID → spec; kindByEvent maps
	// "contractID/eventName" → operation kind for finding retagging.
	specByContract := make(map[string]*Spec)
	kindByEvent := make(map[string]string)
	seenIDs := make(map[string]bool)

	for _, s := range specs {
		if s == nil {
			continue
		}
		for _, d := range s.Check() {
			diags = append(diags, analysis.Diagnostic{
				Severity: d.Severity,
				Category: d.Category,
				Message:  fmt.Sprintf("typestate spec %q: %s", s.ID, d.Message),
				Span:     d.Span,
			})
		}
		if seenIDs[s.ID] {
			diags = append(diags, analysis.Diagnostic{
				Severity: analysis.DiagSeverityError,
				Category: analysis.DiagParseError,
				Message:  fmt.Sprintf("typestate spec %q: duplicate spec ID", s.ID),
			})
			continue
		}
		seenIDs[s.ID] = true

		c := BuildContract(s)
		if c == nil || len(c.Events) == 0 {
			continue
		}
		contracts = append(contracts, c)
		specByContract[c.ID] = s
		names := s.eventNames()
		for i := range s.Operations {
			kindByEvent[c.ID+"/"+names[i]] = s.Operations[i].Kind
		}
	}

	res, err := statemachine.Evaluate(ctx, prog, contracts, opts)
	if err != nil {
		return nil, err
	}
	res.Diagnostics = append(res.Diagnostics, diags...)
	analysis.SortDiagnostics(res.Diagnostics)

	retagFindings(res, specByContract, kindByEvent)
	return res, nil
}

// retagFindings rewrites findings produced by the derived contracts
// into typestate findings: analyzer identity, operation-kind rule ID,
// and a lifecycle-specific message. Finding IDs are recomputed so they
// reflect the retagged rule.
func retagFindings(res *statemachine.Result, specByContract map[string]*Spec, kindByEvent map[string]string) {
	changed := false
	for i := range res.Findings {
		f := &res.Findings[i]
		if f.Analyzer != "statemachine" || f.Metadata == nil {
			continue
		}
		spec, ok := specByContract[f.Metadata["contract"]]
		if !ok {
			continue
		}
		kind := kindByEvent[f.Metadata["contract"]+"/"+f.Metadata["event"]]
		f.Analyzer = "typestate"
		f.RuleName = "Typestate lifecycle violation"
		f.RuleID = ruleIDForKind(kind)
		f.Message = violationMessage(spec, kind, f.Metadata["event"], f.Metadata["state"], f.Metadata["instance"])
		f.Metadata["kind"] = kind
		changed = true
	}
	if changed {
		res.Findings = analysis.AssignFindingIDs(res.Findings)
		analysis.SortFindings(res.Findings)
	}
}

// ruleIDForKind maps an operation kind to the finding rule ID. The
// state in which the operation fired determines the violation class;
// because each kind has exactly one legal source state, the kind fully
// determines the violation.
func ruleIDForKind(kind string) string {
	switch kind {
	case KindConsume:
		return "typestate-double-consume"
	case KindUse:
		return "typestate-use-after-consume"
	case KindReset:
		return "typestate-invalid-reset"
	default:
		return "typestate-illegal-transition"
	}
}

// violationMessage renders the lifecycle violation description. It
// names the spec, the violated rule class, and the machine context
// (event, state, instance) for correlation with the evidence trace.
func violationMessage(spec *Spec, kind, event, state, instance string) string {
	var desc string
	switch kind {
	case KindConsume:
		desc = "single-use resource consumed more than once along one path"
	case KindUse:
		desc = "resource used after it was consumed"
	case KindReset:
		desc = "reset/reissue attempted on a resource that is not consumed"
	default:
		desc = "illegal lifecycle transition"
	}
	msg := fmt.Sprintf("typestate %q: %s (event %q fired in state %q", spec.ID, desc, event, state)
	if instance != "" {
		msg += ", instance " + instance
	}
	return msg + ")"
}
