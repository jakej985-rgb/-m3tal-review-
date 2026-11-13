package typestate

import (
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/statemachine"
)

// Lifecycle state names in every derived contract.
const (
	stateAvailable = "available"
	stateConsumed  = "consumed"
)

// BuildContract derives the statemachine contract for spec s. The
// derived contract uses the fixed two-state lifecycle:
//
//	available --consume--> consumed
//	available --use-----> available   (stays; consumed use is illegal)
//	consumed  --reset---> available
//
// Any bound operation firing outside its legal source state produces
// an illegal-transition violation — there is no permissive fallback.
// BuildContract returns nil when the spec has no usable operations.
func BuildContract(s *Spec) *statemachine.Contract {
	if s == nil {
		return nil
	}
	names := s.eventNames()
	c := &statemachine.Contract{
		SchemaVersion: statemachine.SchemaVersion,
		ID:            s.ID,
		Name:          s.Name,
		Description:   s.Description,
		Resource:      s.Resource,
		OnUnhandled:   "report",
	}
	if c.Name == "" {
		c.Name = "Typestate: " + s.ID
	}
	c.States = []statemachine.StateSpec{
		{Name: stateAvailable, Initial: true, Description: "resource is live and usable"},
		{Name: stateConsumed, Description: "resource's single use has been consumed"},
	}
	for i := range s.Operations {
		op := &s.Operations[i]
		if op.Function == nil {
			continue // reported by Check; cannot bind
		}
		ev := statemachine.EventSpec{
			Name:        names[i],
			Description: operationDescription(op),
			Function:    op.Function,
		}
		if op.SubjectArg != nil {
			arg := *op.SubjectArg
			ev.SubjectArg = &arg
		}
		c.Events = append(c.Events, ev)

		var from, to string
		switch op.Kind {
		case KindConsume:
			from, to = stateAvailable, stateConsumed
		case KindUse:
			from = stateAvailable // empty To: stay in available
		case KindReset:
			from, to = stateConsumed, stateAvailable
		default:
			continue // invalid kind; reported by Check
		}
		c.Transitions = append(c.Transitions, statemachine.TransitionSpec{
			Event:       names[i],
			From:        from,
			To:          to,
			Description: operationDescription(op),
		})
	}
	c.Entry = append([]statemachine.FunctionSpec(nil), s.Entry...)
	return c
}

func operationDescription(op *OperationSpec) string {
	switch op.Kind {
	case KindConsume:
		return "consume the resource's single use"
	case KindUse:
		return "use the resource while available"
	case KindReset:
		return "reset/reissue a consumed resource"
	}
	return "lifecycle operation"
}
