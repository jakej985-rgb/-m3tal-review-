package typestate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/analysis/statemachine"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only typestate spec schema version this
// package understands.
const SchemaVersion = "typestate/1"

// Operation kinds. The kind determines the operation's place in the
// derived lifecycle; the operation's *name* in the program is
// irrelevant — only the structural function binding matters.
const (
	// KindConsume marks the single use of a resource: legal only in
	// the "available" state, moving the instance to "consumed". A
	// second consume on the same path is a double-consumption
	// violation.
	KindConsume = "consume"
	// KindUse reads or otherwise relies on the resource without
	// consuming it: legal only while "available". Firing in
	// "consumed" is a use-after-consume violation.
	KindUse = "use"
	// KindReset re-arms a consumed resource (reissue, refresh,
	// reopen): legal only in "consumed", returning the instance to
	// "available". Firing while "available" is an invalid reset.
	KindReset = "reset"
)

// Spec is a versioned typestate declaration for one resource type.
// It is language-neutral: operations bind to program entities
// structurally through the semantic program model.
type Spec struct {
	SchemaVersion string `yaml:"schema_version"`
	// ID is a stable identifier used in diagnostics, finding
	// metadata, and sequence reports. Defaults to "typestate".
	ID string `yaml:"id"`
	// Name and Description are human-readable documentation.
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Resource optionally declares the subject type the lifecycle
	// governs ("[pkg/path][*].Name"). When present it is bound
	// structurally; an unbound resource degrades instance tracking
	// to shared/unknown keys and is reported.
	Resource *statemachine.ResourceSpec `yaml:"resource"`

	// Operations declares the lifecycle operations. At least one
	// operation is required.
	Operations []OperationSpec `yaml:"operations"`

	// Entry optionally lists function bindings that seed the bounded
	// path exploration. When empty, every modeled function with a
	// body is a potential entry point.
	Entry []statemachine.FunctionSpec `yaml:"entry"`

	prepared bool
	diags    []analysis.Diagnostic
}

// OperationSpec declares one lifecycle operation and its function
// binding.
type OperationSpec struct {
	// Kind is one of "consume", "use", or "reset" (see the Kind*
	// constants). Required.
	Kind string `yaml:"kind"`
	// Name optionally overrides the derived event name used in
	// messages and metadata. Defaults to the kind (suffixed -2, -3,
	// ... on collisions). The name is documentation only — it never
	// affects which program functions are bound.
	Name string `yaml:"name"`
	// Function structurally binds the operation to program
	// functions. Required for program evaluation.
	Function *statemachine.FunctionSpec `yaml:"function"`
	// SubjectArg is the index (in the aligned argument list, where
	// index 0 is the receiver for methods) of the call argument that
	// identifies the resource instance. Default 0; -1 selects the
	// contract's single shared instance.
	SubjectArg *int `yaml:"subject_arg"`
}

// ParseSpec parses a typestate spec document. YAML is canonical; JSON
// parses as a YAML subset. A non-nil error is returned only for
// unreadable input or a wrong/missing schema version; semantic
// problems are reported through Check.
func ParseSpec(data []byte) (*Spec, error) {
	var s Spec
	if err := yaml.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("typestate spec: %w", err)
	}
	if s.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("typestate spec: unsupported schema_version %q (want %q)", s.SchemaVersion, SchemaVersion)
	}
	if s.ID == "" {
		s.ID = "typestate"
	}
	return &s, nil
}

// Check validates the spec and returns all problems found, sorted
// deterministically. It is idempotent.
func (s *Spec) Check() []analysis.Diagnostic {
	if s.prepared {
		return s.diags
	}
	s.prepared = true
	var diags []analysis.Diagnostic
	add := func(sev analysis.DiagnosticSeverity, cat analysis.DiagnosticCategory, msg string) {
		diags = append(diags, analysis.Diagnostic{Severity: sev, Category: cat, Message: msg})
	}

	if len(s.Operations) == 0 {
		add(analysis.DiagSeverityError, analysis.DiagParseError, "spec declares no operations")
	}
	names := s.eventNames()
	for i, op := range s.Operations {
		where := fmt.Sprintf("operations[%d]", i)
		switch op.Kind {
		case KindConsume, KindUse, KindReset:
		default:
			add(analysis.DiagSeverityError, analysis.DiagParseError,
				fmt.Sprintf("%s: unknown kind %q (want %q, %q, or %q)",
					where, op.Kind, KindConsume, KindUse, KindReset))
		}
		if op.Function == nil {
			add(analysis.DiagSeverityError, analysis.DiagParseError,
				fmt.Sprintf("%s: function binding is required", where))
		}
		if op.SubjectArg != nil && *op.SubjectArg < -1 {
			add(analysis.DiagSeverityError, analysis.DiagParseError,
				fmt.Sprintf("%s: subject_arg must be >= -1", where))
		}
		name := names[i]
		for j := 0; j < i; j++ {
			if names[j] == name {
				add(analysis.DiagSeverityError, analysis.DiagParseError,
					fmt.Sprintf("%s: event name %q collides with operations[%d]", where, name, j))
				break
			}
		}
	}

	sort.SliceStable(diags, func(i, j int) bool {
		if diags[i].Message != diags[j].Message {
			return diags[i].Message < diags[j].Message
		}
		return diags[i].Category < diags[j].Category
	})
	s.diags = diags
	return diags
}

// Diagnostics returns the spec's validation diagnostics.
func (s *Spec) Diagnostics() []analysis.Diagnostic { return s.Check() }

// eventNames resolves each operation's event name deterministically:
// the explicit Name when set, else the kind, suffixed -2, -3, ... on
// collision with an earlier resolved name.
func (s *Spec) eventNames() []string {
	out := make([]string, len(s.Operations))
	used := make(map[string]bool)
	for i := range s.Operations {
		op := &s.Operations[i]
		name := strings.TrimSpace(op.Name)
		if name == "" {
			// Defaulted names are suffixed on collision; explicit
			// names are kept verbatim so Check can report duplicates.
			base := op.Kind
			name = base
			for n := 2; used[name]; n++ {
				name = fmt.Sprintf("%s-%d", base, n)
			}
		}
		used[name] = true
		out[i] = name
	}
	return out
}
