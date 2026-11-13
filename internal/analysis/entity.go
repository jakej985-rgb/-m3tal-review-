package analysis

// EntityKind classifies the semantic entity an EntityRef points at.
// The kinds intentionally cover the identity-bearing node types of the
// internal/semantic program model without importing it: frontends map
// their stable IDs (semantic.Function.ID, semantic.Value.ID, package
// keys, type names, instruction/block IDs) onto these kinds.
type EntityKind string

const (
	// EntityPackage references a package (semantic.Package.Key()).
	EntityPackage EntityKind = "package"
	// EntityFunction references a callable unit (semantic.Function.ID).
	EntityFunction EntityKind = "function"
	// EntityValue references a program value (semantic.Value.ID).
	EntityValue EntityKind = "value"
	// EntityType references a declared type.
	EntityType EntityKind = "type"
	// EntityInstruction references a single instruction within a
	// function (semantic.Instruction, identified by function ID plus
	// instruction ID in ID).
	EntityInstruction EntityKind = "instruction"
	// EntityBlock references a basic block within a function.
	EntityBlock EntityKind = "block"
	// EntityFile references a whole source file.
	EntityFile EntityKind = "file"
)

// Valid reports whether the kind is a recognized entity kind.
func (k EntityKind) Valid() bool {
	switch k {
	case EntityPackage, EntityFunction, EntityValue, EntityType,
		EntityInstruction, EntityBlock, EntityFile:
		return true
	}
	return false
}

// EntityRef is a language-neutral reference to a semantic entity by its
// stable ID. ID is the canonical cross-run identity (e.g. a
// semantic.Value or semantic.Function ID); Name is a display hint only
// and is never used for identity or equality.
type EntityRef struct {
	Kind EntityKind `json:"kind"`
	// ID is the entity's stable identifier within the analyzed program.
	ID string `json:"id"`
	// Name is a human-readable display name (e.g. function short name).
	Name string `json:"name,omitempty"`
	// Span optionally locates the entity's declaration or definition.
	Span Span `json:"span,omitempty"`
}

// Valid reports whether the reference carries a usable identity.
func (e *EntityRef) Valid() bool {
	return e != nil && e.Kind.Valid() && e.ID != ""
}

// Identity returns the canonical serialization of the entity used for
// evidence hashing. Name and Span.Snippet are excluded: display text and
// cosmetic edits must not change finding identity.
func (e *EntityRef) Identity() string {
	if e == nil {
		return ""
	}
	return string(e.Kind) + "\x00" + e.ID + "\x00" + e.Span.Key()
}
