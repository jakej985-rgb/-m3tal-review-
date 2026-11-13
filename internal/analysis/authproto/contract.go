package authproto

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only authproto contract schema version this
// package understands. The version is carried in every contract
// document (`schema_version: authproto/1`) so future revisions can
// coexist.
const SchemaVersion = "authproto/1"

// Contract is a versioned, declarative model of an authentication or
// key-establishment protocol transcript. It is language-neutral: the
// model describes parties, ordered messages, and the cryptographic
// roles of transcript fields (nonces, challenges, proofs, session
// identifiers, keys) plus the *declared* properties of those fields
// (freshness, single-use enforcement, transcript coverage, verifier
// type, derivation inputs).
//
// A Contract is parsed from YAML (JSON is accepted as a YAML subset)
// and validated by Check. It is a *model*: nothing in it asserts that
// the implementation conforms. Every finding produced from a contract
// is therefore StatusPotential at best — the analyzer checks the
// declared model for exploitable shapes, it never proves properties of
// deployed code. Fields may optionally bind to program functions
// (Source) so a semantic frontend can verify generation claims such as
// "this nonce comes from crypto/rand"; unbound claims remain declared
// assumptions.
//
// Contracts must not be copied after use: parsed state is cached in
// unexported fields.
type Contract struct {
	SchemaVersion string `yaml:"schema_version"`
	// ID is a stable contract identifier used in diagnostics, finding
	// metadata, and result bookkeeping. Defaults to "authproto".
	ID string `yaml:"id"`
	// Name and Description are human-readable documentation.
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	// Parties optionally names the protocol participants (e.g.
	// "client", "server"). When declared, every transcript step's
	// from/to must name a member. When empty, parties are unrestricted
	// opaque labels.
	Parties []string `yaml:"parties"`

	// Transcript is the ordered message exchange. Steps execute in
	// declaration order; each step's fields are unique across the
	// whole transcript so proof `covers` references resolve
	// unambiguously.
	Transcript []StepSpec `yaml:"transcript"`

	// Source is the file the contract was loaded from, used for
	// finding spans. It is never parsed from YAML.
	Source string `yaml:"-"`

	prepared bool
	diags    []analysis.Diagnostic

	fieldIndex map[string]*FieldSpec // global field name → field
	stepIndex  map[string]int        // step name → transcript index
	partySet   map[string]bool
}

// StepSpec declares one message in the transcript.
type StepSpec struct {
	// Name uniquely identifies the step within the transcript.
	Name string `yaml:"name"`
	// From and To name the sending and receiving parties.
	From string `yaml:"from"`
	To   string `yaml:"to"`
	// Description documents the step.
	Description string `yaml:"description"`
	// Fields are the message's elements. Field names must be unique
	// across the entire transcript.
	Fields []FieldSpec `yaml:"fields"`
}

// Field kinds recognized by the contract format. The set is
// deliberately small; richer constructions should use "other" and are
// treated as unmodeled by the checks.
var validKinds = map[string]bool{
	"nonce":           true,
	"challenge":       true,
	"proof":           true,
	"session":         true,
	"key":             true,
	"password":        true,
	"transcript-hash": true,
	"signature":       true,
	"metadata":        true,
	"other":           true,
}

// Verifier types recognized on proof fields. The type names the
// *verification construction* — what the verifier checks and what an
// attacker holding the transcript can do with it.
var validVerifiers = map[string]bool{
	// server-secret: the proof is checked against a long-term secret
	// held only by the verifier (e.g. HMAC, MAC-then-compare). An
	// eavesdropper cannot test candidate secrets offline.
	"server-secret": true,
	// public-key: the proof is a signature or asymmetric
	// verification under a public key. Candidates cannot be tested
	// offline, but the transcript is malleable to active attackers
	// unless the proof is bound (see covers).
	"public-key": true,
	// password: the proof is derived from a low-entropy password
	// (e.g. H(password || transcript)). An eavesdropper holding one
	// transcript can verify password candidates offline.
	"password": true,
	// pake: a password-authenticated key exchange (e.g. SPAKE2,
	// OPAQUE-style). Offline guessing is assumed prevented by the
	// PAKE construction; the primitive itself is not verified.
	"pake": true,
	// symmetric-key: the proof is checked under a pre-shared
	// symmetric key.
	"symmetric-key": true,
	// unknown: explicitly declared as unmodeled. Produces an
	// unverified finding rather than silence.
	"unknown": true,
}

// FieldSpec declares one transcript element and its modeled
// cryptographic role.
type FieldSpec struct {
	// Name uniquely identifies the field across the transcript.
	// Required.
	Name string `yaml:"name"`
	// Kind classifies the element's role: nonce, challenge, proof,
	// session, key, password, transcript-hash, signature, metadata,
	// or other. Default "other".
	Kind string `yaml:"kind"`
	// Fresh reports that the value is generated fresh for each
	// protocol run (a declared claim about generation, verified
	// against source only when Source is bound). Nonce and challenge
	// fields should set fresh: true.
	Fresh bool `yaml:"fresh"`
	// SingleUse reports that the verifier rejects reuse of this value
	// (a declared server-side property, e.g. a used-nonce store).
	// Only meaningful on server-issued nonce/challenge/session
	// fields.
	SingleUse bool `yaml:"single_use"`
	// Covers lists the names of transcript fields this element
	// commits to — the transcript-binding claim. On proof fields it
	// records which earlier elements the proof authenticates; an
	// empty covers means the proof binds to nothing.
	Covers []string `yaml:"covers"`
	// Verifier describes how a proof field is verified. Only
	// meaningful on kind: proof fields.
	Verifier *VerifierSpec `yaml:"verifier"`
	// DerivedFrom lists the names of fields this element's value is
	// derived from (key-derivation inputs). Used to detect
	// password-derived session keys.
	DerivedFrom []string `yaml:"derived_from"`
	// KDF optionally names the key-derivation/function used. Free
	// text; "pake" suppresses the password-derivation finding because
	// PAKE constructions are assumed offline-guessing resistant.
	KDF string `yaml:"kdf"`
	// Secret marks the element as low-entropy secret input (e.g. a
	// password). Informational; verifier.type: password is the
	// operative trigger for offline-guessing checks.
	Secret bool `yaml:"secret"`
	// Source optionally binds the element's generation (or
	// verification) to a program function so source analysis can
	// check claims such as CSPRNG use. Unbound claims remain
	// declared assumptions.
	Source *FunctionSpec `yaml:"source"`
	// Description documents the field.
	Description string `yaml:"description"`
}

// VerifierSpec declares how a proof is verified.
type VerifierSpec struct {
	// Type names the verification construction: server-secret,
	// public-key, password, pake, symmetric-key, or unknown.
	// Required on proof fields.
	Type string `yaml:"type"`
	// Description documents the construction.
	Description string `yaml:"description"`
}

// FunctionSpec structurally binds a contract element to a program
// function. Matching is structural: ID is exact, Name is filtered by
// Package path and Receiver type when given. Zero matches is
// "unbound"; multiple matches is "ambiguous" — both are reported,
// never guessed.
type FunctionSpec struct {
	// ID is an exact semantic function ID.
	ID string `yaml:"id"`
	// Name is the function's short name.
	Name string `yaml:"name"`
	// Package optionally restricts matches to a package import path.
	Package string `yaml:"package"`
	// Receiver optionally restricts matches to methods whose receiver
	// base type is "[pkg/path.]Name" (pointers are unwrapped).
	Receiver string `yaml:"receiver"`
}

// ---------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------

// ParseContract parses a contract document. YAML is the canonical
// format; JSON documents parse as a YAML subset. A non-nil error is
// returned only for unreadable input or a wrong/missing schema
// version; semantic problems are reported through Check.
func ParseContract(data []byte) (*Contract, error) {
	var c Contract
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("authproto contract: %w", err)
	}
	if c.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("authproto contract: unsupported schema_version %q (want %q)", c.SchemaVersion, SchemaVersion)
	}
	if c.ID == "" {
		c.ID = "authproto"
	}
	return &c, nil
}

// LoadContract reads and parses a contract file, recording the path in
// Contract.Source for finding spans.
func LoadContract(path string) (*Contract, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := ParseContract(data)
	if err != nil {
		return nil, err
	}
	c.Source = path
	return c, nil
}

// Check validates the contract and returns all problems found, sorted
// deterministically. It also normalizes field kinds and builds the
// global field index used by the checks. Check is idempotent.
func (c *Contract) Check() []analysis.Diagnostic {
	if c.prepared {
		return c.diags
	}
	c.prepared = true
	var diags []analysis.Diagnostic
	add := func(sev analysis.DiagnosticSeverity, cat analysis.DiagnosticCategory, msg string) {
		diags = append(diags, analysis.Diagnostic{Severity: sev, Category: cat, Message: msg})
	}

	c.partySet = make(map[string]bool)
	for _, p := range c.Parties {
		if strings.TrimSpace(p) == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, "parties: empty party name")
			continue
		}
		if c.partySet[p] {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate party %q", p))
			continue
		}
		c.partySet[p] = true
	}

	c.stepIndex = make(map[string]int)
	c.fieldIndex = make(map[string]*FieldSpec)
	if len(c.Transcript) == 0 {
		add(analysis.DiagSeverityWarning, analysis.DiagUnsupported,
			"contract declares no transcript; no protocol properties can be evaluated")
	}
	for i := range c.Transcript {
		s := &c.Transcript[i]
		where := fmt.Sprintf("transcript[%d]", i)
		if strings.TrimSpace(s.Name) == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, where+": name is required")
			continue
		}
		if _, dup := c.stepIndex[s.Name]; dup {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate transcript step %q", s.Name))
			continue
		}
		c.stepIndex[s.Name] = i
		if strings.TrimSpace(s.From) == "" || strings.TrimSpace(s.To) == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, where+": from and to are required")
			continue
		}
		if len(c.partySet) > 0 {
			if !c.partySet[s.From] {
				add(analysis.DiagSeverityError, analysis.DiagParseError,
					fmt.Sprintf("%s: unknown from-party %q", where, s.From))
			}
			if !c.partySet[s.To] {
				add(analysis.DiagSeverityError, analysis.DiagParseError,
					fmt.Sprintf("%s: unknown to-party %q", where, s.To))
			}
		}
		for j := range s.Fields {
			f := &s.Fields[j]
			fw := fmt.Sprintf("%s.fields[%d]", where, j)
			if strings.TrimSpace(f.Name) == "" {
				add(analysis.DiagSeverityError, analysis.DiagParseError, fw+": name is required")
				continue
			}
			if _, dup := c.fieldIndex[f.Name]; dup {
				add(analysis.DiagSeverityError, analysis.DiagParseError,
					fmt.Sprintf("%s: duplicate field name %q across transcript", fw, f.Name))
				continue
			}
			// Register the name before kind validation so duplicates
			// are caught even when the first occurrence is invalid.
			c.fieldIndex[f.Name] = f
			normalizeKind(&f.Kind)
			if !validKinds[f.Kind] {
				add(analysis.DiagSeverityError, analysis.DiagParseError,
					fmt.Sprintf("%s: unknown kind %q for field %q", fw, f.Kind, f.Name))
				continue
			}
			if f.Kind == "proof" {
				if f.Verifier == nil || strings.TrimSpace(f.Verifier.Type) == "" {
					add(analysis.DiagSeverityWarning, analysis.DiagUnsupported,
						fmt.Sprintf("%s: proof field %q declares no verifier.type; verification construction is unmodeled", fw, f.Name))
				} else if !validVerifiers[f.Verifier.Type] {
					add(analysis.DiagSeverityWarning, analysis.DiagUnsupported,
						fmt.Sprintf("%s: proof field %q has unrecognized verifier.type %q; construction is unmodeled", fw, f.Name, f.Verifier.Type))
				}
			} else if f.Verifier != nil {
				add(analysis.DiagSeverityWarning, analysis.DiagUnsupported,
					fmt.Sprintf("%s: verifier is only meaningful on kind: proof fields; ignored on %q", fw, f.Name))
			}
		}
	}

	// Second pass: covers/derived_from references must resolve to
	// declared fields. Runs after all fields are indexed.
	for i := range c.Transcript {
		for j := range c.Transcript[i].Fields {
			f := &c.Transcript[i].Fields[j]
			fw := fmt.Sprintf("transcript[%d].fields[%d]", i, j)
			for _, ref := range f.Covers {
				if _, ok := c.fieldIndex[ref]; !ok {
					add(analysis.DiagSeverityError, analysis.DiagParseError,
						fmt.Sprintf("%s: covers references undeclared field %q", fw, ref))
				}
			}
			for _, ref := range f.DerivedFrom {
				if _, ok := c.fieldIndex[ref]; !ok {
					add(analysis.DiagSeverityError, analysis.DiagParseError,
						fmt.Sprintf("%s: derived_from references undeclared field %q", fw, ref))
				}
			}
		}
	}

	sort.SliceStable(diags, func(i, j int) bool {
		if diags[i].Message != diags[j].Message {
			return diags[i].Message < diags[j].Message
		}
		return diags[i].Category < diags[j].Category
	})
	c.diags = diags
	return diags
}

// Diagnostics returns the contract's validation diagnostics.
func (c *Contract) Diagnostics() []analysis.Diagnostic { return c.Check() }

// HasErrors reports whether Check produced error-severity
// diagnostics. Analysis over invalid contracts still runs but its
// findings are downgraded: model findings keep StatusPotential and
// source-derived findings lose their evidence claim.
func (c *Contract) HasErrors() bool {
	for _, d := range c.Check() {
		if d.Severity == analysis.DiagSeverityError {
			return true
		}
	}
	return false
}

// fieldStep returns the transcript index containing the named field.
func (c *Contract) fieldStep(name string) int {
	f := c.fieldIndex[name]
	if f == nil {
		return -1
	}
	for i := range c.Transcript {
		for j := range c.Transcript[i].Fields {
			if &c.Transcript[i].Fields[j] == f {
				return i
			}
		}
	}
	return -1
}

func normalizeKind(k *string) {
	if strings.TrimSpace(*k) == "" {
		*k = "other"
	}
}
