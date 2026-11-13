package protocol

import (
	"fmt"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the only protocol contract schema version this
// package understands. The version is carried in every contract
// document (`schema_version: protocol/1`) so future revisions can
// coexist.
const SchemaVersion = "protocol/1"

// Field types recognized by the contract format. The set is
// intentionally small and language-neutral; richer type systems are
// expressed through the description field or a future schema version.
var validTypes = map[string]bool{
	"string":  true,
	"integer": true,
	"number":  true,
	"boolean": true,
	"array":   true,
	"object":  true,
	"binary":  true,
	"null":    true,
	"any":     true,
}

// Auth schemes with dedicated comparator semantics.

var knownAuthSchemes = map[string]bool{
	"none": true, "bearer": true, "basic": true, "hmac": true,
	"api-key": true, "mtls": true, "custom": true,
}

// Contract is a versioned, declarative protocol contract. It is
// language-neutral: contracts describe wire elements (requests,
// responses, headers, auth, pairing, capabilities) and are compared
// against each other — never parsed from source code. A Contract is
// parsed from YAML (JSON is accepted as a YAML subset) and validated
// by Check.
type Contract struct {
	SchemaVersion string `yaml:"schema_version"`
	// ID is a stable contract identifier used in diagnostics,
	// finding metadata, and snapshot sets. Defaults to "protocol".
	ID string `yaml:"id"`
	// Name and Description are human-readable documentation.
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Version is the deployed protocol version label this snapshot
	// represents (e.g. "1.4.0"). It is metadata for matrix
	// bookkeeping; comparisons never interpret its ordering.
	Version string `yaml:"version"`

	// Requests declares client-to-server operations.
	Requests []MessageSpec `yaml:"requests"`
	// Responses declares server-to-client message shapes. Response
	// names need not match request names; they describe payloads.
	Responses []MessageSpec `yaml:"responses"`
	// Headers declares request headers (name, type, requiredness,
	// default). Response headers are modeled as response fields or a
	// future schema revision.
	Headers []HeaderSpec `yaml:"headers"`
	// Auth declares the authentication behavior. Nil means the
	// contract declares no authentication (equivalent to
	// scheme: none, required: false).
	Auth *AuthSpec `yaml:"auth"`
	// Pairing optionally declares the pairing/handshake exchange.
	// Pairing is mutual: field changes affect both directions.
	Pairing *PairingSpec `yaml:"pairing"`
	// Capabilities declares negotiable features.
	Capabilities []CapabilitySpec `yaml:"capabilities"`

	// Compat carries explicit compatibility declarations: which
	// deployed versions this contract claims compatibility with,
	// documented intentional breaking changes, and assertions
	// acknowledging semantic changes.
	Compat *CompatSpec `yaml:"compat"`

	// Source is the file the contract was loaded from, used for
	// finding spans. It is never parsed from YAML.
	Source string `yaml:"-"`

	prepared bool
	diags    []analysis.Diagnostic

	requestIndex  map[string]int
	responseIndex map[string]int
	headerIndex   map[string]int
	capIndex      map[string]int
}

// MessageSpec declares one request or response message.
type MessageSpec struct {
	Name        string      `yaml:"name"`
	Method      string      `yaml:"method"` // requests only; e.g. POST
	Path        string      `yaml:"path"`   // requests only; e.g. /v1/sessions
	Description string      `yaml:"description"`
	Fields      []FieldSpec `yaml:"fields"`
}

// FieldSpec declares one named field inside a message, header,
// pairing exchange, or capability payload.
type FieldSpec struct {
	Name        string        `yaml:"name"`
	Type        string        `yaml:"type"` // see validTypes; default "string"
	Required    bool          `yaml:"required"`
	Default     *DefaultValue `yaml:"default"`
	RenamedFrom string        `yaml:"renamed_from"`
	Description string        `yaml:"description"`
}

// DefaultValue wraps a field's declared default so "absent" is
// distinguishable from an explicit null default. It accepts any YAML
// scalar or collection.
type DefaultValue struct {
	Value interface{}
}

// UnmarshalYAML decodes any YAML node into the wrapped value.
func (d *DefaultValue) UnmarshalYAML(n *yaml.Node) error {
	return n.Decode(&d.Value)
}

// String renders the default for messages.
func (d *DefaultValue) String() string {
	if d == nil {
		return "<unset>"
	}
	return fmt.Sprintf("%v", d.Value)
}

// HeaderSpec declares one request header.
type HeaderSpec struct {
	Name        string        `yaml:"name"`
	Type        string        `yaml:"type"`
	Required    bool          `yaml:"required"`
	Default     *DefaultValue `yaml:"default"`
	Description string        `yaml:"description"`
}

// AuthSpec declares authentication behavior.
type AuthSpec struct {
	// Scheme names the scheme: none, bearer, basic, hmac, api-key,
	// mtls, custom, or an unrecognized opaque name.
	Scheme string `yaml:"scheme"`
	// Required reports whether credentials must be presented.
	// Defaults to true when the auth block is present: declaring an
	// auth scheme that is not required is almost always a mistake.
	// Set required: false explicitly for optional auth.
	Required *bool `yaml:"required"`
	// Header names the credential-carrying header. Defaults to
	// "Authorization".
	Header      string `yaml:"header"`
	Description string `yaml:"description"`
}

// RequiredValue returns the effective requiredness of the auth
// block (default true).
func (a *AuthSpec) RequiredValue() bool {
	if a == nil || a.Required == nil {
		return a != nil
	}
	return *a.Required
}

// HeaderValue returns the effective credential header (default
// "Authorization").
func (a *AuthSpec) HeaderValue() string {
	if a == nil || strings.TrimSpace(a.Header) == "" {
		return "Authorization"
	}
	return a.Header
}

// PairingSpec declares the pairing/handshake exchange.
type PairingSpec struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Fields      []FieldSpec `yaml:"fields"`
}

// CapabilitySpec declares one negotiable capability.
type CapabilitySpec struct {
	Name        string        `yaml:"name"`
	Type        string        `yaml:"type"` // see validTypes; default "string"
	Values      []string      `yaml:"values"`
	Required    bool          `yaml:"required"`
	Default     *DefaultValue `yaml:"default"`
	Description string        `yaml:"description"`
}

// CompatSpec carries explicit compatibility declarations that the
// comparator honors. Annotations live in the contract that introduces
// (or acknowledges) the change; the comparator consults the compat
// blocks of BOTH compared contracts.
type CompatSpec struct {
	// CompatibleWith lists deployed version labels this contract
	// claims wire compatibility with. It is a declaration for
	// humans and matrix consumers; the comparator still verifies
	// claims structurally rather than trusting them.
	CompatibleWith []string `yaml:"compatible_with"`
	// BreakingChanges documents intentional breaking changes. Each
	// entry suppresses exactly the finding for its element (and
	// optional change kind and direction) — never unrelated
	// findings.
	BreakingChanges []Annotation `yaml:"breaking_changes"`
	// Assertions acknowledges semantic changes (changed defaults,
	// auth-behavior changes, capability value changes) that cannot
	// be proven wire-compatible or wire-incompatible from structure
	// alone. Matching works exactly like BreakingChanges.
	Assertions []Annotation `yaml:"assertions"`
}

// Annotation targets one changed contract element. Element is the
// canonical element path (see docs/protocol-contracts.md), e.g.
// "request.CreateSession.field.ttl". Change optionally restricts the
// annotation to one change kind (e.g. "type-changed"); Direction
// optionally restricts it to one compatibility direction; Reason is
// required documentation.
type Annotation struct {
	Element   string `yaml:"element"`
	Change    string `yaml:"change"`
	Direction string `yaml:"direction"`
	Reason    string `yaml:"reason"`
}

// ---------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------

// ParseContract parses a contract document. YAML is the canonical
// format; JSON documents parse as a YAML subset. A non-nil error is
// returned only for unreadable input or a wrong/missing schema
// version; semantic problems (duplicate names, unknown types, bad
// annotations) are reported through Check.
func ParseContract(data []byte) (*Contract, error) {
	var c Contract
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("protocol contract: %w", err)
	}
	if c.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("protocol contract: unsupported schema_version %q (want %q)", c.SchemaVersion, SchemaVersion)
	}
	if c.ID == "" {
		c.ID = "protocol"
	}
	return &c, nil
}

// Check validates the contract and returns all problems found,
// sorted deterministically. It also normalizes defaults (empty field
// types become "string"). Check is idempotent.
func (c *Contract) Check() []analysis.Diagnostic {
	if c.prepared {
		return c.diags
	}
	c.prepared = true
	var diags []analysis.Diagnostic
	add := func(sev analysis.DiagnosticSeverity, cat analysis.DiagnosticCategory, msg string) {
		diags = append(diags, analysis.Diagnostic{Severity: sev, Category: cat, Message: msg})
	}

	c.requestIndex = make(map[string]int)
	for i := range c.Requests {
		m := &c.Requests[i]
		where := fmt.Sprintf("requests[%d]", i)
		checkMessage(add, where, m, c.requestIndex)
	}
	c.responseIndex = make(map[string]int)
	for i := range c.Responses {
		m := &c.Responses[i]
		where := fmt.Sprintf("responses[%d]", i)
		checkMessage(add, where, m, c.responseIndex)
	}
	c.headerIndex = make(map[string]int)
	for i := range c.Headers {
		h := &c.Headers[i]
		where := fmt.Sprintf("headers[%d]", i)
		if !validHeaderName(h.Name) {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("%s: invalid header name %q", where, h.Name))
			continue
		}
		if _, dup := c.headerIndex[h.Name]; dup {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate header %q", h.Name))
			continue
		}
		c.headerIndex[h.Name] = i
		normalizeType(&h.Type)
		if !validTypes[h.Type] {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("%s: unknown type %q for header %q", where, h.Type, h.Name))
		}
	}
	if c.Auth != nil {
		if strings.TrimSpace(c.Auth.Scheme) == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, "auth: scheme is required")
		} else if !knownAuthSchemes[c.Auth.Scheme] {
			add(analysis.DiagSeverityWarning, analysis.DiagUnsupported,
				fmt.Sprintf("auth: unrecognized scheme %q; changes are still detected but scheme semantics are opaque", c.Auth.Scheme))
		}
	}
	if c.Pairing != nil {
		checkFields(add, "pairing.fields", c.Pairing.Fields)
	}
	c.capIndex = make(map[string]int)
	for i := range c.Capabilities {
		cap := &c.Capabilities[i]
		where := fmt.Sprintf("capabilities[%d]", i)
		if strings.TrimSpace(cap.Name) == "" {
			add(analysis.DiagSeverityError, analysis.DiagParseError, where+": name is required")
			continue
		}
		if _, dup := c.capIndex[cap.Name]; dup {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate capability %q", cap.Name))
			continue
		}
		c.capIndex[cap.Name] = i
		normalizeType(&cap.Type)
		if !validTypes[cap.Type] {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("%s: unknown type %q for capability %q", where, cap.Type, cap.Name))
		}
		seenVals := make(map[string]bool)
		for _, v := range cap.Values {
			if strings.TrimSpace(v) == "" {
				add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("%s: empty value in capability %q", where, cap.Name))
				continue
			}
			if seenVals[v] {
				add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("%s: duplicate value %q in capability %q", where, v, cap.Name))
				continue
			}
			seenVals[v] = true
		}
	}
	if c.Compat != nil {
		for i, a := range c.Compat.BreakingChanges {
			checkAnnotation(add, fmt.Sprintf("compat.breaking_changes[%d]", i), a)
		}
		for i, a := range c.Compat.Assertions {
			checkAnnotation(add, fmt.Sprintf("compat.assertions[%d]", i), a)
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
// diagnostics. Comparisons over invalid contracts still run but
// their findings are downgraded to StatusPotential.
func (c *Contract) HasErrors() bool {
	for _, d := range c.Check() {
		if d.Severity == analysis.DiagSeverityError {
			return true
		}
	}
	return false
}

func checkMessage(add func(analysis.DiagnosticSeverity, analysis.DiagnosticCategory, string), where string, m *MessageSpec, index map[string]int) {
	if strings.TrimSpace(m.Name) == "" {
		add(analysis.DiagSeverityError, analysis.DiagParseError, where+": name is required")
		return
	}
	if _, dup := index[m.Name]; dup {
		add(analysis.DiagSeverityError, analysis.DiagParseError, fmt.Sprintf("duplicate message name %q", m.Name))
		return
	}
	index[m.Name] = len(index)
	if m.Method != "" && strings.ToUpper(m.Method) != m.Method {
		add(analysis.DiagSeverityWarning, analysis.DiagParseError,
			fmt.Sprintf("%s %q: method %q is not uppercase; comparisons are case-sensitive", where, m.Name, m.Method))
	}
	if m.Path != "" && !strings.HasPrefix(m.Path, "/") {
		add(analysis.DiagSeverityWarning, analysis.DiagParseError,
			fmt.Sprintf("%s %q: path %q does not start with /", where, m.Name, m.Path))
	}
	checkFields(add, where+".fields", m.Fields)
}

// checkFields validates a field list: unique valid names, known
// types, and unambiguous renamed_from targets within the same list.
func checkFields(add func(analysis.DiagnosticSeverity, analysis.DiagnosticCategory, string), where string, fields []FieldSpec) {
	seen := make(map[string]int)
	renamedFrom := make(map[string]int)
	for i := range fields {
		f := &fields[i]
		fw := fmt.Sprintf("%s[%d]", where, i)
		if !validIdent(f.Name) {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fw+": invalid field name "+quote(f.Name))
			continue
		}
		if prev, dup := seen[f.Name]; dup {
			add(analysis.DiagSeverityError, analysis.DiagParseError,
				fmt.Sprintf("%s: duplicate field %q (also %s[%d])", fw, f.Name, where, prev))
			continue
		}
		seen[f.Name] = i
		normalizeType(&f.Type)
		if !validTypes[f.Type] {
			add(analysis.DiagSeverityError, analysis.DiagParseError, fw+": unknown type "+quote(f.Type)+" for field "+quote(f.Name))
		}
		if f.RenamedFrom != "" {
			if f.RenamedFrom == f.Name {
				add(analysis.DiagSeverityError, analysis.DiagParseError, fw+": renamed_from must differ from name")
				continue
			}
			if prev, dup := renamedFrom[f.RenamedFrom]; dup {
				add(analysis.DiagSeverityError, analysis.DiagParseError,
					fmt.Sprintf("%s: renamed_from %q already claimed by %s[%d]", fw, f.RenamedFrom, where, prev))
				continue
			}
			renamedFrom[f.RenamedFrom] = i
		}
	}
	// A renamed_from target that is itself a field in the same list
	// is ambiguous: the old name still exists, so the rename claim
	// cannot be honored.
	for _, f := range fields {
		if f.RenamedFrom == "" {
			continue
		}
		if _, stillThere := seen[f.RenamedFrom]; stillThere {
			add(analysis.DiagSeverityError, analysis.DiagParseError,
				fmt.Sprintf("%s: field %q declares renamed_from %q but %q is still declared in the same list",
					where, f.Name, f.RenamedFrom, f.RenamedFrom))
		}
	}
}

func checkAnnotation(add func(analysis.DiagnosticSeverity, analysis.DiagnosticCategory, string), where string, a Annotation) {
	if strings.TrimSpace(a.Element) == "" {
		add(analysis.DiagSeverityError, analysis.DiagParseError, where+": element is required")
	}
	if strings.TrimSpace(a.Reason) == "" {
		add(analysis.DiagSeverityError, analysis.DiagParseError, where+": reason is required")
	}
	if a.Direction != "" {
		if _, ok := ParseDirection(a.Direction); !ok {
			add(analysis.DiagSeverityError, analysis.DiagParseError,
				fmt.Sprintf("%s: invalid direction %q (want \"both\", \"old-client/new-server\", or \"new-client/old-server\")", where, a.Direction))
		}
	}
}

func normalizeType(t *string) {
	if strings.TrimSpace(*t) == "" {
		*t = "string"
	}
}

func quote(s string) string { return fmt.Sprintf("%q", s) }

func validIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// validHeaderName accepts HTTP field-name tokens: letters, digits,
// and hyphens (e.g. "X-Request-Id", "Authorization").
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}
