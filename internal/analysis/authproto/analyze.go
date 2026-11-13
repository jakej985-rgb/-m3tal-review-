package authproto

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

// This file implements the modeled protocol-property checks. Every
// check evaluates the *declared* transcript model: it asks whether the
// modeled construction admits a named attacker capability under the
// declared assumptions. Nothing here inspects implementation code —
// that is the job of source.go (Evaluate) for source-bound fields —
// and no check ever claims a cryptographic proof. A clean model means
// "no modeled weakness found", never "the protocol is secure".

// Options controls analysis budgets. Zero values select defaults.
type Options struct {
	// MaxSourceDepth bounds transitive callee traversal when checking
	// source-bound nonce generators. Default 3; negative means
	// unlimited.
	MaxSourceDepth int
	// MaxSourceFunctions bounds the number of functions visited per
	// source-bound field. Default 64; negative means unlimited.
	MaxSourceFunctions int
}

const (
	defaultMaxSourceDepth     = 3
	defaultMaxSourceFunctions = 64
)

func (o Options) withDefaults() Options {
	if o.MaxSourceDepth == 0 {
		o.MaxSourceDepth = defaultMaxSourceDepth
	}
	if o.MaxSourceFunctions == 0 {
		o.MaxSourceFunctions = defaultMaxSourceFunctions
	}
	return o
}

// Result is the outcome of Analyze/Evaluate.
type Result struct {
	// Findings are modeled protocol-property violations in the shared
	// analysis contract, deterministically ordered. Model findings are
	// StatusPotential (the model may diverge from the implementation);
	// unmodeled constructions are StatusUnverified.
	Findings []analysis.Finding
	// Diagnostics records contract validation problems, unbound
	// source references, and unsupported constructs — never silent.
	Diagnostics []analysis.Diagnostic
	// Assumptions lists analysis caveats that qualify the findings:
	// declared-but-unverified properties (freshness, single-use,
	// verifier strength, PAKE soundness).
	Assumptions []string
	// Budgets records the limits in effect and whether each was hit.
	Budgets []analysis.Budget
	// Truncated is true when any budget was exhausted.
	Truncated bool
}

// Analyze runs the modeled protocol-property checks over the given
// contracts. It is purely model-based: no program is consulted, so
// source-bound fields contribute declared assumptions only. Pass the
// result of Evaluate for source-verified generation claims.
func Analyze(_ context.Context, contracts []*Contract, _ Options) (*Result, error) {
	res := &Result{}
	for _, c := range contracts {
		if c == nil {
			continue
		}
		res.Diagnostics = append(res.Diagnostics, c.Check()...)
		res.Diagnostics = append(res.Diagnostics, checkContract(c, res)...)
	}
	res.finish()
	return res, nil
}

// finish orders findings, deduplicates/sorts diagnostics and
// assumptions, and assigns finding IDs.
func (r *Result) finish() {
	r.Findings = analysis.AssignFindingIDs(r.Findings)
	analysis.SortFindings(r.Findings)
	analysis.SortDiagnostics(r.Diagnostics)
	sort.Strings(r.Assumptions)
	seen := make(map[string]bool)
	var out []string
	for _, a := range r.Assumptions {
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	r.Assumptions = out
}

// ---------------------------------------------------------------------
// Modeled checks
// ---------------------------------------------------------------------

// bindingKinds are the field kinds a proof must cover to be bound to
// the protocol session: fresh challenges, nonces, and session
// identifiers.
var bindingKinds = map[string]bool{
	"nonce": true, "challenge": true, "session": true,
}

// checkContract runs every modeled check over one contract and
// appends findings, diagnostics, and assumptions to res.
func checkContract(c *Contract, res *Result) []analysis.Diagnostic {
	_ = c.Check() // ensure indexes are built
	var diags []analysis.Diagnostic
	var assumptions []string

	coveredSet := func(f *FieldSpec) map[string]bool {
		set := make(map[string]bool, len(f.Covers))
		for _, name := range f.Covers {
			set[name] = true
		}
		return set
	}

	// Collect proof fields and binding-relevant fields in transcript
	// order.
	var proofs []*FieldSpec
	var bindingFields []*FieldSpec
	for i := range c.Transcript {
		for j := range c.Transcript[i].Fields {
			f := &c.Transcript[i].Fields[j]
			switch {
			case f.Kind == "proof":
				proofs = append(proofs, f)
			case bindingKinds[f.Kind]:
				bindingFields = append(bindingFields, f)
			}
		}
	}

	if len(proofs) == 0 {
		if len(c.Transcript) > 0 {
			res.Findings = append(res.Findings, c.finding(c, "authproto.unmodeled",
				"Authentication transcript declares no proof construction",
				"the modeled transcript contains no proof field, so replay resistance, transcript binding, and offline-guessing exposure could not be evaluated",
				analysis.StatusUnverified, "low",
				[]string{"the model contains no proof step; authentication properties are unchecked, not verified"},
				nil, nil, nil))
			assumptions = append(assumptions,
				fmt.Sprintf("contract %q: no proof construction modeled; authentication properties unverified", c.ID))
		}
	}
	// Proof-dependent checks (1–3) run only when proofs exist; the
	// derivation and nonce checks below apply regardless.

	for _, p := range proofs {
		stepIdx := c.fieldStep(p.Name)
		step := c.Transcript[stepIdx]
		// The verifier is the recipient of the proof message.
		verifierParty := step.To
		cov := coveredSet(p)

		// --- Check 1: verification construction modeling ---
		vtype := ""
		if p.Verifier != nil {
			vtype = p.Verifier.Type
		}
		switch {
		case vtype == "" || vtype == "unknown" || !validVerifiers[vtype]:
			res.Findings = append(res.Findings, c.finding(c, "authproto.unmodeled",
				fmt.Sprintf("Proof %q uses an unmodeled verification construction", p.Name),
				fmt.Sprintf("proof field %q has verifier.type %q, which the analyzer does not model; replay, binding, and offline-guessing properties were not evaluated for it", p.Name, displayType(vtype)),
				analysis.StatusUnverified, "low",
				[]string{
					"the verification construction is outside the modeled set; nothing was proven or disproven about it",
				},
				traceSteps(c, stepIdx),
				map[string]string{"field": p.Name, "verifier_type": vtype},
				nil))
		case vtype == "password":
			res.Findings = append(res.Findings, c.finding(c, "authproto.offline-guessing",
				fmt.Sprintf("Proof %q permits offline password-candidate verification", p.Name),
				fmt.Sprintf("proof field %q is verified with verifier.type %q: anyone holding one transcript can test password candidates offline without further interaction", p.Name, vtype),
				analysis.StatusPotential, "high",
				[]string{
					"password entropy and KDF cost are unverified; the finding shows the transcript *enables* offline verification, not that passwords are guessable",
					"implementation conformance to this model is unverified",
				},
				traceSteps(c, stepIdx),
				map[string]string{
					"field":                 p.Name,
					"verifier_type":         vtype,
					"attacker_capabilities": "passive transcript observer; offline dictionary/brute-force computation",
					"not_proven":            "password strength, KDF parameters, rate limiting, and implementation conformance",
				},
				[]string{"verification relies on a low-entropy password secret; consider a PAKE or server-held-secret construction"}))
		default:
			assumptions = append(assumptions, fmt.Sprintf(
				"contract %q: proof %q relies on verifier.type %q; primitive and key strength are assumed, not verified",
				c.ID, p.Name, vtype))
			if vtype == "pake" {
				assumptions = append(assumptions, fmt.Sprintf(
					"contract %q: proof %q assumes PAKE soundness (offline-guessing resistance); the PAKE construction itself is unverified",
					c.ID, p.Name))
			}
		}

		// --- Check 2: transcript/session binding ---
		var uncovered []string
		for _, bf := range bindingFields {
			if !cov[bf.Name] {
				uncovered = append(uncovered, bf.Name)
			}
		}
		sort.Strings(uncovered)
		if len(uncovered) > 0 {
			res.Findings = append(res.Findings, c.finding(c, "authproto.transcript-binding",
				fmt.Sprintf("Proof %q is not bound to the full session transcript", p.Name),
				fmt.Sprintf("proof field %q does not commit to session-binding field(s) %s; a proof minted for one session context may verify in another", p.Name, strings.Join(uncovered, ", ")),
				analysis.StatusPotential, "medium",
				[]string{
					"binding is evaluated on the declared covers list; the implementation's actual MAC/signature input is unverified",
				},
				traceSteps(c, stepIdx),
				map[string]string{
					"field":                 p.Name,
					"uncovered_fields":      strings.Join(uncovered, ","),
					"attacker_capabilities": "active man-in-the-middle or session-resumption attacker replaying proofs across contexts",
					"not_proven":            "that the implementation signs/MACs exactly the declared covers set",
				},
				[]string{"extend the proof input to cover every nonce, challenge, and session identifier in the transcript"}))
		}

		// --- Check 3: replay resistance ---
		// A proof is replay-resistant in the model only if it covers at
		// least one value that is (a) issued by the verifying party,
		// (b) declared fresh per run, and (c) declared single-use.
		var bestCovered *FieldSpec
		var coveredFresh, coveredSingle bool
		for _, name := range p.Covers {
			f := c.fieldIndex[name]
			if f == nil {
				continue
			}
			fstep := c.Transcript[c.fieldStep(name)]
			if fstep.From != verifierParty {
				continue
			}
			if !f.Fresh {
				continue
			}
			coveredFresh = true
			if f.SingleUse {
				coveredSingle = true
				bestCovered = f
				break
			}
			if bestCovered == nil {
				bestCovered = f
			}
		}
		if !coveredFresh {
			res.Findings = append(res.Findings, c.finding(c, "authproto.replay",
				fmt.Sprintf("Proof %q covers no fresh challenge from %s", p.Name, verifierParty),
				fmt.Sprintf("proof field %q commits to no fresh value issued by verifier %q; a recorded proof can be replayed in a later or parallel session under the declared model", p.Name, verifierParty),
				analysis.StatusPotential, "medium",
				[]string{
					"replay resistance is evaluated on declared covers/fresh/single_use properties; server-side nonce storage and timing are unverified",
				},
				traceSteps(c, stepIdx),
				map[string]string{
					"field":                 p.Name,
					"verifier_party":        verifierParty,
					"attacker_capabilities": "network attacker recording and replaying protocol messages",
					"not_proven":            "that the server enforces freshness or single-use at runtime",
				},
				[]string{"issue a fresh per-session challenge from the verifier and require the proof to cover it"}))
		} else if !coveredSingle {
			res.Findings = append(res.Findings, c.finding(c, "authproto.replay",
				fmt.Sprintf("Proof %q covers a fresh %s challenge but reuse is not declared prevented", p.Name, bestCovered.Kind),
				fmt.Sprintf("proof field %q covers %q (fresh, issued by %s) but no covered value is declared single_use; the model permits challenge reuse across sessions", p.Name, bestCovered.Name, verifierParty),
				analysis.StatusPotential, "medium",
				[]string{
					"single_use is a declared server property; the existence of a used-nonce store is unverified",
				},
				traceSteps(c, stepIdx),
				map[string]string{
					"field":                 p.Name,
					"covered_challenge":     bestCovered.Name,
					"attacker_capabilities": "network attacker recording and replaying protocol messages",
					"not_proven":            "that the server rejects reused challenges",
				},
				[]string{"declare single_use: true on the challenge/nonce and verify the server enforces it"}))
		}

	}

	// --- Check 4: password-derived key material (any field) ---
	for i := range c.Transcript {
		for j := range c.Transcript[i].Fields {
			f := &c.Transcript[i].Fields[j]
			for _, name := range f.DerivedFrom {
				src := c.fieldIndex[name]
				if src == nil || src.Kind != "password" {
					continue
				}
				if strings.Contains(strings.ToLower(f.KDF), "pake") {
					assumptions = append(assumptions, fmt.Sprintf(
						"contract %q: field %q derives from password material via a declared PAKE; offline-guessing resistance is assumed, not verified",
						c.ID, f.Name))
					continue
				}
				res.Findings = append(res.Findings, c.finding(c, "authproto.offline-guessing",
					fmt.Sprintf("Field %q derives from password material without a declared PAKE", f.Name),
					fmt.Sprintf("field %q lists password field %q in derived_from; unless the KDF is a PAKE, transcript material enables offline candidate verification", f.Name, name),
					analysis.StatusPotential, "high",
					[]string{
						"KDF parameters and password entropy are unverified; the finding shows offline verification is *enabled*, not that it succeeds",
						"implementation conformance to this model is unverified",
					},
					traceSteps(c, i),
					map[string]string{
						"field":                 f.Name,
						"password_source":       name,
						"attacker_capabilities": "passive transcript observer; offline dictionary/brute-force computation",
						"not_proven":            "KDF strength, salt usage, password entropy, implementation conformance",
					},
					[]string{"use a PAKE or a server-held secret; if password auth is required, use a memory-hard salted KDF and rate limiting"}))
			}
		}
	}

	// --- Check 5: nonce/challenge freshness and uniqueness ---
	for i := range c.Transcript {
		for j := range c.Transcript[i].Fields {
			f := &c.Transcript[i].Fields[j]
			if f.Kind != "nonce" && f.Kind != "challenge" {
				continue
			}
			if !f.Fresh {
				res.Findings = append(res.Findings, c.finding(c, "authproto.nonce-uniqueness",
					fmt.Sprintf("%s %q is not generated fresh per run", cap(f.Kind), f.Name),
					fmt.Sprintf("%s field %q declares fresh: false (or omits it); the model assumes the value repeats across sessions, defeating replay and binding checks that rely on it", cap(f.Kind), f.Name),
					analysis.StatusPotential, "medium",
					[]string{
						"freshness is a declared property; generation is unverified unless a source binding exists",
					},
					traceSteps(c, i),
					map[string]string{
						"field":                 f.Name,
						"attacker_capabilities": "network attacker replaying recorded values across sessions",
						"not_proven":            "that the implementation ever generates a fresh value",
					},
					[]string{"generate the value fresh per protocol run from a CSPRNG"}))
				continue
			}
			if f.Source == nil {
				assumptions = append(assumptions, fmt.Sprintf(
					"contract %q: %s %q declares fresh: true but has no source binding; uniqueness rests on the declaration",
					c.ID, f.Kind, f.Name))
			} else {
				assumptions = append(assumptions, fmt.Sprintf(
					"contract %q: %s %q freshness is claimed by declaration and source binding %s; entropy quality requires source verification",
					c.ID, f.Kind, f.Name, specSummary(*f.Source)))
			}
		}
	}

	res.Assumptions = append(res.Assumptions, assumptions...)
	return diags
}

// traceSteps renders the minimal protocol trace: one state step per
// transcript message from the first step through the step containing
// the offending field (stepIdx). This is the "minimal protocol trace"
// each finding carries — the attacker sees exactly these messages.
func traceSteps(c *Contract, stepIdx int) []analysis.EvidenceStep {
	if stepIdx < 0 {
		stepIdx = len(c.Transcript) - 1
	}
	if stepIdx >= len(c.Transcript) {
		stepIdx = len(c.Transcript) - 1
	}
	var steps []analysis.EvidenceStep
	for i := 0; i <= stepIdx && i < len(c.Transcript); i++ {
		s := c.Transcript[i]
		var names []string
		for _, f := range s.Fields {
			names = append(names, f.Name)
		}
		steps = append(steps, analysis.EvidenceStep{
			Kind: analysis.EvidenceState,
			Note: fmt.Sprintf("%s: %s -> %s fields [%s]", s.Name, s.From, s.To, strings.Join(names, ", ")),
		})
	}
	return steps
}

func displayType(t string) string {
	if t == "" {
		return "<unset>"
	}
	return t
}

func cap(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// finding builds an analysis.Finding for a modeled violation. The
// primary span is the contract file (or a synthetic name when the
// contract was parsed from bytes); evidence carries the minimal
// protocol trace. Model findings are always StatusPotential — the
// declared model may diverge from the implementation — and unmodeled
// constructions are StatusUnverified. Nothing here is ever StatusProven:
// pattern/model matching cannot prove cryptographic properties.
func (c *Contract) finding(_ *Contract, ruleID, ruleName, message string,
	status analysis.Status, severity string,
	assumptions []string, evidence []analysis.EvidenceStep,
	meta map[string]string, remediation []string) analysis.Finding {
	spanFile := c.Source
	if spanFile == "" {
		spanFile = "authproto-contract:" + c.ID
	}
	if meta == nil {
		meta = make(map[string]string)
	}
	meta["contract"] = c.ID
	if _, ok := meta["attacker_capabilities"]; !ok && status == analysis.StatusPotential {
		meta["attacker_capabilities"] = "network attacker (Dolev-Yao: observe, modify, drop, replay, inject)"
	}
	if _, ok := meta["not_proven"]; !ok {
		meta["not_proven"] = "implementation conformance and cryptographic primitive strength"
	}
	confidence := analysis.ConfidenceMedium
	if status == analysis.StatusUnverified {
		confidence = analysis.ConfidenceUnknown
	}
	f := analysis.Finding{
		RuleID:      ruleID,
		RuleName:    ruleName,
		Analyzer:    "authproto",
		Message:     message,
		Category:    "security",
		Severity:    severity,
		Status:      status,
		Confidence:  confidence,
		Trace:       analysis.TraceStateTransition,
		Spans:       []analysis.Span{{File: spanFile, StartLine: 1}},
		Evidence:    evidence,
		Assumptions: assumptions,
		Remediation: strings.Join(remediation, "; "),
		Metadata:    meta,
	}
	return analysis.NewFinding(f)
}

// specSummary renders a FunctionSpec for diagnostics.
func specSummary(spec FunctionSpec) string {
	if spec.ID != "" {
		return "id=" + spec.ID
	}
	var parts []string
	if spec.Name != "" {
		parts = append(parts, "name="+spec.Name)
	}
	if spec.Package != "" {
		parts = append(parts, "package="+spec.Package)
	}
	if spec.Receiver != "" {
		parts = append(parts, "receiver="+spec.Receiver)
	}
	return strings.Join(parts, ", ")
}
