package protocol

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

// Direction identifies which client/server version pairing a
// contract change affects.
type Direction uint8

const (
	// DirOldClientNewServer: a client running the older contract
	// version talking to a server running the newer contract.
	DirOldClientNewServer Direction = 1 << iota
	// DirNewClientOldServer: a client running the newer contract
	// version talking to a server running the older contract.
	DirNewClientOldServer
	// DirBoth marks changes observable in (and potentially breaking)
	// both pairings.
	DirBoth = DirOldClientNewServer | DirNewClientOldServer
)

// String renders the direction in the canonical matrix vocabulary.
func (d Direction) String() string {
	switch d {
	case DirOldClientNewServer:
		return "old-client/new-server"
	case DirNewClientOldServer:
		return "new-client/old-server"
	case DirBoth:
		return "both"
	}
	return "none"
}

// Intersects reports whether d and o share at least one direction.
func (d Direction) Intersects(o Direction) bool { return d&o != 0 }

// ParseDirection maps a direction string onto Direction. Accepted
// values: "both", "old-client/new-server", "new-client/old-server"
// (also the hyphenated "old-client-new-server" spellings are NOT
// accepted — the slash form is canonical).
func ParseDirection(s string) (Direction, bool) {
	switch strings.TrimSpace(s) {
	case "", "both":
		return DirBoth, true
	case "old-client/new-server":
		return DirOldClientNewServer, true
	case "new-client/old-server":
		return DirNewClientOldServer, true
	}
	return 0, false
}

// Change kinds emitted by the comparator.
const (
	KindAdded               = "added"
	KindRemoved             = "removed"
	KindRenamed             = "renamed"
	KindTypeChanged         = "type-changed"
	KindDefaultChanged      = "default-changed"
	KindRequirednessChanged = "requiredness-changed"
	KindMethodChanged       = "method-changed"
	KindPathChanged         = "path-changed"
	KindAuthChanged         = "auth-changed"
	KindValuesChanged       = "values-changed"
)

// Change is one detected difference between two contract versions.
// Structural changes (removals, renames, type and requiredness
// changes) are wire-level facts; semantic changes (defaults, auth
// behavior, capability values) are flagged Structural=false and
// require an explicit compat assertion to be considered acknowledged.
type Change struct {
	// Kind is one of the Kind* constants.
	Kind string
	// Element is the canonical element path, e.g.
	// "request.CreateSession.field.ttl" or "auth.scheme".
	Element string
	// Directions lists the compatibility pairings the change
	// affects.
	Directions Direction
	// Structural is true for wire-level incompatibilities, false
	// for semantic changes requiring explicit assertions.
	Structural bool
	// Old and New describe the element in each contract
	// ("<unset>" when absent).
	Old, New string
	// Severity is the finding severity: info/low for benign or
	// informational changes, medium for breaking changes.
	Severity string
	// Finding is the analysis.Finding emitted for this change
	// (empty when suppressed by a compat annotation).
	Finding analysis.Finding
}

// SuppressedChange records a change that was documented by a compat
// annotation (intentional breaking change or semantic assertion) in
// one of the compared contracts. The annotation suppressed exactly
// this finding.
type SuppressedChange struct {
	Change     Change
	Annotation Annotation
	// DeclaredBy is the contract version label whose compat block
	// carried the annotation.
	DeclaredBy string
	// Kind is "breaking_changes" or "assertions".
	Kind string
}

// Comparison is the result of comparing two contract versions.
type Comparison struct {
	Old, New *Contract
	// Changes are the unsuppressed differences, in deterministic
	// order.
	Changes []Change
	// Suppressed lists changes silenced by compat annotations.
	Suppressed []SuppressedChange
	// Diagnostics carries contract validation problems and
	// comparator-level issues (e.g. dangling renamed_from).
	Diagnostics []analysis.Diagnostic
}

// Findings returns the analysis findings for unsuppressed changes,
// ID-assigned and deterministically ordered.
func (c *Comparison) Findings() []analysis.Finding {
	out := make([]analysis.Finding, 0, len(c.Changes))
	for _, ch := range c.Changes {
		if ch.Finding.ID != "" || ch.Finding.RuleID != "" {
			out = append(out, ch.Finding)
		}
	}
	return analysis.AssignFindingIDs(out)
}

// Breaking reports whether any unsuppressed change has breaking
// severity (medium or higher).
func (c *Comparison) Breaking() bool {
	for _, ch := range c.Changes {
		if breakingSeverity(ch.Severity) {
			return true
		}
	}
	return false
}

func breakingSeverity(s string) bool {
	return s == "medium" || s == "high" || s == "critical"
}

// label returns a human label for a contract in messages.
func label(c *Contract) string {
	if c == nil {
		return "<nil>"
	}
	if c.Version != "" {
		return c.ID + "@" + c.Version
	}
	return c.ID
}

// ---------------------------------------------------------------------
// Comparison
// ---------------------------------------------------------------------

// Compare diffs two protocol contracts element-by-element and
// produces findings for every detected change. Old plays the
// "older deployed version" role and New the "newer" role for
// direction attribution; the comparison itself is symmetric in the
// sense that both directions are always evaluated.
//
// Compat annotations in EITHER contract suppress matching findings:
// a finding is suppressed when an annotation's element equals the
// change's element path, its optional change kind matches, and its
// optional direction intersects the change's directions.
func Compare(old, new *Contract) *Comparison {
	cmp := &Comparison{Old: old, New: new}
	if old == nil || new == nil {
		cmp.Diagnostics = append(cmp.Diagnostics, analysis.Diagnostic{
			Severity: analysis.DiagSeverityError, Category: analysis.DiagLoadError,
			Message: "protocol comparison requires two non-nil contracts",
		})
		return cmp
	}
	cmp.Diagnostics = append(cmp.Diagnostics, old.Check()...)
	cmp.Diagnostics = append(cmp.Diagnostics, new.Check()...)

	clean := !old.HasErrors() && !new.HasErrors()

	// Messages: requests are client->server, responses server->client.
	diffMessages(cmp, "request", old.Requests, new.Requests, clean, modeRequest)
	diffMessages(cmp, "response", old.Responses, new.Responses, clean, modeResponse)

	// Headers behave like request fields (client -> server).
	diffHeaders(cmp, old.Headers, new.Headers, clean)

	// Pairing is mutual: every change affects both directions.
	diffPairing(cmp, old.Pairing, new.Pairing, clean)

	// Capabilities.
	diffCapabilities(cmp, old.Capabilities, new.Capabilities, clean)

	// Auth.
	diffAuth(cmp, old.Auth, new.Auth, clean)

	// Apply compat annotations last so suppression sees every change.
	applyAnnotations(cmp)

	sort.SliceStable(cmp.Changes, func(i, j int) bool {
		if cmp.Changes[i].Element != cmp.Changes[j].Element {
			return cmp.Changes[i].Element < cmp.Changes[j].Element
		}
		return cmp.Changes[i].Kind < cmp.Changes[j].Kind
	})
	return cmp
}

// fieldMode selects the direction/severity rules for field changes.
type fieldMode int

const (
	modeRequest  fieldMode = iota // client -> server
	modeResponse                  // server -> client
	modeMutual                    // pairing: both directions
)

// diffMessages compares two message lists. Message-level attrs
// (method, path) are compared for requests; removals/additions are
// reported at message granularity and suppress per-field diffs.
func diffMessages(cmp *Comparison, section string, oldMsgs, newMsgs []MessageSpec,
	clean bool, mode fieldMode) {

	oldByName := make(map[string]*MessageSpec)
	for i := range oldMsgs {
		oldByName[oldMsgs[i].Name] = &oldMsgs[i]
	}
	newByName := make(map[string]*MessageSpec)
	for i := range newMsgs {
		newByName[newMsgs[i].Name] = &newMsgs[i]
	}

	// Removed and matched messages.
	for _, om := range oldMsgs {
		elem := section + "." + om.Name
		nm, ok := newByName[om.Name]
		if !ok {
			sev := "medium"
			if mode == modeResponse {
				sev = "low"
			}
			cmp.addChange(Change{
				Kind: KindRemoved, Element: elem, Directions: DirOldClientNewServer,
				Structural: true, Old: describeMessage(om), New: "<absent>",
				Severity: sev,
			}, clean, cmp.Old, cmp.New)
			continue
		}
		// Message-level attributes.
		if om.Method != nm.Method {
			cmp.addChange(Change{
				Kind: KindMethodChanged, Element: elem + ".method",
				Directions: DirBoth, Structural: true,
				Old: om.Method, New: nm.Method, Severity: "medium",
			}, clean, cmp.Old, cmp.New)
		}
		if om.Path != nm.Path {
			cmp.addChange(Change{
				Kind: KindPathChanged, Element: elem + ".path",
				Directions: DirBoth, Structural: true,
				Old: om.Path, New: nm.Path, Severity: "medium",
			}, clean, cmp.Old, cmp.New)
		}
		diffFields(cmp, elem+".field.", om.Fields, nm.Fields, mode, clean)
	}
	// Added messages.
	for _, nm := range newMsgs {
		if _, ok := oldByName[nm.Name]; ok {
			continue
		}
		cmp.addChange(Change{
			Kind: KindAdded, Element: section + "." + nm.Name, Directions: DirBoth,
			Structural: true, Old: "<absent>", New: describeMessage(nm),
			Severity: "low",
		}, clean, cmp.Old, cmp.New)
	}
}

func describeMessage(m MessageSpec) string {
	var b strings.Builder
	if m.Method != "" {
		b.WriteString(m.Method)
		b.WriteByte(' ')
	}
	if m.Path != "" {
		b.WriteString(m.Path)
	}
	if b.Len() == 0 {
		b.WriteString("message")
	}
	return b.String()
}

// diffFields compares two field lists of the same message, honoring
// renamed_from declarations in the new contract.
func diffFields(cmp *Comparison, prefix string, oldFields, newFields []FieldSpec, mode fieldMode, clean bool) {
	oldByName := make(map[string]*FieldSpec)
	for i := range oldFields {
		oldByName[oldFields[i].Name] = &oldFields[i]
	}
	newByName := make(map[string]*FieldSpec)
	for i := range newFields {
		newByName[newFields[i].Name] = &newFields[i]
	}

	consumedOld := make(map[string]bool)
	consumedNew := make(map[string]bool)

	// Pass 1: explicit renames declared via renamed_from on new
	// fields. The comparator trusts Check to have rejected ambiguous
	// declarations; dangling targets are diagnosed here.
	for i := range newFields {
		nf := &newFields[i]
		if nf.RenamedFrom == "" {
			continue
		}
		elem := prefix + nf.Name
		oldTarget, ok := oldByName[nf.RenamedFrom]
		if !ok {
			cmp.Diagnostics = append(cmp.Diagnostics, analysis.Diagnostic{
				Severity: analysis.DiagSeverityWarning, Category: analysis.DiagParseError,
				Message: fmt.Sprintf("%s%s: renamed_from %q has no matching field in the old contract", prefix, nf.Name, nf.RenamedFrom),
			})
			continue
		}
		if _, clash := newByName[nf.RenamedFrom]; clash {
			// Check already reported the ambiguity; compare normally.
			continue
		}
		consumedOld[nf.RenamedFrom] = true
		consumedNew[nf.Name] = true
		dirs, sev := renameDirs(mode)
		cmp.addChange(Change{
			Kind: KindRenamed, Element: elem, Directions: dirs,
			Structural: true,
			Old:        describeField(nf.RenamedFrom, oldTarget),
			New:        describeField(nf.Name, nf),
			Severity:   sev,
		}, clean, cmp.Old, cmp.New)
	}

	// Pass 2: removals and matched fields.
	for i := range oldFields {
		of := &oldFields[i]
		if consumedOld[of.Name] {
			continue
		}
		elem := prefix + of.Name
		nf, ok := newByName[of.Name]
		if !ok {
			dirs, sev := removedDirs(mode, of.Required)
			cmp.addChange(Change{
				Kind: KindRemoved, Element: elem, Directions: dirs,
				Structural: true,
				Old:        describeField(of.Name, of), New: "<absent>",
				Severity: sev,
			}, clean, cmp.Old, cmp.New)
			continue
		}
		consumedNew[nf.Name] = true
		diffFieldAttrs(cmp, elem, of, nf, mode, clean)
	}

	// Pass 3: additions.
	for i := range newFields {
		nf := &newFields[i]
		if consumedNew[nf.Name] {
			continue
		}
		dirs, sev := addedDirs(mode, nf.Required)
		cmp.addChange(Change{
			Kind: KindAdded, Element: prefix + nf.Name, Directions: dirs,
			Structural: true,
			Old:        "<absent>", New: describeField(nf.Name, nf),
			Severity: sev,
		}, clean, cmp.Old, cmp.New)
	}
}

func describeField(name string, f *FieldSpec) string {
	return fmt.Sprintf("%s (type=%s, required=%t)", name, f.Type, f.Required)
}

// diffFieldAttrs compares type, requiredness, and default of a
// matched field pair.
func diffFieldAttrs(cmp *Comparison, elem string, of, nf *FieldSpec, mode fieldMode, clean bool) {
	if of.Type != nf.Type {
		dirs := DirBoth
		if mode == modeMutual {
			dirs = DirBoth
		}
		cmp.addChange(Change{
			Kind: KindTypeChanged, Element: elem, Directions: dirs,
			Structural: true,
			Old:        "type=" + of.Type, New: "type=" + nf.Type,
			Severity: "medium",
		}, clean, cmp.Old, cmp.New)
	}
	if of.Required != nf.Required {
		dirs, sev := requirednessDirs(mode, of.Required, nf.Required)
		cmp.addChange(Change{
			Kind: KindRequirednessChanged, Element: elem, Directions: dirs,
			Structural: true,
			Old:        fmt.Sprintf("required=%t", of.Required),
			New:        fmt.Sprintf("required=%t", nf.Required),
			Severity:   sev,
		}, clean, cmp.Old, cmp.New)
	}
	if !defaultEqual(of.Default, nf.Default) {
		cmp.addChange(Change{
			Kind: KindDefaultChanged, Element: elem, Directions: DirBoth,
			Structural: false, // semantic: requires an assertion
			Old:        defaultString(of.Default), New: defaultString(nf.Default),
			Severity: "low",
		}, clean, cmp.Old, cmp.New)
	}
}

// Direction/severity rules. "old" is the older deployed contract,
// "new" the newer. Request fields travel client->server; response
// fields server->client; mutual (pairing) fields affect both.

func renameDirs(mode fieldMode) (Direction, string) {
	// A rename breaks whichever peer still uses the old name; both
	// pairings are affected unless the deployment is synchronized.
	return DirBoth, "medium"
}

func removedDirs(mode fieldMode, wasRequired bool) (Direction, string) {
	switch mode {
	case modeRequest:
		// New client omits a field the old server may require.
		if wasRequired {
			return DirNewClientOldServer, "medium"
		}
		return DirBoth, "low"
	case modeResponse:
		// New server omits a field the old client may require.
		if wasRequired {
			return DirOldClientNewServer, "medium"
		}
		return DirBoth, "low"
	default: // mutual
		if wasRequired {
			return DirBoth, "medium"
		}
		return DirBoth, "low"
	}
}

func addedDirs(mode fieldMode, nowRequired bool) (Direction, string) {
	switch mode {
	case modeRequest:
		// Old client omits a field the new server may require.
		if nowRequired {
			return DirOldClientNewServer, "medium"
		}
		return DirBoth, "low"
	case modeResponse:
		// New client requires a field the old server may not send.
		if nowRequired {
			return DirNewClientOldServer, "medium"
		}
		return DirBoth, "low"
	default:
		if nowRequired {
			return DirBoth, "medium"
		}
		return DirBoth, "low"
	}
}

func requirednessDirs(mode fieldMode, oldReq, newReq bool) (Direction, string) {
	if oldReq == newReq {
		return DirBoth, "low"
	}
	switch mode {
	case modeRequest:
		if !oldReq && newReq {
			// Old client does not send what the new server requires.
			return DirOldClientNewServer, "medium"
		}
		// New client may omit what the old server requires.
		return DirNewClientOldServer, "medium"
	case modeResponse:
		if !oldReq && newReq {
			// New client requires what the old server may omit.
			return DirNewClientOldServer, "medium"
		}
		// Old client requires what the new server may omit.
		return DirOldClientNewServer, "medium"
	default:
		return DirBoth, "medium"
	}
}

func diffHeaders(cmp *Comparison, oldH, newH []HeaderSpec, clean bool) {
	oldByName := make(map[string]*HeaderSpec)
	for i := range oldH {
		oldByName[oldH[i].Name] = &oldH[i]
	}
	newByName := make(map[string]*HeaderSpec)
	for i := range newH {
		newByName[newH[i].Name] = &newH[i]
	}
	for _, oh := range oldH {
		elem := "header." + oh.Name
		nh, ok := newByName[oh.Name]
		if !ok {
			dirs, sev := removedDirs(modeRequest, oh.Required)
			cmp.addChange(Change{
				Kind: KindRemoved, Element: elem, Directions: dirs,
				Structural: true, Old: describeHeader(oh), New: "<absent>", Severity: sev,
			}, clean, cmp.Old, cmp.New)
			continue
		}
		if oh.Type != nh.Type {
			cmp.addChange(Change{
				Kind: KindTypeChanged, Element: elem, Directions: DirBoth,
				Structural: true, Old: "type=" + oh.Type, New: "type=" + nh.Type, Severity: "medium",
			}, clean, cmp.Old, cmp.New)
		}
		if oh.Required != nh.Required {
			dirs, sev := requirednessDirs(modeRequest, oh.Required, nh.Required)
			cmp.addChange(Change{
				Kind: KindRequirednessChanged, Element: elem, Directions: dirs,
				Structural: true,
				Old:        fmt.Sprintf("required=%t", oh.Required), New: fmt.Sprintf("required=%t", nh.Required),
				Severity: sev,
			}, clean, cmp.Old, cmp.New)
		}
		if !defaultEqual(oh.Default, nh.Default) {
			cmp.addChange(Change{
				Kind: KindDefaultChanged, Element: elem, Directions: DirBoth,
				Structural: false,
				Old:        defaultString(oh.Default), New: defaultString(nh.Default), Severity: "low",
			}, clean, cmp.Old, cmp.New)
		}
	}
	for _, nh := range newH {
		if _, ok := oldByName[nh.Name]; ok {
			continue
		}
		dirs, sev := addedDirs(modeRequest, nh.Required)
		cmp.addChange(Change{
			Kind: KindAdded, Element: "header." + nh.Name, Directions: dirs,
			Structural: true, Old: "<absent>", New: describeHeader(nh), Severity: sev,
		}, clean, cmp.Old, cmp.New)
	}
}

func describeHeader(h HeaderSpec) string {
	return fmt.Sprintf("%s (type=%s, required=%t)", h.Name, h.Type, h.Required)
}

func diffPairing(cmp *Comparison, oldP, newP *PairingSpec, clean bool) {
	switch {
	case oldP == nil && newP == nil:
		return
	case oldP == nil:
		cmp.addChange(Change{
			Kind: KindAdded, Element: "pairing", Directions: DirBoth,
			Structural: true, Old: "<absent>", New: "pairing exchange", Severity: "low",
		}, clean, cmp.Old, cmp.New)
		return
	case newP == nil:
		cmp.addChange(Change{
			Kind: KindRemoved, Element: "pairing", Directions: DirBoth,
			Structural: true, Old: "pairing exchange", New: "<absent>", Severity: "medium",
		}, clean, cmp.Old, cmp.New)
		return
	}
	diffFields(cmp, "pairing.field.", oldP.Fields, newP.Fields, modeMutual, clean)
}

func diffCapabilities(cmp *Comparison, oldCaps, newCaps []CapabilitySpec, clean bool) {
	oldByName := make(map[string]*CapabilitySpec)
	for i := range oldCaps {
		oldByName[oldCaps[i].Name] = &oldCaps[i]
	}
	newByName := make(map[string]*CapabilitySpec)
	for i := range newCaps {
		newByName[newCaps[i].Name] = &newCaps[i]
	}
	for _, oc := range oldCaps {
		elem := "capability." + oc.Name
		nc, ok := newByName[oc.Name]
		if !ok {
			cmp.addChange(Change{
				Kind: KindRemoved, Element: elem, Directions: DirBoth,
				Structural: true, Old: describeCapability(oc), New: "<absent>", Severity: "low",
			}, clean, cmp.Old, cmp.New)
			continue
		}
		diffCapabilityAttrs(cmp, elem, &oc, nc, clean)
	}
	for _, nc := range newCaps {
		if _, ok := oldByName[nc.Name]; ok {
			continue
		}
		cmp.addChange(Change{
			Kind: KindAdded, Element: "capability." + nc.Name, Directions: DirBoth,
			Structural: true, Old: "<absent>", New: describeCapability(nc), Severity: "info",
		}, clean, cmp.Old, cmp.New)
	}
}

func diffCapabilityAttrs(cmp *Comparison, elem string, oc *CapabilitySpec, nc *CapabilitySpec, clean bool) {
	if oc.Type != nc.Type {
		cmp.addChange(Change{
			Kind: KindTypeChanged, Element: elem, Directions: DirBoth,
			Structural: true, Old: "type=" + oc.Type, New: "type=" + nc.Type, Severity: "low",
		}, clean, cmp.Old, cmp.New)
	}
	if oc.Required != nc.Required {
		cmp.addChange(Change{
			Kind: KindRequirednessChanged, Element: elem, Directions: DirBoth,
			Structural: false,
			Old:        fmt.Sprintf("required=%t", oc.Required), New: fmt.Sprintf("required=%t", nc.Required),
			Severity: "low",
		}, clean, cmp.Old, cmp.New)
	}
	if !stringSliceEqual(oc.Values, nc.Values) {
		cmp.addChange(Change{
			Kind: KindValuesChanged, Element: elem, Directions: DirBoth,
			Structural: false,
			Old:        strings.Join(oc.Values, ","), New: strings.Join(nc.Values, ","),
			Severity: "low",
		}, clean, cmp.Old, cmp.New)
	}
	if !defaultEqual(oc.Default, nc.Default) {
		cmp.addChange(Change{
			Kind: KindDefaultChanged, Element: elem, Directions: DirBoth,
			Structural: false,
			Old:        defaultString(oc.Default), New: defaultString(nc.Default), Severity: "low",
		}, clean, cmp.Old, cmp.New)
	}
}

func describeCapability(c CapabilitySpec) string {
	return fmt.Sprintf("%s (type=%s)", c.Name, c.Type)
}

func diffAuth(cmp *Comparison, oldA, newA *AuthSpec, clean bool) {
	oldScheme, newScheme := "none", "none"
	oldReq, newReq := false, false
	oldHdr, newHdr := "", ""
	if oldA != nil {
		oldScheme = oldA.Scheme
		oldReq = oldA.RequiredValue()
		oldHdr = oldA.HeaderValue()
	}
	if newA != nil {
		newScheme = newA.Scheme
		newReq = newA.RequiredValue()
		newHdr = newA.HeaderValue()
	}
	if oldScheme == newScheme && oldReq == newReq && oldHdr == newHdr {
		return
	}
	if oldScheme != newScheme {
		cmp.addChange(Change{
			Kind: KindAuthChanged, Element: "auth.scheme",
			Directions: DirBoth, Structural: false, // semantic: needs assertion
			Old: oldScheme, New: newScheme, Severity: "medium",
		}, clean, cmp.Old, cmp.New)
	}
	if oldReq != newReq {
		dirs := DirBoth
		if !oldReq && newReq {
			dirs = DirOldClientNewServer // old clients lack credentials
		} else {
			dirs = DirNewClientOldServer // new clients may omit credentials
		}
		cmp.addChange(Change{
			Kind: KindRequirednessChanged, Element: "auth.required",
			Directions: dirs, Structural: true,
			Old: fmt.Sprintf("required=%t", oldReq), New: fmt.Sprintf("required=%t", newReq),
			Severity: "medium",
		}, clean, cmp.Old, cmp.New)
	}
	if oldHdr != newHdr {
		cmp.addChange(Change{
			Kind: KindAuthChanged, Element: "auth.header",
			Directions: DirBoth, Structural: false,
			Old: oldHdr, New: newHdr, Severity: "medium",
		}, clean, cmp.Old, cmp.New)
	}
}

// addChange finalizes a change: builds the analysis.Finding, then
// either appends it to Changes or records it as suppressed once
// annotations have been applied. Suppression is applied in a second
// pass (applyAnnotations) so every change is visible first.
func (cmp *Comparison) addChange(ch Change, clean bool, oldC, newC *Contract) {
	ch.Finding = buildFinding(ch, oldC, newC, clean)
	cmp.Changes = append(cmp.Changes, ch)
}

// buildFinding renders a change as an analysis.Finding. The finding
// is StatusProven only when both contracts validated cleanly;
// otherwise StatusPotential. Semantic (non-structural) changes are
// always StatusPotential because wire compatibility cannot be
// proven from structure alone.
func buildFinding(ch Change, oldC, newC *Contract, clean bool) analysis.Finding {
	status := analysis.StatusProven
	confidence := analysis.ConfidenceHigh
	if !clean || !ch.Structural {
		status = analysis.StatusPotential
		confidence = analysis.ConfidenceMedium
	}
	spanFile := ""
	if newC != nil && newC.Source != "" {
		spanFile = newC.Source
	} else if oldC != nil && oldC.Source != "" {
		spanFile = oldC.Source
	}
	if spanFile == "" {
		spanFile = "protocol-contract"
	}

	oldLabel, newLabel := label(oldC), label(newC)
	msg := fmt.Sprintf("%s %s: %s -> %s (affects %s)",
		ch.Element, changeVerb(ch.Kind), ch.Old, ch.New, ch.Directions)
	if !ch.Structural {
		msg += "; semantic change requires an explicit compat assertion"
	}

	f := analysis.Finding{
		RuleID:     "protocol-compat",
		RuleName:   "Protocol compatibility",
		Analyzer:   "protocol",
		Message:    msg,
		Category:   "drift",
		Severity:   ch.Severity,
		Status:     status,
		Confidence: confidence,
		Trace:      analysis.TraceGeneral,
		Spans: []analysis.Span{
			{File: spanFile, StartLine: 1},
		},
		Evidence: []analysis.EvidenceStep{
			{Kind: analysis.EvidenceNote, Note: fmt.Sprintf("old contract %s: %s", oldLabel, ch.Old)},
			{Kind: analysis.EvidenceNote, Note: fmt.Sprintf("new contract %s: %s", newLabel, ch.New)},
		},
		Metadata: map[string]string{
			"change_kind":  ch.Kind,
			"element":      ch.Element,
			"directions":   ch.Directions.String(),
			"structural":   fmt.Sprintf("%t", ch.Structural),
			"old_contract": oldLabel,
			"new_contract": newLabel,
		},
	}
	return analysis.NewFinding(f)
}

func changeVerb(kind string) string {
	switch kind {
	case KindAdded:
		return "added"
	case KindRemoved:
		return "removed"
	case KindRenamed:
		return "renamed"
	}
	return "changed (" + kind + ")"
}

// applyAnnotations removes findings matched by compat annotations
// from either contract, recording them as Suppressed.
func applyAnnotations(cmp *Comparison) {
	type ann struct {
		Annotation
		declaredBy string
		list       string
	}
	var anns []ann
	collect := func(c *Contract) {
		if c == nil || c.Compat == nil {
			return
		}
		for _, a := range c.Compat.BreakingChanges {
			anns = append(anns, ann{a, label(c), "breaking_changes"})
		}
		for _, a := range c.Compat.Assertions {
			anns = append(anns, ann{a, label(c), "assertions"})
		}
	}
	collect(cmp.Old)
	collect(cmp.New)

	kept := cmp.Changes[:0]
	for _, ch := range cmp.Changes {
		var match *ann
		for i := range anns {
			a := &anns[i]
			if !annotationMatches(a.Annotation, ch) {
				continue
			}
			match = a
			break
		}
		if match == nil {
			kept = append(kept, ch)
			continue
		}
		cmp.Suppressed = append(cmp.Suppressed, SuppressedChange{
			Change:     ch,
			Annotation: match.Annotation,
			DeclaredBy: match.declaredBy,
			Kind:       match.list,
		})
	}
	cmp.Changes = kept
}

// annotationMatches reports whether an annotation suppresses a
// change. Matching is exact on the element path — an annotation for
// "request.Foo" does NOT suppress findings for
// "request.Foo.field.bar" — plus optional kind and direction
// filters. This guarantees documented changes never hide unrelated
// findings.
func annotationMatches(a Annotation, ch Change) bool {
	if a.Element != ch.Element {
		return false
	}
	if a.Change != "" && a.Change != ch.Kind {
		return false
	}
	if a.Direction != "" {
		d, ok := ParseDirection(a.Direction)
		if !ok {
			return false // invalid direction already diagnosed by Check
		}
		if !d.Intersects(ch.Directions) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------

func defaultEqual(a, b *DefaultValue) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.DeepEqual(a.Value, b.Value)
}

func defaultString(d *DefaultValue) string {
	if d == nil {
		return "<unset>"
	}
	return fmt.Sprintf("%v", d.Value)
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
