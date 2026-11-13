package protocol

import (
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
)

func mustParse(t *testing.T, doc string) *Contract {
	t.Helper()
	c, err := ParseContract([]byte(doc))
	if err != nil {
		t.Fatalf("ParseContract: %v", err)
	}
	return c
}

func changeByElement(cmp *Comparison, element string) *Change {
	for i := range cmp.Changes {
		if cmp.Changes[i].Element == element {
			return &cmp.Changes[i]
		}
	}
	return nil
}

func hasDiag(diags []analysis.Diagnostic, substr string) bool {
	for _, d := range diags {
		if strings.Contains(d.Message, substr) {
			return true
		}
	}
	return false
}

const baseOld = `
schema_version: protocol/1
id: demo
version: "1.0.0"
requests:
  - name: CreateSession
    method: POST
    path: /v1/sessions
    fields:
      - name: device_id
        type: string
        required: true
      - name: ttl
        type: integer
        required: false
        default: 300
responses:
  - name: SessionAck
    fields:
      - name: session_id
        type: string
        required: true
      - name: server_time
        type: integer
        required: false
headers:
  - name: X-Request-Id
    type: string
    required: false
auth:
  scheme: bearer
  required: true
  header: Authorization
pairing:
  fields:
    - name: code
      type: string
      required: true
capabilities:
  - name: streaming
    type: boolean
    default: false
`

func TestParseContract(t *testing.T) {
	c := mustParse(t, baseOld)
	if c.ID != "demo" || c.Version != "1.0.0" {
		t.Fatalf("unexpected id/version: %q %q", c.ID, c.Version)
	}
	if len(c.Check()) != 0 {
		t.Fatalf("unexpected diagnostics: %v", c.Check())
	}
	f := c.Requests[0].Fields[1]
	if f.Default == nil || f.Default.Value != 300 {
		t.Fatalf("default not decoded: %#v", f.Default)
	}
	if !c.Auth.RequiredValue() || c.Auth.HeaderValue() != "Authorization" {
		t.Fatal("auth defaults wrong")
	}
}

func TestParseContractRejectsBadVersion(t *testing.T) {
	for _, doc := range []string{
		"schema_version: protocol/2\nid: x\n",
		"id: x\n",
		"schema_version: statemachine/1\n",
	} {
		if _, err := ParseContract([]byte(doc)); err == nil {
			t.Fatalf("expected error for %q", doc)
		}
	}
}

func TestCheckDiagnostics(t *testing.T) {
	bad := `
schema_version: protocol/1
requests:
  - name: Foo
    fields:
      - name: a
        type: string
      - name: a
        type: integer
      - name: b
        type: bogus
        renamed_from: a
  - name: Foo
responses:
  - name: Bar
    fields:
      - name: x
        type: string
        renamed_from: y
        renamed_from2: z
auth:
  scheme: ""
compat:
  breaking_changes:
    - element: ""
      reason: ""
    - element: request.Foo.field.a
      direction: sideways
      reason: r
`
	c := mustParse(t, bad)
	diags := c.Check()
	for _, want := range []string{
		"duplicate message name", "duplicate field", "unknown type",
		"renamed_from", "scheme is required", "element is required",
		"reason is required", "invalid direction",
	} {
		if !hasDiag(diags, want) {
			t.Errorf("missing diagnostic containing %q; got %v", want, diags)
		}
	}
	// renamed_from ambiguity: field b claims renamed_from "a" while
	// "a" is still declared — must be diagnosed.
	if !hasDiag(diags, "still declared") {
		t.Error("missing renamed_from ambiguity diagnostic")
	}
}

func TestCompareIdentical(t *testing.T) {
	old := mustParse(t, baseOld)
	new := mustParse(t, baseOld)
	new.Version = "1.0.1"
	cmp := Compare(old, new)
	if len(cmp.Changes) != 0 {
		t.Fatalf("expected no changes, got %v", cmp.Changes)
	}
	if cmp.Breaking() {
		t.Fatal("identical contracts must not break")
	}
}

func TestCompareFieldChanges(t *testing.T) {
	old := mustParse(t, baseOld)
	new := mustParse(t, `
schema_version: protocol/1
id: demo
version: "2.0.0"
requests:
  - name: CreateSession
    method: POST
    path: /v1/sessions
    fields:
      - name: device_id
        type: integer        # type change
        required: true
      - name: ttl
        type: integer
        required: true       # optional -> required
        default: 60          # default change
      - name: region         # added required
        type: string
        required: true
responses:
  - name: SessionAck
    fields:
      - name: session_id
        type: string
        required: true
`)
	cmp := Compare(old, new)

	tc := changeByElement(cmp, "request.CreateSession.field.device_id")
	if tc == nil || tc.Kind != KindTypeChanged || tc.Severity != "medium" || tc.Directions != DirBoth {
		t.Fatalf("type change wrong: %+v", tc)
	}
	if !tc.Structural {
		t.Fatal("type change must be structural")
	}

	tc = changeByElement(cmp, "request.CreateSession.field.ttl")
	// requiredness + default on same element: two changes share the
	// element; find by kind.
	var reqCh, defCh *Change
	for i := range cmp.Changes {
		ch := &cmp.Changes[i]
		if ch.Element == "request.CreateSession.field.ttl" && ch.Kind == KindRequirednessChanged {
			reqCh = ch
		}
		if ch.Element == "request.CreateSession.field.ttl" && ch.Kind == KindDefaultChanged {
			defCh = ch
		}
	}
	if reqCh == nil || reqCh.Directions != DirOldClientNewServer || reqCh.Severity != "medium" {
		t.Fatalf("requiredness change wrong: %+v", reqCh)
	}
	if defCh == nil || defCh.Structural || defCh.Severity != "low" {
		t.Fatalf("default change wrong: %+v", defCh)
	}

	tc = changeByElement(cmp, "request.CreateSession.field.region")
	if tc == nil || tc.Kind != KindAdded || tc.Directions != DirOldClientNewServer {
		t.Fatalf("added required request field wrong: %+v", tc)
	}

	tc = changeByElement(cmp, "response.SessionAck.field.server_time")
	if tc == nil || tc.Kind != KindRemoved || tc.Directions != DirBoth || tc.Severity != "low" {
		t.Fatalf("removed optional response field wrong: %+v", tc)
	}

	// Findings validate and carry metadata.
	for _, f := range cmp.Findings() {
		if err := f.Validate(); err != nil {
			t.Fatalf("invalid finding %s: %v", f.ID, err)
		}
		if f.Metadata["element"] == "" || f.Metadata["directions"] == "" {
			t.Fatalf("finding missing metadata: %+v", f.Metadata)
		}
	}
}

func TestCompareRemovedRequiredField(t *testing.T) {
	old := mustParse(t, `
schema_version: protocol/1
requests:
  - name: Ping
    fields:
      - name: token
        type: string
        required: true
`)
	new := mustParse(t, `
schema_version: protocol/1
requests:
  - name: Ping
    fields: []
`)
	cmp := Compare(old, new)
	ch := changeByElement(cmp, "request.Ping.field.token")
	// Old server required the field; new client no longer sends it.
	if ch == nil || ch.Kind != KindRemoved || ch.Directions != DirNewClientOldServer || ch.Severity != "medium" {
		t.Fatalf("removed required request field wrong: %+v", ch)
	}
}

func TestCompareRenamedField(t *testing.T) {
	old := mustParse(t, baseOld)
	new := mustParse(t, `
schema_version: protocol/1
requests:
  - name: CreateSession
    fields:
      - name: deviceId
        type: string
        required: true
        renamed_from: device_id
`)
	cmp := Compare(old, new)
	ch := changeByElement(cmp, "request.CreateSession.field.deviceId")
	if ch == nil || ch.Kind != KindRenamed || ch.Directions != DirBoth || ch.Severity != "medium" {
		t.Fatalf("rename wrong: %+v", ch)
	}
	// No separate removed/added findings for the renamed pair.
	if changeByElement(cmp, "request.CreateSession.field.device_id") != nil {
		t.Fatal("renamed field must not also produce a removal finding")
	}
}

func TestCompareDanglingRenamedFrom(t *testing.T) {
	old := mustParse(t, baseOld)
	new := mustParse(t, `
schema_version: protocol/1
requests:
  - name: CreateSession
    fields:
      - name: other
        type: string
        renamed_from: nonexistent
`)
	cmp := Compare(old, new)
	if !hasDiag(cmp.Diagnostics, "renamed_from") {
		t.Fatalf("expected dangling renamed_from diagnostic, got %v", cmp.Diagnostics)
	}
}

func TestCompareAuthChanges(t *testing.T) {
	old := mustParse(t, baseOld)

	// Scheme change: semantic, both directions.
	new := mustParse(t, strings.Replace(baseOld, "scheme: bearer", "scheme: hmac", 1))
	new.Version = "1.1.0"
	cmp := Compare(old, new)
	ch := changeByElement(cmp, "auth.scheme")
	if ch == nil || ch.Kind != KindAuthChanged || ch.Structural || ch.Directions != DirBoth || ch.Severity != "medium" {
		t.Fatalf("auth scheme change wrong: %+v", ch)
	}

	// required false->true: old clients lack credentials.
	new2 := mustParse(t, `
schema_version: protocol/1
auth:
  scheme: bearer
  required: false
`)
	old2 := mustParse(t, `
schema_version: protocol/1
auth:
  scheme: bearer
  required: true
`)
	cmp2 := Compare(old2, new2)
	// old required=true, new required=false -> new clients may omit -> new-client/old-server
	ch = changeByElement(cmp2, "auth.required")
	if ch == nil || ch.Directions != DirNewClientOldServer || ch.Severity != "medium" {
		t.Fatalf("auth required change wrong: %+v", ch)
	}
	cmp3 := Compare(new2, old2)
	ch = changeByElement(cmp3, "auth.required")
	if ch == nil || ch.Directions != DirOldClientNewServer {
		t.Fatalf("auth required direction wrong: %+v", ch)
	}
}

func TestCompareNoAuthVsAuth(t *testing.T) {
	old := mustParse(t, "schema_version: protocol/1\nrequests: []\n")
	new := mustParse(t, "schema_version: protocol/1\nauth:\n  scheme: bearer\n")
	cmp := Compare(old, new)
	if changeByElement(cmp, "auth.scheme") == nil {
		t.Fatal("expected auth.scheme change when auth is introduced")
	}
}

func TestCompareCapabilities(t *testing.T) {
	old := mustParse(t, baseOld)
	new := mustParse(t, strings.Replace(baseOld,
		"  - name: streaming\n    type: boolean\n    default: false",
		"  - name: streaming\n    type: string\n    values: [v1, v2]\n  - name: compression\n    type: boolean", 1))
	new.Version = "1.1.0"
	cmp := Compare(old, new)
	var capCh *Change
	for i := range cmp.Changes {
		if cmp.Changes[i].Element == "capability.streaming" && cmp.Changes[i].Kind == KindTypeChanged {
			capCh = &cmp.Changes[i]
		}
	}
	if capCh == nil {
		t.Fatal("expected capability.streaming type change")
	}
	if ch := changeByElement(cmp, "capability.compression"); ch == nil || ch.Kind != KindAdded || ch.Severity != "info" {
		t.Fatalf("added capability wrong: %+v", ch)
	}
}

func TestComparePairing(t *testing.T) {
	withPairing := mustParse(t, `
schema_version: protocol/1
pairing:
  fields:
    - name: code
      type: string
      required: true
    - name: region
      type: string
      required: true
`)
	without := mustParse(t, "schema_version: protocol/1\n")

	// Whole-section addition is reported at pairing granularity.
	cmp := Compare(without, withPairing)
	ch := changeByElement(cmp, "pairing")
	if ch == nil || ch.Kind != KindAdded || ch.Directions != DirBoth {
		t.Fatalf("pairing addition wrong: %+v", ch)
	}

	// Field-level diff when both contracts declare pairing.
	codeOnly := mustParse(t, `
schema_version: protocol/1
pairing:
  fields:
    - name: code
      type: string
      required: true
`)
	cmpF := Compare(codeOnly, withPairing)
	ch = changeByElement(cmpF, "pairing.field.region")
	if ch == nil || ch.Kind != KindAdded || ch.Directions != DirBoth || ch.Severity != "medium" {
		t.Fatalf("pairing added required field wrong: %+v", ch)
	}

	// Pairing removed entirely.
	cmp2 := Compare(withPairing, without)
	ch = changeByElement(cmp2, "pairing")
	if ch == nil || ch.Kind != KindRemoved || ch.Severity != "medium" || ch.Directions != DirBoth {
		t.Fatalf("pairing removal wrong: %+v", ch)
	}
}

func TestCompareHeaders(t *testing.T) {
	old := mustParse(t, baseOld)
	new := mustParse(t, strings.Replace(baseOld,
		"  - name: X-Request-Id\n    type: string\n    required: false",
		"  - name: X-Request-Id\n    type: string\n    required: true", 1))
	new.Version = "1.1.0"
	cmp := Compare(old, new)
	ch := changeByElement(cmp, "header.X-Request-Id")
	if ch == nil || ch.Kind != KindRequirednessChanged || ch.Directions != DirOldClientNewServer {
		t.Fatalf("header requiredness wrong: %+v", ch)
	}
}

func TestIntentionalBreakingChangeAnnotation(t *testing.T) {
	old := mustParse(t, baseOld)
	newDoc := strings.Replace(baseOld, "version: \"1.0.0\"", `version: "2.0.0"
compat:
  breaking_changes:
    - element: request.CreateSession.field.ttl
      change: default-changed
      reason: "ttl semantics changed in ADR-9; old default was wrong"
    - element: auth.scheme
      reason: "hmac migration documented"`, 1)
	// Introduce a real default change on ttl and an auth scheme change.
	newDoc = strings.Replace(newDoc, "scheme: bearer", "scheme: hmac", 1)
	newDoc = strings.Replace(newDoc, "default: 300", "default: 60", 1)
	new := mustParse(t, newDoc)
	cmp := Compare(old, new)

	// Both annotated findings suppressed; nothing else exists here.
	if len(cmp.Changes) != 0 {
		t.Fatalf("expected all changes suppressed, got %v", cmp.Changes)
	}
	if len(cmp.Suppressed) != 2 {
		t.Fatalf("expected 2 suppressed, got %d: %v", len(cmp.Suppressed), cmp.Suppressed)
	}
	for _, s := range cmp.Suppressed {
		if s.Annotation.Reason == "" || s.DeclaredBy == "" {
			t.Fatalf("suppressed change missing annotation metadata: %+v", s)
		}
	}
}

func TestAnnotationSuppressesOnlyItsOwnFinding(t *testing.T) {
	old := mustParse(t, baseOld)
	newDoc := strings.Replace(baseOld, "version: \"1.0.0\"", `version: "2.0.0"
compat:
  breaking_changes:
    - element: request.CreateSession.field.device_id
      change: type-changed
      reason: "intentional"`, 1)
	newDoc = strings.Replace(newDoc, "type: string\n        required: true\n      - name: ttl",
		"type: integer\n        required: true\n      - name: ttl", 1)
	// Also change ttl type — must NOT be suppressed.
	newDoc = strings.Replace(newDoc, "      - name: ttl\n        type: integer",
		"      - name: ttl\n        type: string", 1)
	new := mustParse(t, newDoc)
	cmp := Compare(old, new)
	if changeByElement(cmp, "request.CreateSession.field.device_id") != nil {
		t.Fatal("annotated finding should be suppressed")
	}
	ch := changeByElement(cmp, "request.CreateSession.field.ttl")
	found := false
	for i := range cmp.Changes {
		if cmp.Changes[i].Element == "request.CreateSession.field.ttl" && cmp.Changes[i].Kind == KindTypeChanged {
			found = true
		}
	}
	if !found {
		t.Fatalf("unrelated type change was suppressed or missing: %+v", cmp.Changes)
	}
	_ = ch
}

func TestAssertionOnSemanticChange(t *testing.T) {
	old := mustParse(t, baseOld)
	newDoc := strings.Replace(baseOld, "version: \"1.0.0\"", `version: "1.1.0"
compat:
  assertions:
    - element: auth.scheme
      reason: "scheme rotation covered by ADR-3"`, 1)
	newDoc = strings.Replace(newDoc, "scheme: bearer", "scheme: hmac", 1)
	new := mustParse(t, newDoc)
	cmp := Compare(old, new)
	if len(cmp.Changes) != 0 {
		t.Fatalf("asserted semantic change should be suppressed: %v", cmp.Changes)
	}
	if len(cmp.Suppressed) != 1 || cmp.Suppressed[0].Kind != "assertions" {
		t.Fatalf("expected 1 assertion suppression: %+v", cmp.Suppressed)
	}
}

func TestUnassertedSemanticChangeIsPotential(t *testing.T) {
	old := mustParse(t, baseOld)
	new := mustParse(t, strings.Replace(baseOld, "scheme: bearer", "scheme: hmac", 1))
	new.Version = "1.1.0"
	cmp := Compare(old, new)
	ch := changeByElement(cmp, "auth.scheme")
	if ch == nil {
		t.Fatal("expected auth.scheme change")
	}
	if ch.Finding.Status != analysis.StatusPotential {
		t.Fatalf("semantic change must be potential, got %s", ch.Finding.Status)
	}
}

func TestCompareDirectionFilter(t *testing.T) {
	old := mustParse(t, baseOld)
	newDoc := strings.Replace(baseOld, "version: \"1.0.0\"", `version: "2.0.0"
compat:
  breaking_changes:
    - element: request.CreateSession.field.ttl
      change: requiredness-changed
      direction: old-client/new-server
      reason: "only old clients are affected"`, 1)
	newDoc = strings.Replace(newDoc, "        required: false\n        default: 300",
		"        required: true\n        default: 60", 1)
	new := mustParse(t, newDoc)
	cmp := Compare(old, new)
	// The requiredness change only affects old-client/new-server and
	// is suppressed; the default change on the same element has a
	// different kind and is NOT suppressed.
	var kinds []string
	for _, ch := range cmp.Changes {
		if ch.Element == "request.CreateSession.field.ttl" {
			kinds = append(kinds, ch.Kind)
		}
	}
	if len(kinds) != 1 || kinds[0] != KindDefaultChanged {
		t.Fatalf("direction-filtered suppression wrong; remaining kinds %v", kinds)
	}
}

func TestMatrixUnit(t *testing.T) {
	v1 := mustParse(t, baseOld)
	v1.Version = "1.0.0"
	v2doc := strings.Replace(baseOld, "version: \"1.0.0\"", "version: \"2.0.0\"", 1)
	v2doc = strings.Replace(v2doc, "        required: false\n        default: 300",
		"        required: true\n        default: 300", 1)
	v2 := mustParse(t, v2doc)
	v3 := mustParse(t, strings.Replace(v2doc, "version: \"2.0.0\"", "version: \"3.0.0\"", 1))

	set := &SnapshotSet{
		Protocol: "demo",
		ByVersion: map[string]*Snapshot{
			"1.0.0": {Version: "1.0.0", Contract: v1},
			"2.0.0": {Version: "2.0.0", Contract: v2},
			"3.0.0": {Version: "3.0.0", Contract: v3},
		},
	}
	// Expect version 9.9.9 which has no snapshot -> missing diagnostic.
	res := EvaluateMatrix(set, []string{"1.0.0", "2.0.0", "3.0.0", "9.9.9"})
	if !hasDiag(res.Diagnostics, "9.9.9") {
		t.Fatalf("missing snapshot not reported: %v", res.Diagnostics)
	}
	if res.Cells["9.9.9"]["9.9.9"].Missing != true {
		t.Fatal("missing-version diagonal cell must be marked Missing")
	}

	// ttl optional->required between 1.0.0 and 2.0.0 affects
	// old-client/new-server only: cell (client=1.0.0, server=2.0.0)
	// incompatible; reverse cell compatible.
	if res.Cells["1.0.0"]["2.0.0"].Compatible {
		t.Fatal("old-client/new-server cell should be incompatible")
	}
	if !res.Cells["2.0.0"]["1.0.0"].Compatible {
		t.Fatal("new-client/old-server cell should be compatible")
	}
	// 2.0.0 vs 3.0.0 identical -> compatible both ways.
	if !res.Cells["2.0.0"]["3.0.0"].Compatible || !res.Cells["3.0.0"]["2.0.0"].Compatible {
		t.Fatal("identical versions must be compatible")
	}
	// Diagonal compatible.
	if !res.Cells["1.0.0"]["1.0.0"].Compatible {
		t.Fatal("diagonal cell must be compatible")
	}
	// Findings carry direction metadata.
	found := false
	for _, f := range res.Findings {
		if f.Metadata["directions"] == "old-client/new-server" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected directional finding in matrix results")
	}
}

func TestMatrixMissingSnapshotCellsSkipped(t *testing.T) {
	set := &SnapshotSet{ByVersion: map[string]*Snapshot{}}
	res := EvaluateMatrix(set, []string{"1.0.0", "2.0.0"})
	if len(res.Diagnostics) != 2 {
		t.Fatalf("expected 2 missing diagnostics, got %v", res.Diagnostics)
	}
	// Off-diagonal cells for missing versions are absent.
	if _, ok := res.Cells["1.0.0"]["2.0.0"]; ok {
		t.Fatal("cell for missing snapshot must not be evaluated")
	}
}
