package authproto

import (
	"context"
	"strings"
	"testing"
)

func mustContract(t *testing.T, doc string) *Contract {
	t.Helper()
	c, err := ParseContract([]byte(doc))
	if err != nil {
		t.Fatalf("ParseContract: %v", err)
	}
	return c
}

func ruleIDs(res *Result) map[string]int {
	out := make(map[string]int)
	for _, f := range res.Findings {
		out[f.RuleID]++
	}
	return out
}

const minimalSafe = `
schema_version: authproto/1
id: t
parties: [client, server]
transcript:
  - name: challenge
    from: server
    to: client
    fields:
      - name: server_nonce
        kind: challenge
        fresh: true
        single_use: true
  - name: response
    from: client
    to: server
    fields:
      - name: proof
        kind: proof
        verifier: {type: server-secret}
        covers: [server_nonce]
`

func TestParseRejectsWrongSchema(t *testing.T) {
	if _, err := ParseContract([]byte("schema_version: authproto/2\n")); err == nil {
		t.Fatal("expected error for wrong schema_version")
	}
}

func TestCheckValidation(t *testing.T) {
	c := mustContract(t, `
schema_version: authproto/1
transcript:
  - name: s1
    from: client
    to: server
    fields:
      - name: a
        kind: bogus-kind
      - name: a
        kind: nonce
      - name: p
        kind: proof
        covers: [missing]
`)
	diags := c.Check()
	var sawKind, sawDup, sawCovers bool
	for _, d := range diags {
		if strings.Contains(d.Message, "unknown kind") {
			sawKind = true
		}
		if strings.Contains(d.Message, "duplicate field name") {
			sawDup = true
		}
		if strings.Contains(d.Message, "covers references undeclared field") {
			sawCovers = true
		}
	}
	if !sawKind || !sawDup || !sawCovers {
		t.Fatalf("missing expected diagnostics: kind=%v dup=%v covers=%v\n%v", sawKind, sawDup, sawCovers, diags)
	}
}

func TestSafeModelProducesNoFindings(t *testing.T) {
	c := mustContract(t, minimalSafe)
	res, err := Analyze(context.Background(), []*Contract{c}, Options{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %v", res.Findings)
	}
}

func TestNoProofIsUnverifiedNotSilent(t *testing.T) {
	c := mustContract(t, `
schema_version: authproto/1
transcript:
  - name: hello
    from: client
    to: server
    fields:
      - name: blob
        kind: other
`)
	res, _ := Analyze(context.Background(), []*Contract{c}, Options{})
	ids := ruleIDs(res)
	if ids["authproto.unmodeled"] != 1 {
		t.Fatalf("expected one unmodeled finding, got %v", res.Findings)
	}
	f := res.Findings[0]
	if f.Status != "unverified" {
		t.Fatalf("unmodeled finding status = %q, want unverified", f.Status)
	}
}

func TestPasswordDerivedKeyFlagged(t *testing.T) {
	c := mustContract(t, `
schema_version: authproto/1
transcript:
  - name: login
    from: client
    to: server
    fields:
      - name: pw
        kind: password
        secret: true
      - name: session_key
        kind: key
        derived_from: [pw]
`)
	res, _ := Analyze(context.Background(), []*Contract{c}, Options{})
	ids := ruleIDs(res)
	// No proof field → unmodeled; the password-derived key is still
	// flagged for offline-guessing exposure.
	if ids["authproto.unmodeled"] != 1 {
		t.Fatalf("expected unmodeled finding, got %v", res.Findings)
	}
	if ids["authproto.offline-guessing"] != 1 {
		t.Fatalf("expected offline-guessing finding for derived key, got %v", res.Findings)
	}
}

func TestPasswordProofOfflineGuessingMetadata(t *testing.T) {
	c := mustContract(t, strings.Replace(minimalSafe,
		"type: server-secret", "type: password", 1))
	res, _ := Analyze(context.Background(), []*Contract{c}, Options{})
	ids := ruleIDs(res)
	if ids["authproto.offline-guessing"] != 1 {
		t.Fatalf("expected offline-guessing finding, got %v", res.Findings)
	}
	f := res.Findings[0]
	if f.Status != "potential" {
		t.Fatalf("model finding status = %q, want potential", f.Status)
	}
	if f.Metadata["attacker_capabilities"] == "" {
		t.Fatal("finding lacks attacker_capabilities metadata")
	}
	if f.Metadata["not_proven"] == "" {
		t.Fatal("finding lacks not_proven metadata")
	}
	if len(f.Evidence) == 0 {
		t.Fatal("finding lacks protocol trace evidence")
	}
}

func TestReplayNoServerChallenge(t *testing.T) {
	// Proof covers only a client nonce: no fresh verifier-issued value.
	c := mustContract(t, `
schema_version: authproto/1
transcript:
  - name: response
    from: client
    to: server
    fields:
      - name: client_nonce
        kind: nonce
        fresh: true
      - name: proof
        kind: proof
        verifier: {type: server-secret}
        covers: [client_nonce]
`)
	res, _ := Analyze(context.Background(), []*Contract{c}, Options{})
	ids := ruleIDs(res)
	if ids["authproto.replay"] != 1 {
		t.Fatalf("expected replay finding, got %v", res.Findings)
	}
	// client_nonce is a binding field uncovered? It IS covered. No
	// server challenge exists, so no binding finding either.
}

func TestEvaluateNilProgram(t *testing.T) {
	c := mustContract(t, minimalSafe)
	res, err := Evaluate(context.Background(), nil, []*Contract{c}, Options{})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %v", res.Findings)
	}
}
