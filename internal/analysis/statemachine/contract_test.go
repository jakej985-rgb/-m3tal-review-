package statemachine

import (
	"strings"
	"testing"
)

func TestParseContractMinimal(t *testing.T) {
	c, err := ParseContract([]byte(`
schema_version: statemachine/1
id: tok
states:
  - name: fresh
    initial: true
  - name: consumed
events:
  - name: consume
transitions:
  - event: consume
    from: fresh
    to: consumed
`))
	if err != nil {
		t.Fatalf("ParseContract: %v", err)
	}
	if c.ID != "tok" {
		t.Fatalf("ID = %q", c.ID)
	}
	diags := c.Check()
	for _, d := range diags {
		if d.Severity == "error" {
			t.Fatalf("unexpected error diagnostic: %v", d)
		}
	}
}

func TestParseContractBadVersion(t *testing.T) {
	_, err := ParseContract([]byte(`schema_version: statemachine/99`))
	if err == nil || !strings.Contains(err.Error(), "schema_version") {
		t.Fatalf("expected schema version error, got %v", err)
	}
}

func TestCheckReportsProblems(t *testing.T) {
	c, err := ParseContract([]byte(`
schema_version: statemachine/1
states:
  - name: a
    initial: true
  - name: a
  - name: b
events:
  - name: go
transitions:
  - event: missing
    from: nowhere
    to: b
    guard: "attempts <"
invariants:
  - expr: "bogus_field > 1"
`))
	if err != nil {
		t.Fatalf("ParseContract: %v", err)
	}
	diags := c.Check()
	if len(diags) == 0 {
		t.Fatal("expected diagnostics")
	}
	var sawDup, sawUnknownEvent, sawBadGuard, sawUndeclared bool
	for _, d := range diags {
		msg := d.Message
		switch {
		case strings.Contains(msg, "duplicate state"):
			sawDup = true
		case strings.Contains(msg, "unknown event"):
			sawUnknownEvent = true
		case strings.Contains(msg, "guard expression"):
			sawBadGuard = true
		case strings.Contains(msg, "undeclared name"):
			sawUndeclared = true
		}
	}
	for name, ok := range map[string]bool{
		"duplicate state": sawDup, "unknown event": sawUnknownEvent,
		"bad guard": sawBadGuard, "undeclared": sawUndeclared,
	} {
		if !ok {
			t.Fatalf("missing expected diagnostic %q; got %v", name, diags)
		}
	}
}

func TestCheckExactlyOneInitial(t *testing.T) {
	c, err := ParseContract([]byte(`
schema_version: statemachine/1
states:
  - name: a
  - name: b
    initial: true
  - name: c
    initial: true
events:
  - name: e
transitions:
  - event: e
    from: any
    to: b
`))
	if err != nil {
		t.Fatal(err)
	}
	diags := c.Check()
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "exactly one initial") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected initial-state diagnostic; got %v", diags)
	}
}
