package statemachine

import (
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/semantic"
)

// bindForTest binds a contract against an empty program: sufficient
// for Runtime tests that never touch program entities.
func bindForTest(t *testing.T, c *Contract) *BoundContract {
	t.Helper()
	prog := &semantic.Program{}
	prog.Index()
	return Bind(prog, c)
}

// lifecycleContract is the fresh→consumed contract required by the
// issue: a second consumption is illegal.
const lifecycleContract = `
schema_version: statemachine/1
id: one-shot
states:
  - name: fresh
    initial: true
  - name: consumed
events:
  - name: consume
  - name: reset
transitions:
  - event: consume
    from: fresh
    to: consumed
  - event: reset
    from: any
    to: fresh
`

func mustContract(t *testing.T, src string) *Contract {
	t.Helper()
	c, err := ParseContract([]byte(src))
	if err != nil {
		t.Fatalf("ParseContract: %v", err)
	}
	for _, d := range c.Check() {
		if d.Severity == "error" {
			t.Fatalf("contract check: %v", d)
		}
	}
	return c
}

func TestRuntimeLifecycle(t *testing.T) {
	c := mustContract(t, lifecycleContract)
	// Bind requires a program for full binding, but Runtime only
	// needs the contract structure: build a minimal BoundContract via
	// Bind against an empty program.
	prog := &struct{ P interface{} }{}
	_ = prog
	bc := bindForTest(t, c)

	rt := bc.NewRuntime("")
	if rt.State() != "fresh" {
		t.Fatalf("initial state = %q", rt.State())
	}
	res := rt.Step(EventInput{Name: "consume"})
	if !res.Applied || res.Violation != nil {
		t.Fatalf("first consume should apply cleanly: %+v", res)
	}
	if rt.State() != "consumed" {
		t.Fatalf("state = %q", rt.State())
	}
	res = rt.Step(EventInput{Name: "consume"})
	if res.Applied || res.Violation == nil || res.Violation.Kind != ViolationIllegalTransition {
		t.Fatalf("second consume should be illegal: %+v", res)
	}
	res = rt.Step(EventInput{Name: "reset"})
	if !res.Applied || rt.State() != "fresh" {
		t.Fatalf("reset should return to fresh: %+v state=%q", res, rt.State())
	}
	res = rt.Step(EventInput{Name: "consume"})
	if !res.Applied {
		t.Fatalf("consume after reset should apply: %+v", res)
	}
}

// lockoutContract exercises counters, timestamps, expiry windows, and
// reset behavior — the second required invariant class.
const lockoutContract = `
schema_version: statemachine/1
id: lockout
states:
  - name: active
    initial: true
  - name: locked
events:
  - name: attempt
  - name: success
  - name: unlock
transitions:
  - event: attempt
    from: active
    to: active
    guard: "attempts < max_attempts"
    effects:
      - inc: attempts
      - set: last_attempt = arg[0]
  - event: attempt
    from: active
    to: locked
    guard: "attempts >= max_attempts"
    effects:
      - set: locked_until = arg[0] + window
  - event: success
    from: any
    to: active
    effects:
      - reset: [attempts, locked_until]
  - event: unlock
    from: locked
    to: active
    guard: "arg[0] >= locked_until"
    effects:
      - reset: [attempts, locked_until]
invariants:
  - expr: "attempts <= max_attempts"
    message: "too many attempts"
fields:
  - name: attempts
    kind: int
    initial: 0
  - name: max_attempts
    kind: int
    initial: 3
  - name: window
    kind: int
    initial: 60
  - name: last_attempt
    kind: int
    initial: 0
  - name: locked_until
    kind: int
    initial: 0
inputs:
  - name: now
    arg: 0
`

func TestRuntimeLockout(t *testing.T) {
	c := mustContract(t, lockoutContract)
	bc := bindForTest(t, c)
	rt := bc.NewRuntime("")

	attempt := func(now int64) StepResult {
		return rt.Step(EventInput{Name: "attempt", Args: []Value{Int(now)}})
	}
	// Three failed attempts reach the cap; the fourth locks.
	for i := int64(0); i < 3; i++ {
		res := attempt(100 + i)
		if !res.Applied {
			t.Fatalf("attempt %d should apply: %+v", i, res)
		}
	}
	if rt.State() != "active" || rt.Field("attempts") != Int(3) {
		t.Fatalf("after 3 attempts: state=%q attempts=%v", rt.State(), rt.Field("attempts"))
	}
	res := attempt(103)
	if !res.Applied || rt.State() != "locked" {
		t.Fatalf("attempt at cap should lock: %+v state=%q", res, rt.State())
	}
	if rt.Field("locked_until") != Int(163) {
		t.Fatalf("locked_until = %v, want 163", rt.Field("locked_until"))
	}
	// Attempt while locked is illegal.
	res = attempt(200)
	if res.Applied || res.Violation == nil {
		t.Fatalf("attempt while locked should be rejected: %+v", res)
	}
	// Unlock before expiry is illegal (guard false; locked_until=163).
	res = rt.Step(EventInput{Name: "unlock", Args: []Value{Int(120)}})
	if res.Applied {
		t.Fatalf("unlock at t=120 should be guarded (locked_until=163)")
	}
	// Unlock after expiry works and resets counters.
	res = rt.Step(EventInput{Name: "unlock", Args: []Value{Int(200)}})
	if !res.Applied || rt.State() != "active" {
		t.Fatalf("unlock at t=200 should apply: %+v", res)
	}
	if rt.Field("attempts") != Int(0) {
		t.Fatalf("attempts after reset = %v", rt.Field("attempts"))
	}
	// Success resets too.
	attempt(300)
	res = rt.Step(EventInput{Name: "success"})
	if !res.Applied || rt.Field("attempts") != Int(0) {
		t.Fatalf("success should reset attempts: %+v", res)
	}
}

func TestRuntimeUnknownGuardIsMayEnabled(t *testing.T) {
	c := mustContract(t, `
schema_version: statemachine/1
id: maybe
states:
  - name: a
    initial: true
  - name: b
events:
  - name: go
transitions:
  - event: go
    from: a
    to: b
    guard: "arg[0] > 0"
`)
	bc := bindForTest(t, c)
	rt := bc.NewRuntime("")
	res := rt.Step(EventInput{Name: "go"}) // no args → arg[0] unknown
	if !res.Applied || !res.GuardUnknown {
		t.Fatalf("unknown guard should be may-enabled: %+v", res)
	}
}

func TestRuntimeInvariantViolation(t *testing.T) {
	c := mustContract(t, `
schema_version: statemachine/1
id: inv
states:
  - name: a
    initial: true
events:
  - name: bump
transitions:
  - event: bump
    from: any
    to: a
    effects:
      - inc: n
invariants:
  - expr: "n <= 2"
    message: "n too large"
fields:
  - name: n
    kind: int
    initial: 0
`)
	bc := bindForTest(t, c)
	rt := bc.NewRuntime("")
	for i := 0; i < 3; i++ {
		res := rt.Step(EventInput{Name: "bump"})
		if i < 2 && res.Violation != nil {
			t.Fatalf("step %d should not violate: %+v", i, res)
		}
		if i == 2 {
			if res.Violation == nil || res.Violation.Kind != ViolationInvariant {
				t.Fatalf("step 2 should violate invariant: %+v", res)
			}
			if !strings.Contains(res.Violation.Message, "n too large") {
				t.Fatalf("violation message = %q", res.Violation.Message)
			}
		}
	}
}
