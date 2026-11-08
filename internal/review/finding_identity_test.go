package review

import (
	"testing"
)

func TestFindingIdentityResilientToLineMovement(t *testing.T) {
	f1 := Finding{
		Rule:     "hardcoded-secret",
		File:     "internal/auth/login.go",
		Line:     15,
		Message:  "Possible hardcoded credentials detected",
		Category: "security",
	}

	f2 := f1
	f2.Line = 92 // Line moved due to code insertion above

	id1 := FindingID(f1)
	id2 := FindingID(f2)

	if id1 != id2 {
		t.Fatalf("finding identity changed when line moved: %q vs %q", id1, id2)
	}

	// Verify line number is preserved as location metadata
	if f1.Line != 15 || f2.Line != 92 {
		t.Fatalf("line numbers were altered: f1=%d, f2=%d", f1.Line, f2.Line)
	}
}

func TestFindingIdentityPathNormalization(t *testing.T) {
	paths := []string{
		"internal/auth/login.go",
		"./internal/auth/login.go",
		"internal/auth/../auth/login.go",
		"internal\\auth\\login.go",
	}

	var firstID string
	for i, p := range paths {
		f := Finding{
			Rule:     "timing-attack",
			File:     p,
			Line:     30,
			Message:  "Timing-unsafe comparison",
			Category: "security",
		}
		id := FindingID(f)
		if i == 0 {
			firstID = id
		} else if id != firstID {
			t.Fatalf("path variant %q produced ID %q, want %q", p, id, firstID)
		}
	}
}

func TestFindingIdentitySubstantiveSignature(t *testing.T) {
	f1 := Finding{
		Rule:    "resource-leak",
		File:    "cmd/main.go",
		Line:    10,
		Message: "cmd/main.go:10: file descriptor not closed",
	}
	f2 := Finding{
		Rule:    "resource-leak",
		File:    "cmd/main.go",
		Line:    45,
		Message: "cmd/main.go:45: file descriptor not closed",
	}

	id1 := FindingID(f1)
	id2 := FindingID(f2)

	if id1 != id2 {
		t.Fatalf("volatile line number in message broke identity: %q vs %q", id1, id2)
	}
}

func TestAssignFindingIDsDeterministicDuplicates(t *testing.T) {
	findings := []Finding{
		{
			Rule:     "todo-marker",
			File:     "pkg/worker.go",
			Line:     20,
			Message:  "TODO: implement retry",
			Category: "slop",
		},
		{
			Rule:     "todo-marker",
			File:     "pkg/worker.go",
			Line:     65,
			Message:  "TODO: implement retry",
			Category: "slop",
		},
	}

	assigned := AssignFindingIDs(findings)
	if len(assigned) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(assigned))
	}
	if assigned[0].ID == "" || assigned[1].ID == "" {
		t.Fatalf("IDs not assigned: %+v", assigned)
	}
	if assigned[0].ID == assigned[1].ID {
		t.Fatalf("duplicate findings received identical IDs: %q", assigned[0].ID)
	}

	// Verify line movement does not change duplicate identities
	moved := []Finding{
		{
			Rule:     "todo-marker",
			File:     "pkg/worker.go",
			Line:     25, // moved from 20
			Message:  "TODO: implement retry",
			Category: "slop",
		},
		{
			Rule:     "todo-marker",
			File:     "pkg/worker.go",
			Line:     70, // moved from 65
			Message:  "TODO: implement retry",
			Category: "slop",
		},
	}
	assignedMoved := AssignFindingIDs(moved)
	if assignedMoved[0].ID != assigned[0].ID {
		t.Fatalf("first duplicate ID changed after line move: %q vs %q", assignedMoved[0].ID, assigned[0].ID)
	}
	if assignedMoved[1].ID != assigned[1].ID {
		t.Fatalf("second duplicate ID changed after line move: %q vs %q", assignedMoved[1].ID, assigned[1].ID)
	}

	// Verify duplicate findings with identical pre-existing IDs are disambiguated
	samePreexisting := []Finding{
		{
			ID:      "shared-hash",
			Rule:    "todo-marker",
			File:    "pkg/worker.go",
			Line:    10,
			Message: "TODO: implement retry",
		},
		{
			ID:      "shared-hash",
			Rule:    "todo-marker",
			File:    "pkg/worker.go",
			Line:    50,
			Message: "TODO: implement retry",
		},
	}
	reassigned := AssignFindingIDs(samePreexisting)
	if reassigned[0].ID == reassigned[1].ID {
		t.Fatalf("pre-existing identical IDs were not disambiguated: %q", reassigned[0].ID)
	}
}

func TestFindingIdentityVariousLineMessageFormats(t *testing.T) {
	cases := []struct {
		name string
		msg1 string
		msg2 string
	}{
		{"colon line and col", "cmd/main.go:10:25: error", "cmd/main.go:45:25: error"},
		{"colon line only", "cmd/main.go:10 error", "cmd/main.go:45 error"},
		{"paren line", "syntax error (line 12)", "syntax error (line 88)"},
		{"on line", "syntax error on line 42", "syntax error on line 105"},
		{"at line col", "error at line 15, col 4: bad token", "error at line 99, col 4: bad token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f1 := Finding{Rule: "test-rule", File: "a.go", Line: 10, Message: tc.msg1}
			f2 := Finding{Rule: "test-rule", File: "a.go", Line: 99, Message: tc.msg2}
			if FindingID(f1) != FindingID(f2) {
				t.Fatalf("FindingID mismatch for %s: %q vs %q", tc.name, FindingID(f1), FindingID(f2))
			}
		})
	}
}
