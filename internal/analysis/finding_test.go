package analysis

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

func validFinding() Finding {
	return Finding{
		RuleID:   "taint",
		Message:  "user input reaches SQL query",
		Severity: "high",
		Status:   StatusProven,
		Trace:    TraceSourceToSink,
		Spans: []Span{
			{File: "src/db.go", StartOffset: 10, StartLine: 3, EndLine: 3},
		},
		Evidence: []EvidenceStep{
			{
				Kind:   EvidenceSource,
				Entity: &EntityRef{Kind: EntityFunction, ID: "main.handle", Name: "handle"},
				Span:   Span{File: "src/api.go", StartLine: 12, EndLine: 12},
				Note:   "request.Body read",
			},
			{
				Kind: EvidenceSink,
				Span: Span{File: "src/db.go", StartOffset: 10, StartLine: 3, EndLine: 3},
				Note: "db.Query executed",
			},
		},
	}
}

func TestDeriveIDDeterministic(t *testing.T) {
	a := validFinding().EnsureID()
	b := validFinding().EnsureID()
	if a.ID == "" || len(a.ID) != 16 {
		t.Fatalf("expected 16-hex ID, got %q", a.ID)
	}
	if a.ID != b.ID {
		t.Fatalf("IDs differ across identical findings: %s vs %s", a.ID, b.ID)
	}
}

func TestDeriveIDStableAcrossNoteEdits(t *testing.T) {
	base := validFinding().EnsureID()
	edited := validFinding()
	edited.Evidence[0].Note = "completely reworded note"
	edited.Evidence[1].Metadata = map[string]string{"k": "v"}
	if edited.EnsureID().ID != base.ID {
		t.Fatal("note/metadata edits must not change the finding ID")
	}
}

func TestDeriveIDChangesWithEvidence(t *testing.T) {
	base := validFinding().EnsureID()

	otherSpan := validFinding()
	otherSpan.Evidence[1].Span.StartLine = 99
	if otherSpan.EnsureID().ID == base.ID {
		t.Fatal("evidence span change must change the ID")
	}

	reordered := validFinding()
	reordered.Evidence[0], reordered.Evidence[1] = reordered.Evidence[1], reordered.Evidence[0]
	if reordered.EnsureID().ID == base.ID {
		t.Fatal("evidence order change must change the ID")
	}

	otherRule := validFinding()
	otherRule.RuleID = "sqli"
	if otherRule.EnsureID().ID == base.ID {
		t.Fatal("rule change must change the ID")
	}
}

func TestAssignFindingIDsCollisionDeterministic(t *testing.T) {
	dup := validFinding()
	dup.Status = StatusPotential // avoid proven constraints; irrelevant to IDs
	dup.Truncation.Truncated = true
	dup.Truncation.Reasons = []string{"budget hit"}

	in := []Finding{dup, dup, dup}
	got1 := AssignFindingIDs(in)
	got2 := AssignFindingIDs(in)

	seen := map[string]bool{}
	for i, f := range got1 {
		if f.ID == "" {
			t.Fatalf("finding %d has empty ID", i)
		}
		if seen[f.ID] {
			t.Fatalf("duplicate ID %q after assignment", f.ID)
		}
		seen[f.ID] = true
		if f.ID != got2[i].ID {
			t.Fatalf("assignment not deterministic at %d: %s vs %s", i, f.ID, got2[i].ID)
		}
	}
}

func TestValidateProvenRequiresCompleteEvidence(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Finding)
		wantErr bool
	}{
		{"proven complete", func(f *Finding) {}, false},
		{"proven truncated flag", func(f *Finding) {
			f.Truncation.Truncated = true
		}, true},
		{"proven truncated reason", func(f *Finding) {
			f.Truncation.Reasons = []string{"max paths reached"}
		}, true},
		{"proven truncated budget", func(f *Finding) {
			f.Truncation.Budgets = []Budget{{Name: "max-paths", Limit: 10, Used: 10, Truncated: true}}
		}, true},
		{"proven no evidence", func(f *Finding) {
			f.Evidence = nil
		}, true},
		{"potential truncated ok", func(f *Finding) {
			f.Status = StatusPotential
			f.Truncation.Truncated = true
		}, false},
		{"unverified truncated ok", func(f *Finding) {
			f.Status = StatusUnverified
			f.Truncation.Truncated = true
			f.Truncation.Reasons = []string{"unsupported: cgo"}
		}, false},
		{"missing status", func(f *Finding) { f.Status = "" }, true},
		{"bad status", func(f *Finding) { f.Status = "maybe" }, true},
		{"missing spans", func(f *Finding) { f.Spans = nil }, true},
		{"empty primary file", func(f *Finding) { f.Spans[0].File = "" }, true},
		{"bad severity", func(f *Finding) { f.Severity = "catastrophic" }, true},
		{"bad confidence", func(f *Finding) { f.Confidence = "certain-ish" }, true},
		{"empty evidence step", func(f *Finding) {
			f.Evidence = append(f.Evidence, EvidenceStep{Kind: EvidenceNote})
		}, true},
		{"bad evidence kind", func(f *Finding) {
			f.Evidence[0].Kind = "magic"
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := validFinding()
			tc.mutate(&f)
			err := f.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("expected validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestMarshalJSONRejectsProvenTruncated(t *testing.T) {
	f := validFinding()
	f.Truncation.Truncated = true
	if _, err := json.Marshal(f); err == nil {
		t.Fatal("expected marshal of proven+truncated finding to fail")
	} else if !strings.Contains(err.Error(), "proven") {
		t.Fatalf("expected error to mention proven constraint, got: %v", err)
	}

	f.Status = StatusPotential
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("potential truncated finding should marshal: %v", err)
	}
	var back Finding
	// Unmarshal is permissive; validation is the consumer's job.
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("round-trip unmarshal failed: %v", err)
	}
	if back.Status != StatusPotential || !back.Truncation.Truncated {
		t.Fatalf("round-trip lost status/truncation: %+v", back)
	}
}

func TestSortFindingsDeterministic(t *testing.T) {
	mk := func(file string, line int, rule string) Finding {
		f := validFinding()
		f.Status = StatusPotential
		f.Truncation.Truncated = true
		f.RuleID = rule
		f.Spans = []Span{SingleLineSpan(file, line)}
		return f.EnsureID()
	}
	in := []Finding{
		mk("b.go", 2, "z-rule"),
		mk("a.go", 9, "a-rule"),
		mk("a.go", 3, "b-rule"),
		mk("a.go", 3, "a-rule"),
	}
	SortFindings(in)
	want := []string{"a.go:3:a-rule", "a.go:3:b-rule", "a.go:9:a-rule", "b.go:2:z-rule"}
	for i, f := range in {
		got := f.PrimarySpan().File + ":" + strconv.Itoa(f.PrimarySpan().StartLine) + ":" + f.RuleID
		if got != want[i] {
			t.Fatalf("position %d: got %s want %s", i, got, want[i])
		}
	}
}

func TestParseConfidence(t *testing.T) {
	cases := map[string]Confidence{
		"high":        ConfidenceHigh,
		"HIGH":        ConfidenceHigh,
		"certain":     ConfidenceHigh,
		"medium":      ConfidenceMedium,
		"likely":      ConfidenceMedium,
		"low":         ConfidenceLow,
		"unconfirmed": ConfidenceLow,
		"":            ConfidenceUnknown,
		"bogus":       ConfidenceUnknown,
	}
	for in, want := range cases {
		if got := ParseConfidence(in); got != want {
			t.Errorf("ParseConfidence(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseStatus(t *testing.T) {
	for _, s := range []string{"proven", "Potential", "UNVERIFIED"} {
		if st, ok := ParseStatus(s); !ok || !st.Valid() {
			t.Errorf("ParseStatus(%q) failed", s)
		}
	}
	if _, ok := ParseStatus("definitely"); ok {
		t.Error("ParseStatus accepted invalid value")
	}
}
