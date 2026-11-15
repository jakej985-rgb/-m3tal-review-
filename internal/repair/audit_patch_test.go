package repair

import (
	"strings"
	"testing"
)

// Regression (was audit repro): GenerateUnifiedDiff output must be
// applicable by ApplyPatchToContent for every content pair, including
// trailing-newline transitions, empty files, and CRLF input.
func TestAuditPatchRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		orig string
		prop string
	}{
		{"single line change", "a\nb\nc\n", "a\nB\nc\n"},
		{"two distant hunks", strings.Repeat("x\n", 50) + "OLD1\n" + strings.Repeat("y\n", 50) + "OLD2\n" + strings.Repeat("z\n", 50),
			strings.Repeat("x\n", 50) + "NEW1\n" + strings.Repeat("y\n", 50) + "NEW2\n" + strings.Repeat("z\n", 50)},
		{"no trailing newline orig", "a\nb", "a\nc"},
		{"no trailing newline both", "a\nb", "a\nc"},
		{"add trailing newline", "a\nb", "a\nb\n"},
		{"remove trailing newline", "a\nb\n", "a\nb"},
		{"empty to content", "", "hello\n"},
		{"content to empty", "hello\n", ""},
		{"insert at top", "b\nc\n", "a\nb\nc\n"},
		{"delete at top", "a\nb\nc\n", "b\nc\n"},
		{"crlf input", "a\r\nb\r\n", "a\r\nB\r\n"},
		{"crlf no trailing newline", "a\r\nb", "a\r\nc"},
		{"only newline added", "a", "a\n"},
		{"only newline removed", "a\n", "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			patch := GenerateUnifiedDiff("f.txt", tc.orig, tc.prop)
			if patch == "" && tc.orig != tc.prop {
				t.Fatalf("empty patch for differing content")
			}
			got, err := ApplyPatchToContent(tc.orig, patch)
			if err != nil {
				t.Fatalf("apply failed: %v\npatch:\n%s", err, patch)
			}
			if got != tc.prop {
				t.Fatalf("mismatch:\ngot:  %q\nwant: %q\npatch:\n%s", got, tc.prop, patch)
			}
		})
	}
}

// Regression (was audit repro): "\ No newline at end of file" markers must
// be honored per-side and only at end of file.
func TestAuditPatchNoNewlineMarker(t *testing.T) {
	// Old file lacks trailing newline; new file gains one.
	patch := "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n\\ No newline at end of file\n+b\n"
	got, err := ApplyPatchToContent("a\nb", patch)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if got != "a\nb\n" {
		t.Fatalf("got %q, want %q", got, "a\nb\n")
	}

	// New file loses its trailing newline.
	patch2 := "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n+b\n\\ No newline at end of file\n"
	got2, err := ApplyPatchToContent("a\nb\n", patch2)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if got2 != "a\nb" {
		t.Fatalf("got %q, want %q", got2, "a\nb")
	}

	// Marker not at end of file must be rejected.
	bad := "--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n a\n-b\n\\ No newline at end of file\n+c\n d\n"
	if _, err := ApplyPatchToContent("a\nb\nd\n", bad); err == nil {
		t.Fatal("expected error for mid-file newline marker")
	}
}

// Regression (was audit repro): malformed patches must error in the
// applier, matching what ValidatePatch rejects — the two parsers must not
// disagree on validity.
func TestAuditPatchMalformed(t *testing.T) {
	cases := []struct {
		name  string
		patch string
	}{
		{"context mismatch", "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-x\n+y\n"},
		{"hunk count mismatch", "--- a/f\n+++ b/f\n@@ -1,5 +1,5 @@\n a\n-b\n+c\n"},
		{"bad prefix", "--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n?weird\n"},
		{"overlapping hunks", "--- a/f\n+++ b/f\n@@ -1,2 +1,2 @@\n a\n-b\n+c\n@@ -1,2 +1,2 @@\n a\n-d\n+e\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verr := ValidatePatch(tc.patch, "f")
			_, aerr := ApplyPatchToContent("a\nb\n", tc.patch)
			if verr == nil && aerr == nil {
				t.Fatalf("malformed patch accepted by both validator and applier:\n%s", tc.patch)
			}
			// The applier must never silently accept what the validator
			// rejects.
			if verr != nil && aerr == nil {
				t.Fatalf("validator rejected but applier accepted:\n%s", tc.patch)
			}
		})
	}
}
