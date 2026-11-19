package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type goldenCase struct {
	name          string
	file          string
	expectVersion string
	expectPassed  bool
	hasAnalysis   bool
	hasCoverage   bool
	hasAttest     bool
}

func verifyGoldenFixture(t *testing.T, fixtureDir string, tc goldenCase) {
	t.Helper()
	path := filepath.Join(fixtureDir, tc.file)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", tc.file, err)
	}

	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("failed to unmarshal fixture %s: %v", tc.file, err)
	}

	if rep.SchemaVersion != tc.expectVersion {
		t.Errorf("schema_version mismatch: got %q, want %q", rep.SchemaVersion, tc.expectVersion)
	}
	if rep.Passed != tc.expectPassed {
		t.Errorf("passed mismatch: got %v, want %v", rep.Passed, tc.expectPassed)
	}
	if (rep.Analysis != nil) != tc.hasAnalysis {
		t.Errorf("hasAnalysis mismatch: got %v, want %v", rep.Analysis != nil, tc.hasAnalysis)
	}
	if (rep.Coverage != nil) != tc.hasCoverage {
		t.Errorf("hasCoverage mismatch: got %v, want %v", rep.Coverage != nil, tc.hasCoverage)
	}
	if (rep.Attestation != nil) != tc.hasAttest {
		t.Errorf("hasAttest mismatch: got %v, want %v", rep.Attestation != nil, tc.hasAttest)
	}

	res := ValidateReport(rep, path)
	if !res.Valid {
		t.Fatalf("validation unexpectedly failed for %s: %+v", tc.file, res.Errors)
	}

	verifyRoundtrip(t, tc.file, rep)
}

func verifyRoundtrip(t *testing.T, file string, rep Report) {
	t.Helper()
	marshaled, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("failed to re-marshal report %s: %v", file, err)
	}
	var repRoundtrip Report
	if err := json.Unmarshal(marshaled, &repRoundtrip); err != nil {
		t.Fatalf("failed to unmarshal roundtrip %s: %v", file, err)
	}

	if repRoundtrip.RunID != rep.RunID {
		t.Errorf("roundtrip run_id mismatch: %s vs %s", repRoundtrip.RunID, rep.RunID)
	}
	if repRoundtrip.SchemaVersion != rep.SchemaVersion {
		t.Errorf("roundtrip schema_version mismatch: %s vs %s", repRoundtrip.SchemaVersion, rep.SchemaVersion)
	}
	if len(repRoundtrip.Findings) != len(rep.Findings) {
		t.Errorf("roundtrip findings length mismatch: %d vs %d", len(repRoundtrip.Findings), len(rep.Findings))
	}
}

func loadReportFixture(t *testing.T, file string) Report {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "report-fixtures", file)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read failed for %s: %v", file, err)
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal failed for %s: %v", file, err)
	}
	return rep
}

func TestReportSchemaCompatibility_GoldenFixtures(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "testdata", "report-fixtures")

	fixtures := []goldenCase{
		{
			name:          "v1_golden",
			file:          "v1_golden.json",
			expectVersion: "1.0.0",
			expectPassed:  false,
			hasAnalysis:   true,
			hasCoverage:   true,
			hasAttest:     true,
		},
		{
			name:          "legacy_unversioned",
			file:          "legacy_unversioned.json",
			expectVersion: "",
			expectPassed:  true,
			hasAnalysis:   false,
			hasCoverage:   false,
			hasAttest:     false,
		},
		{
			name:          "degraded_semantic",
			file:          "degraded_semantic.json",
			expectVersion: "1.0.0",
			expectPassed:  false,
			hasAnalysis:   true,
			hasCoverage:   false,
			hasAttest:     false,
		},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			verifyGoldenFixture(t, fixtureDir, tc)
		})
	}
}

func TestReportSchemaCompatibility_SemanticDegradationSurvival(t *testing.T) {
	rep := loadReportFixture(t, "degraded_semantic.json")

	if rep.Analysis == nil {
		t.Fatal("expected analysis section to be non-nil")
	}
	if rep.Analysis.Status != "degraded" {
		t.Errorf("expected status degraded, got %q", rep.Analysis.Status)
	}
	if !rep.Analysis.Truncated {
		t.Errorf("expected truncated to be true")
	}
	if len(rep.Analysis.Diagnostics) != 1 {
		t.Fatalf("expected 1 diagnostic, got %d", len(rep.Analysis.Diagnostics))
	}
	if rep.Analysis.Diagnostics[0].Category != "build" {
		t.Errorf("expected diagnostic category 'build', got %q", rep.Analysis.Diagnostics[0].Category)
	}
}

func TestReportSchemaCompatibility_CoverageExclusionSurvival(t *testing.T) {
	rep := loadReportFixture(t, "v1_golden.json")

	if rep.Coverage == nil {
		t.Fatal("expected coverage to be non-nil")
	}
	if rep.Coverage.Complete {
		t.Errorf("expected incomplete coverage")
	}
	if len(rep.Coverage.Exclusions) != 1 {
		t.Fatalf("expected 1 exclusion, got %d", len(rep.Coverage.Exclusions))
	}
	if rep.Coverage.Exclusions[0].Reason != "vendor_directory" {
		t.Errorf("expected exclusion reason vendor_directory, got %q", rep.Coverage.Exclusions[0].Reason)
	}
}
