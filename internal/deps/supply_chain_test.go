package deps

import (
	"strings"
	"testing"
	"time"
)

func TestDetectGoModSumDrift(t *testing.T) {
	mod := &GoMod{
		Requires: []RequireEntry{
			{Path: "github.com/gin-gonic/gin", Version: "v1.9.0", Line: 5},
			{Path: "github.com/google/uuid", Version: "v1.3.0", Line: 6},
		},
	}
	// go.sum only has gin, missing uuid
	sum := &GoSum{
		Entries: []SumEntry{
			{Path: "github.com/gin-gonic/gin", Version: "v1.9.0", Hash: "hash1"},
		},
	}

	drifts := DetectGoModSumDrift(mod, sum)
	if len(drifts) != 1 {
		t.Fatalf("expected 1 drift, got %d", len(drifts))
	}
	if drifts[0].Kind != DriftMissingLock || drifts[0].Package != "github.com/google/uuid" {
		t.Errorf("unexpected drift: %+v", drifts[0])
	}
}

func TestDetectSuspiciousPackages(t *testing.T) {
	reqs := []RequireEntry{
		{Path: "http://insecure.org/pkg", Version: "v1.0.0"},
		{Path: "github.com/google/uuid", Version: "latest"},
		{Path: "githvb.com/user/repo", Version: "v1.0.0"},
		{Path: "github.com/gin-gonic/gin", Version: "v1.9.0"}, // genuine
	}

	indicators := DetectSuspiciousPackages(reqs)
	if len(indicators) != 3 {
		t.Fatalf("expected 3 indicators, got %d", len(indicators))
	}

	kinds := make(map[SuspiciousKind]bool)
	for _, ind := range indicators {
		kinds[ind.Kind] = true
	}

	if !kinds[SuspiciousInsecureProto] {
		t.Errorf("expected SuspiciousInsecureProto")
	}
	if !kinds[SuspiciousUnpinned] {
		t.Errorf("expected SuspiciousUnpinned")
	}
	if !kinds[SuspiciousTyposquat] {
		t.Errorf("expected SuspiciousTyposquat")
	}
}

func TestCorrelateAdvisoryWithReachability(t *testing.T) {
	adv := SupplyChainAdvisory{
		AdvisoryID:    "GHSA-1234-abcd",
		Package:       "github.com/gin-gonic/gin",
		AffectedRange: "< v1.9.1",
		FixedVersion:  "v1.9.1",
		Claim:         ClaimExternalAdvisory,
		Source:        "GHSA",
		Timestamp:     time.Now().UTC(),
	}

	reach := ReachabilityContext{
		Package:        "github.com/gin-gonic/gin",
		DependencyType: DependencyTypeDirect,
		Status:         ReachabilityReachable,
		Rationale:      "Vulnerable handler directly invoked in main.go",
	}

	finding := CorrelateAdvisoryWithReachability(adv, reach)
	if finding.Severity != "critical" {
		t.Errorf("expected critical severity for reachable advisory, got %s", finding.Severity)
	}
	if !strings.Contains(finding.Message, "Reachability: Reachable") {
		t.Errorf("expected message to carry reachability evidence, got %s", finding.Message)
	}
	if finding.Metadata["claim_tier"] != string(ClaimExternalAdvisory) {
		t.Errorf("expected claim tier external_advisory")
	}
}

func TestSBOM_IngestAndCompare(t *testing.T) {
	cycloneDX := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"components": [
			{"name": "github.com/gin-gonic/gin", "version": "v1.9.0", "purl": "pkg:golang/github.com/gin-gonic/gin@v1.9.0"},
			{"name": "extra/package", "version": "v1.0.0"}
		]
	}`)

	report, err := ParseSBOM(cycloneDX)
	if err != nil {
		t.Fatalf("ParseSBOM CycloneDX failed: %v", err)
	}
	if report.Format != FormatCycloneDX || len(report.Components) != 2 {
		t.Fatalf("unexpected CycloneDX report: %+v", report)
	}

	mod := &GoMod{
		Requires: []RequireEntry{
			{Path: "github.com/gin-gonic/gin", Version: "v1.9.0"},
			{Path: "github.com/google/uuid", Version: "v1.3.0"},
		},
	}

	diff := CompareSBOMWithGoMod(report, mod)
	if len(diff.MissingInSBOM) != 1 || diff.MissingInSBOM[0] != "github.com/google/uuid" {
		t.Errorf("expected uuid missing in SBOM, got %v", diff.MissingInSBOM)
	}
	if len(diff.ExtraInSBOM) != 1 || diff.ExtraInSBOM[0] != "extra/package" {
		t.Errorf("expected extra/package extra in SBOM, got %v", diff.ExtraInSBOM)
	}

	exported, expErr := ExportCycloneDX(mod)
	if expErr != nil || len(exported) == 0 {
		t.Fatalf("ExportCycloneDX failed: %v", expErr)
	}
}
