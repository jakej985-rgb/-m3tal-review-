package deps

import (
	"fmt"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// DriftKind classifies discrepancies between manifests and lockfiles.
type DriftKind string

const (
	DriftMissingLock      DriftKind = "missing_lockfile_entry"
	DriftOrphanLock       DriftKind = "orphan_lockfile_entry"
	DriftChecksumMismatch DriftKind = "checksum_mismatch"
)

// ManifestDrift represents a discrepancy between manifest declarations and lockfiles.
type ManifestDrift struct {
	Package string    `json:"package"`
	Kind    DriftKind `json:"kind"`
	File    string    `json:"file"`
	Line    int       `json:"line"`
	Message string    `json:"message"`
}

// SuspiciousKind classifies potential supply-chain risks in package definitions.
type SuspiciousKind string

const (
	SuspiciousTyposquat     SuspiciousKind = "potential_typosquat"
	SuspiciousInsecureProto SuspiciousKind = "insecure_transport_protocol"
	SuspiciousUnpinned      SuspiciousKind = "unpinned_version"
)

// SuspiciousIndicator records suspicious identity, origin, or pinning indicators.
type SuspiciousIndicator struct {
	Package        string         `json:"package"`
	Kind           SuspiciousKind `json:"kind"`
	Detail         string         `json:"detail"`
	Recommendation string         `json:"recommendation"`
}

// EpistemicClaim explicitly denotes the certainty tier of supply-chain data.
type EpistemicClaim string

const (
	ClaimVerifiedFact          EpistemicClaim = "verified_fact"
	ClaimExternalAdvisory      EpistemicClaim = "external_advisory"
	ClaimHeuristicReachability EpistemicClaim = "heuristic_reachability"
)

// SupplyChainAdvisory represents a vulnerability report with epistemic provenance.
type SupplyChainAdvisory struct {
	AdvisoryID    string         `json:"advisory_id"`
	Package       string         `json:"package"`
	AffectedRange string         `json:"affected_range"`
	FixedVersion  string         `json:"fixed_version,omitempty"`
	Claim         EpistemicClaim `json:"claim"`
	Source        string         `json:"source"`
	Timestamp     time.Time      `json:"timestamp"`
	Limitations   string         `json:"limitations,omitempty"`
}

var knownPopularModules = []string{
	"golang.org/x/crypto",
	"golang.org/x/net",
	"golang.org/x/sys",
	"golang.org/x/text",
	"github.com/gin-gonic/gin",
	"github.com/stretchr/testify",
	"github.com/google/uuid",
	"go.uber.org/zap",
}

// DetectGoModSumDrift checks for unpinned, missing, or mismatched entries between go.mod and go.sum.
func DetectGoModSumDrift(mod *GoMod, sum *GoSum) []ManifestDrift {
	if mod == nil {
		return nil
	}

	sumMap := make(map[string]bool)
	if sum != nil {
		for _, e := range sum.Entries {
			sumMap[e.Path] = true
		}
	}

	var drifts []ManifestDrift
	for _, req := range mod.Requires {
		if !sumMap[req.Path] {
			msg := fmt.Sprintf("Module %q is required in go.mod but missing in go.sum", req.Path)
			drifts = append(drifts, ManifestDrift{
				Package: req.Path,
				Kind:    DriftMissingLock,
				File:    "go.mod",
				Line:    req.Line,
				Message: msg,
			})
		}
	}
	return drifts
}

func checkTyposquat(pkg string) (bool, string) {
	lower := strings.ToLower(pkg)
	for _, popular := range knownPopularModules {
		if lower == popular {
			continue
		}
		// Typosquat checks: exact length diff <= 2 and close prefix/suffix
		if strings.HasPrefix(lower, "github.com/") && strings.HasPrefix(popular, "github.com/") {
			subPopular := strings.TrimPrefix(popular, "github.com/")
			subTarget := strings.TrimPrefix(lower, "github.com/")
			if subPopular != subTarget && strings.Contains(subTarget, subPopular[:len(subPopular)-1]) {
				return true, fmt.Sprintf("Module name resembles popular module %q", popular)
			}
		}
		if strings.Contains(lower, "githvb.com") {
			return true, "Domain contains typosquat permutation 'githvb.com' instead of 'github.com'"
		}
	}
	return false, ""
}

// DetectSuspiciousPackages scans requirements for typosquatting, insecure protocols, or unpinned versions.
func DetectSuspiciousPackages(requires []RequireEntry) []SuspiciousIndicator {
	var indicators []SuspiciousIndicator
	for _, req := range requires {
		if strings.HasPrefix(req.Path, "http://") {
			indicators = append(indicators, SuspiciousIndicator{
				Package:        req.Path,
				Kind:           SuspiciousInsecureProto,
				Detail:         "Package uses plaintext HTTP protocol for source resolution",
				Recommendation: "Upgrade repository URL to use encrypted HTTPS or SSH",
			})
		}

		if req.Version == "latest" || req.Version == "*" || req.Version == "master" {
			indicators = append(indicators, SuspiciousIndicator{
				Package:        req.Path,
				Kind:           SuspiciousUnpinned,
				Detail:         fmt.Sprintf("Package version %q is unpinned", req.Version),
				Recommendation: "Pin dependency to an exact semantic version or commit hash",
			})
		}

		if isSquat, detail := checkTyposquat(req.Path); isSquat {
			indicators = append(indicators, SuspiciousIndicator{
				Package:        req.Path,
				Kind:           SuspiciousTyposquat,
				Detail:         detail,
				Recommendation: "Verify that the dependency origin is genuine and not an attacker lookalike",
			})
		}
	}
	return indicators
}

// CorrelateAdvisoryWithReachability constructs an evidence-attributed finding for a supply chain advisory.
func CorrelateAdvisoryWithReachability(
	adv SupplyChainAdvisory,
	reach ReachabilityContext,
) review.Finding {
	sev := "high"
	conf := "medium"
	if reach.Status == ReachabilityReachable {
		sev = "critical"
		conf = "high"
	} else if reach.Status == ReachabilityUnreachable {
		sev = "medium"
		conf = "low"
	}

	msg := fmt.Sprintf(
		"Dependency %s is vulnerable to %s (%s). Reachability: %s (%s).",
		adv.Package, adv.AdvisoryID, adv.Claim, reach.Status, reach.Rationale,
	)

	return review.Finding{
		Rule:         "supply-chain-advisory",
		Category:     "security",
		Severity:     sev,
		Confidence:   conf,
		File:         "go.mod",
		Message:      msg,
		Remediation:  fmt.Sprintf("Upgrade %s to fixed version %s or newer", adv.Package, adv.FixedVersion),
		Reachability: string(reach.Status),
		AdvisoryID:   adv.AdvisoryID,
		Metadata: map[string]string{
			"advisory_source": adv.Source,
			"claim_tier":      string(adv.Claim),
			"timestamp":       adv.Timestamp.Format(time.RFC3339),
			"dependency_type": string(reach.DependencyType),
		},
	}
}
