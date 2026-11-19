package analysis

import (
	"sort"
	"strings"
)

// CapabilitiesSchemaVersion is the schema version for machine-readable
// analyzer capability declarations.
const CapabilitiesSchemaVersion = "capabilities/1.0.0"

// AnalyzerCapability describes the semantic domain, language support,
// epistemic guarantees, and limitations of a single semantic analyzer.
type AnalyzerCapability struct {
	Name                  string   `json:"name"`
	Version               string   `json:"version"`
	Description           string   `json:"description"`
	Languages             []string `json:"languages"`
	RequiresContracts     bool     `json:"requires_contracts"`
	ProvidesEvidence      bool     `json:"provides_evidence"`
	EpistemicStatuses     []Status `json:"epistemic_statuses"`
	SupportedDomains      []string `json:"supported_domains"`
	UnsupportedConstructs []string `json:"unsupported_constructs"`
	SupportedBudgets      []string `json:"supported_budgets"`
}

var capabilitiesRegistry = map[string]AnalyzerCapability{
	"concurrency": {
		Name:              "concurrency",
		Version:           "1.0.0",
		Description:       "Shared state, check-then-act, and lock-order inversion analysis",
		Languages:         []string{"go"},
		RequiresContracts: false,
		ProvidesEvidence:  true,
		EpistemicStatuses: []Status{StatusPotential},
		SupportedDomains:  []string{"concurrency", "synchronization", "deadlock"},
		UnsupportedConstructs: []string{
			"unmodeled-channels", "sync-once-waitgroup", "dynamic-dispatch",
		},
		SupportedBudgets: []string{"max-steps", "timeout"},
	},
	"typestate": {
		Name:              "typestate",
		Version:           "1.0.0",
		Description:       "Affine and linear resource lifecycle verification",
		Languages:         []string{"go"},
		RequiresContracts: true,
		ProvidesEvidence:  true,
		EpistemicStatuses: []Status{StatusProven, StatusPotential},
		SupportedDomains:  []string{"lifecycle", "typestate", "resource-leak"},
		UnsupportedConstructs: []string{
			"unmodeled-reflection", "unresolved-dynamic-calls",
		},
		SupportedBudgets: []string{"max-transitions", "max-call-depth", "timeout"},
	},
	"statemachine": {
		Name:              "statemachine",
		Version:           "1.0.0",
		Description:       "Explicit state-machine contract transition invariant exploration",
		Languages:         []string{"go"},
		RequiresContracts: true,
		ProvidesEvidence:  true,
		EpistemicStatuses: []Status{StatusProven, StatusPotential},
		SupportedDomains:  []string{"state-machine", "protocol-invariants"},
		UnsupportedConstructs: []string{
			"bodiless-callees", "unbounded-loops",
		},
		SupportedBudgets: []string{
			"max-steps", "max-call-depth", "max-instances", "timeout",
		},
	},
	"flow": {
		Name:              "flow",
		Version:           "1.0.0",
		Description:       "Interprocedural value-flow and taint summary analysis",
		Languages:         []string{"go"},
		RequiresContracts: false,
		ProvidesEvidence:  true,
		EpistemicStatuses: []Status{StatusProven, StatusPotential},
		SupportedDomains:  []string{"taint", "dataflow", "place-facts"},
		UnsupportedConstructs: []string{
			"unsafe-pointers", "assembly-stubs",
		},
		SupportedBudgets: []string{"max-origins", "max-call-depth", "timeout"},
	},
	"authproto": {
		Name:              "authproto",
		Version:           "1.0.0",
		Description:       "Authentication protocol cryptographic property verification",
		Languages:         []string{"go"},
		RequiresContracts: true,
		ProvidesEvidence:  true,
		EpistemicStatuses: []Status{StatusProven, StatusPotential},
		SupportedDomains:  []string{"cryptography", "nonce-freshness", "replay-safety"},
		UnsupportedConstructs: []string{
			"custom-crypto-primitives", "unparsed-transcripts",
		},
		SupportedBudgets: []string{"timeout"},
	},
	"protocol": {
		Name:              "protocol",
		Version:           "1.0.0",
		Description:       "Network protocol framing and state sequencing checks",
		Languages:         []string{"go"},
		RequiresContracts: true,
		ProvidesEvidence:  true,
		EpistemicStatuses: []Status{StatusProven, StatusPotential},
		SupportedDomains:  []string{"network-protocol", "framing"},
		UnsupportedConstructs: []string{
			"raw-bytestreams",
		},
		SupportedBudgets: []string{"timeout"},
	},
}

// AllCapabilities returns a deterministically sorted slice of all registered analyzer
// capabilities.
func AllCapabilities() []AnalyzerCapability {
	names := make([]string, 0, len(capabilitiesRegistry))
	for n := range capabilitiesRegistry {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]AnalyzerCapability, 0, len(names))
	for _, n := range names {
		out = append(out, capabilitiesRegistry[n])
	}
	return out
}

// LookupCapability returns the capability declaration for the named analyzer, or false
// if not registered.
func LookupCapability(name string) (AnalyzerCapability, bool) {
	cap, ok := capabilitiesRegistry[strings.ToLower(strings.TrimSpace(name))]
	return cap, ok
}
