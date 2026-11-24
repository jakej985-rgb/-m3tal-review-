package arch

import "time"

// EdgeLocation provides common coordinates for package-to-package edges.
type EdgeLocation struct {
	FromPkg string `json:"from_pkg"`
	ToPkg   string `json:"to_pkg"`
	File    string `json:"file"`
	Line    int    `json:"line"`
}

// ImportEdge represents an import relationship from one package to another.
type ImportEdge struct {
	EdgeLocation
	IsTest bool `json:"is_test"`
}

// PackageNode describes a package within the repository architecture.
type PackageNode struct {
	Path            string       `json:"path"`
	Name            string       `json:"name"`
	Files           []string     `json:"files"`
	ExportedSymbols []string     `json:"exported_symbols,omitempty"`
	Imports         []ImportEdge `json:"imports,omitempty"`
	ContentHash     string       `json:"content_hash,omitempty"`
}

// GraphDiagnostic records warnings, limits, or missing data during graph construction.
type GraphDiagnostic struct {
	Category string `json:"category"`
	Message  string `json:"message"`
	Path     string `json:"path,omitempty"`
}

// ArchitectureGraph holds the full repository package dependency model.
type ArchitectureGraph struct {
	ModulePath  string                  `json:"module_path"`
	Nodes       map[string]*PackageNode `json:"nodes"`
	Cycles      [][]string              `json:"cycles,omitempty"`
	Diagnostics []GraphDiagnostic       `json:"diagnostics,omitempty"`
	Truncated   bool                    `json:"truncated,omitempty"`
	BuiltAt     time.Time               `json:"built_at"`
}

// LayerRule defines allowed and forbidden import boundaries for a set of packages.
type LayerRule struct {
	Name             string   `json:"name" yaml:"name"`
	PackagePattern   string   `json:"package_pattern" yaml:"package_pattern"`
	ForbiddenImports []string `json:"forbidden_imports" yaml:"forbidden_imports"`
	Description      string   `json:"description,omitempty" yaml:"description,omitempty"`
}

// ArchitecturePolicy defines versioned architectural constraints for the repository.
type ArchitecturePolicy struct {
	Version string      `json:"version" yaml:"version"`
	Rules   []LayerRule `json:"rules" yaml:"rules"`
}

// BoundaryViolation represents an illegal architectural edge violating a policy rule.
type BoundaryViolation struct {
	EdgeLocation
	RuleName string `json:"rule_name"`
	Message  string `json:"message"`
}

// ImpactRelation specifies the epistemic certainty of a change-impact dependency edge.
type ImpactRelation string

const (
	ImpactExact     ImpactRelation = "exact"     // Directly imports or tests the changed unit
	ImpactHeuristic ImpactRelation = "heuristic" // Indirect transitive dependency closure
)

// ImpactNode represents one affected package in a change-impact blast radius.
type ImpactNode struct {
	Package  string         `json:"package"`
	Relation ImpactRelation `json:"relation"`
	Distance int            `json:"distance"`
	Via      string         `json:"via,omitempty"`
}

// ImpactEstimate summarizes the blast radius of a proposed set of changes.
type ImpactEstimate struct {
	ChangedFiles        []string     `json:"changed_files"`
	ChangedPackages     []string     `json:"changed_packages"`
	DirectlyAffected    []ImpactNode `json:"directly_affected"`
	TransitivelyAffect  []ImpactNode `json:"transitively_affected"`
	TotalAffectedCount  int          `json:"total_affected_count"`
	AffectedAnalyzers   []string     `json:"affected_analyzers,omitempty"`
	AffectedTestTargets []string     `json:"affected_test_targets,omitempty"`
}
