package deps

import (
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// RequireEntry represents a single require statement in go.mod.
type RequireEntry struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect"`
	Line     int    `json:"line"`
}

// ReplaceEntry represents a single replace directive in go.mod.
type ReplaceEntry struct {
	OldPath    string `json:"old_path"`
	OldVersion string `json:"old_version,omitempty"`
	NewPath    string `json:"new_path"`
	NewVersion string `json:"new_version,omitempty"`
	Line       int    `json:"line"`
}

// GoMod represents parsed go.mod metadata.
type GoMod struct {
	ModulePath string         `json:"module_path"`
	GoVersion  string         `json:"go_version"`
	Requires   []RequireEntry `json:"requires"`
	Replaces   []ReplaceEntry `json:"replaces,omitempty"`
}

// SumEntry represents a single line in go.sum.
type SumEntry struct {
	Path    string `json:"path"`
	Version string `json:"version"`
	IsGoMod bool   `json:"is_go_mod"`
	Hash    string `json:"hash"`
	Line    int    `json:"line"`
}

// GoSum represents parsed go.sum entries.
type GoSum struct {
	Entries []SumEntry `json:"entries"`
}

// LicenseInfo holds the license classification for a dependency.
type LicenseInfo struct {
	Module      string `json:"module"`
	Version     string `json:"version"`
	License     string `json:"license"` // e.g. "MIT", "Apache-2.0", "GPL-3.0", "Unknown"
	LicenseFile string `json:"license_file,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
}

// LicensePolicy defines allow/deny rules for dependency licenses.
type LicensePolicy struct {
	Allow        []string `json:"allow,omitempty"`
	Deny         []string `json:"deny,omitempty"`
	AllowUnknown bool     `json:"allow_unknown"`
}

// DepReport provides a summary of module and license hygiene analysis.
type DepReport struct {
	IsGoModule    bool                   `json:"is_go_module"`
	ModulePath    string                 `json:"module_path,omitempty"`
	GoVersion     string                 `json:"go_version,omitempty"`
	DirectDeps    int                    `json:"direct_deps"`
	IndirectDeps  int                    `json:"indirect_deps"`
	TotalGoFiles  int                    `json:"total_go_files"`
	UnusedDeps    []string               `json:"unused_deps,omitempty"`
	Duplicates    []string               `json:"duplicates,omitempty"`
	Licenses      map[string]LicenseInfo `json:"licenses,omitempty"`
	FindingsCount int                    `json:"findings_count"`
	Findings      []review.Finding       `json:"findings,omitempty"`
}

// CheckOptions configures the dependency check execution.
type CheckOptions struct {
	Strict        bool
	Format        string
	LicensePolicy LicensePolicy
	VendorOnly    bool
}
