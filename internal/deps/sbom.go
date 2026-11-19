package deps

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SBOMFormat classifies the specification standard of an SBOM document.
type SBOMFormat string

const (
	FormatCycloneDX SBOMFormat = "CycloneDX"
	FormatSPDX      SBOMFormat = "SPDX"
)

// SBOMComponent represents a single component listed in an SBOM.
type SBOMComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

// SBOMReport is the normalized representation of an ingested SBOM.
type SBOMReport struct {
	Format      SBOMFormat      `json:"format"`
	SpecVersion string          `json:"spec_version"`
	Timestamp   time.Time       `json:"timestamp"`
	Components  []SBOMComponent `json:"components"`
}

// SBOMDiff captures the delta between an SBOM and project manifest.
type SBOMDiff struct {
	MissingInSBOM []string          `json:"missing_in_sbom,omitempty"`
	ExtraInSBOM   []string          `json:"extra_in_sbom,omitempty"`
	MismatchedVer map[string]string `json:"mismatched_versions,omitempty"`
}

type cycloneDXDoc struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Components  []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"components"`
}

type spdxDoc struct {
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		Name           string `json:"name"`
		VersionInfo    string `json:"versionInfo"`
		PackageComment string `json:"comment,omitempty"`
	} `json:"packages"`
}

func newSBOMReport(format SBOMFormat, specVer string, comps []SBOMComponent) *SBOMReport {
	return &SBOMReport{
		Format:      format,
		SpecVersion: specVer,
		Timestamp:   time.Now().UTC(),
		Components:  comps,
	}
}

// ParseSBOM auto-detects and parses either CycloneDX or SPDX JSON data.
func ParseSBOM(data []byte) (*SBOMReport, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty SBOM document")
	}

	var cDoc cycloneDXDoc
	if err := json.Unmarshal(data, &cDoc); err == nil && cDoc.BOMFormat == "CycloneDX" {
		var comps []SBOMComponent
		for _, c := range cDoc.Components {
			comps = append(comps, SBOMComponent{
				Name:    c.Name,
				Version: c.Version,
				PURL:    c.PURL,
			})
		}
		return newSBOMReport(FormatCycloneDX, cDoc.SpecVersion, comps), nil
	}

	var sDoc spdxDoc
	if err := json.Unmarshal(data, &sDoc); err == nil && strings.HasPrefix(sDoc.SPDXVersion, "SPDX-") {
		var comps []SBOMComponent
		for _, p := range sDoc.Packages {
			comps = append(comps, SBOMComponent{
				Name:    p.Name,
				Version: p.VersionInfo,
			})
		}
		return newSBOMReport(FormatSPDX, sDoc.SPDXVersion, comps), nil
	}

	return nil, fmt.Errorf("unrecognized SBOM format: document is neither CycloneDX nor SPDX JSON")
}

// CompareSBOMWithGoMod calculates discrepancies between an ingested SBOM and go.mod.
func CompareSBOMWithGoMod(sbom *SBOMReport, mod *GoMod) SBOMDiff {
	diff := SBOMDiff{
		MismatchedVer: make(map[string]string),
	}
	if sbom == nil || mod == nil {
		return diff
	}

	sbomMap := make(map[string]string)
	for _, c := range sbom.Components {
		sbomMap[c.Name] = c.Version
	}

	modMap := make(map[string]string)
	for _, req := range mod.Requires {
		modMap[req.Path] = req.Version
		sbomVer, exists := sbomMap[req.Path]
		if !exists {
			diff.MissingInSBOM = append(diff.MissingInSBOM, req.Path)
		} else if sbomVer != req.Version {
			diff.MismatchedVer[req.Path] = fmt.Sprintf("go.mod=%s vs sbom=%s", req.Version, sbomVer)
		}
	}

	for _, c := range sbom.Components {
		if _, exists := modMap[c.Name]; !exists {
			diff.ExtraInSBOM = append(diff.ExtraInSBOM, c.Name)
		}
	}

	sort.Strings(diff.MissingInSBOM)
	sort.Strings(diff.ExtraInSBOM)
	return diff
}

// ExportCycloneDX creates a minimal CycloneDX JSON document from a GoMod manifest.
func ExportCycloneDX(mod *GoMod) ([]byte, error) {
	if mod == nil {
		return nil, fmt.Errorf("cannot export nil GoMod")
	}

	doc := cycloneDXDoc{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
	}

	for _, req := range mod.Requires {
		doc.Components = append(doc.Components, struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
		}{
			Name:    req.Path,
			Version: req.Version,
			PURL:    fmt.Sprintf("pkg:golang/%s@%s", req.Path, req.Version),
		})
	}

	return json.MarshalIndent(doc, "", "  ")
}
