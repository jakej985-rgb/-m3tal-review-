package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// Dependency vulnerability scanning via the public OSV API. Opt-in only
// (--vuln-scan): performs a network request, so it is never enabled by
// default. Manifests parsed: go.mod, package.json, requirements.txt at
// the repository root.

const (
	osvQueryBatchURL = "https://api.osv.dev/v1/querybatch"
	maxVulnDeps      = 300
	maxVulnFindings  = 200
)

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvQuery struct {
	Pkg     osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvVuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

type osvResult struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvResponse struct {
	Results []osvResult `json:"results"`
}

// depRef is one parsed dependency: name, ecosystem, version, manifest file.
type depRef struct {
	Name      string
	Ecosystem string
	Version   string
	File      string
}

var (
	gomodRequireRe = regexp.MustCompile(`^\s*([A-Za-z0-9_.\-~/]+)\s+(v?\d+\.\d+\.\d+[^\s]*)`)
	reqPinRe       = regexp.MustCompile(`^([A-Za-z0-9_.\-]+)==\s*([^\s;]+)`)
	npmVersionRe   = regexp.MustCompile(`^[\^~>=\s]*(v?\d+\.\d+\.\d+[^\s,"]*)`)
)

// collectDependencies parses supported manifests under root and returns
// pinned dependency references. Missing manifests are ignored; parse
// failures are non-fatal (that file simply contributes no deps).
func collectDependencies(root string) []depRef {
	var deps []depRef
	for _, rel := range []string{"go.mod", "package.json", "requirements.txt"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 4<<20 {
			continue
		}
		switch rel {
		case "go.mod":
			deps = append(deps, parseGoMod(string(data), rel)...)
		case "package.json":
			deps = append(deps, parsePackageJSON(string(data), rel)...)
		case "requirements.txt":
			deps = append(deps, parseRequirements(string(data), rel)...)
		}
	}
	sort.Slice(deps, func(i, j int) bool {
		if deps[i].File != deps[j].File {
			return deps[i].File < deps[j].File
		}
		if deps[i].Name != deps[j].Name {
			return deps[i].Name < deps[j].Name
		}
		return deps[i].Version < deps[j].Version
	})
	if len(deps) > maxVulnDeps {
		deps = deps[:maxVulnDeps]
	}
	return deps
}

func parseGoMod(content, file string) []depRef {
	var deps []depRef
	inRequire := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire {
			if line == ")" {
				inRequire = false
				continue
			}
		} else if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
		}
		if m := gomodRequireRe.FindStringSubmatch(line); m != nil {
			version := strings.TrimSuffix(m[2], "// indirect")
			version = strings.Fields(version)[0]
			deps = append(deps, depRef{Name: m[1], Ecosystem: "Go", Version: version, File: file})
		}
	}
	return deps
}

func parsePackageJSON(content, file string) []depRef {
	var pkg struct {
		Deps    map[string]string `json:"dependencies"`
		DevDeps map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil
	}
	var deps []depRef
	for _, table := range []map[string]string{pkg.Deps, pkg.DevDeps} {
		for name, rangeSpec := range table {
			m := npmVersionRe.FindStringSubmatch(strings.TrimSpace(rangeSpec))
			if m == nil {
				continue // ranges/workspaces/git URLs can't be pinned for OSV
			}
			deps = append(deps, depRef{Name: name, Ecosystem: "npm", Version: strings.TrimPrefix(m[1], "v"), File: file})
		}
	}
	return deps
}

func parseRequirements(content, file string) []depRef {
	var deps []depRef
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if m := reqPinRe.FindStringSubmatch(line); m != nil {
			deps = append(deps, depRef{Name: m[1], Ecosystem: "PyPI", Version: m[2], File: file})
		}
	}
	return deps
}

// queryOSV posts the dependency batch to the OSV API and returns findings.
func queryOSV(ctx context.Context, deps []depRef) ([]review.Finding, error) {
	queries := make([]osvQuery, 0, len(deps))
	for _, d := range deps {
		queries = append(queries, osvQuery{
			Pkg:     osvPackage{Name: d.Name, Ecosystem: d.Ecosystem},
			Version: d.Version,
		})
	}
	body, err := json.Marshal(osvRequest{Queries: queries})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, osvQueryBatchURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("osv API %s: %.500s", resp.Status, string(data))
	}
	var parsed osvResponse
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("osv response parse: %w", err)
	}
	var findings []review.Finding
	for i, result := range parsed.Results {
		if i >= len(deps) {
			break
		}
		d := deps[i]
		for _, v := range result.Vulns {
			if len(findings) >= maxVulnFindings {
				return findings, nil
			}
			id := v.ID
			if id == "" {
				id = "OSV-UNKNOWN"
			}
			msg := fmt.Sprintf("%s %s@%s: %s %s", d.Ecosystem, d.Name, d.Version, id, v.Summary)
			msg = strings.TrimSpace(msg)
			sev := cvssSeverity(v.Severity)
			rawSev := cvssRawScore(v.Severity)
			findings = append(findings, review.Finding{
				Category:    "security",
				Rule:        "dependency-cve",
				Rules:       []string{"dependency-cve"},
				Analyzers:   []string{"osv-api"},
				Severity:    sev,
				RawSeverity: rawSev,
				Confidence:  "high",
				AdvisoryID:  id,
				AdvisoryIDs: []string{id},
				File:        d.File,
				Line:        1,
				Message:     msg,
				Remediation: "Upgrade " + d.Name + " to a non-vulnerable version (see " + id + ").",
			})
		}
	}
	return findings, nil
}

// cvssSeverity maps the first CVSS_V3 score in an OSV severity list to a
// m3tal severity name. Missing/unparseable scores default to medium.
func cvssSeverity(severities []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, s := range severities {
		if s.Type != "CVSS_V3" {
			continue
		}
		idx := strings.LastIndex(s.Score, ":")
		if idx < 0 {
			continue
		}
		score, err := strconv.ParseFloat(s.Score[idx+1:], 64)
		if err != nil {
			continue
		}
		switch {
		case score >= 9.0:
			return "critical"
		case score >= 7.0:
			return "high"
		case score >= 4.0:
			return "medium"
		default:
			return "low"
		}
	}
	return "medium"
}

func cvssRawScore(severities []struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}) string {
	for _, s := range severities {
		if s.Type == "CVSS_V3" && s.Score != "" {
			return s.Score
		}
	}
	return ""
}

// ruleAllowed reports whether ruleName survives --only/--skip filters.
func ruleAllowed(only, skip []string, ruleName string) bool {
	for _, s := range skip {
		if s == ruleName {
			return false
		}
	}
	if len(only) == 0 {
		return true
	}
	for _, s := range only {
		if s == ruleName {
			return true
		}
	}
	return false
}

// runVulnScan collects dependencies and queries OSV. Returns findings;
// errors are returned so the caller can warn without aborting the audit.
func runVulnScan(repositoryRoot string) ([]review.Finding, error) {
	deps := collectDependencies(repositoryRoot)
	if len(deps) == 0 {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return queryOSV(ctx, deps)
}
