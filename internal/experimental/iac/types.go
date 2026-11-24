// Package iac provides static security analyzers for configuration and infrastructure as code.
package iac

import (
	"bufio"
	"strings"
)

// ArtifactKind identifies the configuration or infrastructure format.
type ArtifactKind string

const (
	KindDockerfile ArtifactKind = "dockerfile"
	KindWorkflow   ArtifactKind = "workflow"
	KindKubernetes ArtifactKind = "kubernetes"
	KindTerraform  ArtifactKind = "terraform"
	KindOpenAPI    ArtifactKind = "openapi"
)

// FindingSpec provides parameters to instantiate a ConfigFinding.
type FindingSpec struct {
	RuleID       string
	Severity     string
	File         string
	Line         int
	Message      string
	Remediation  string
	ArtifactKind ArtifactKind
}

// Collector accumulates configuration findings.
type Collector struct {
	items []ConfigFinding
}

func (c *Collector) emit(kind ArtifactKind, id, sev, file string, line int, desc ...string) {
	msg, rem := "", ""
	if len(desc) > 0 {
		msg = desc[0]
	}
	if len(desc) > 1 {
		rem = desc[1]
	}
	c.items = append(c.items, ConfigFinding{
		RuleID:       id,
		Category:     "security",
		Severity:     sev,
		Confidence:   "high",
		File:         file,
		Line:         line,
		Message:      msg,
		Remediation:  rem,
		ArtifactKind: kind,
	})
}

// AddDocker appends a dockerfile finding.
func (c *Collector) AddDocker(file, id, sev, msg, rem string, line int) {
	c.emit(KindDockerfile, id, sev, file, line, msg, rem)
}

// AddWorkflow appends a workflow finding.
func (c *Collector) AddWorkflow(file, id, sev, msg, rem string, line int) {
	c.emit(KindWorkflow, id, sev, file, line, msg, rem)
}

// AddK8s appends a kubernetes manifest finding.
func (c *Collector) AddK8s(file, id, sev, msg, rem string, line int) {
	c.emit(KindKubernetes, id, sev, file, line, msg, rem)
}

// AddTerraform appends a terraform finding.
func (c *Collector) AddTerraform(file, id, sev, msg, rem string, line int) {
	c.emit(KindTerraform, id, sev, file, line, msg, rem)
}

// AddOpenAPI appends an API route finding.
func (c *Collector) AddOpenAPI(file, id, sev, msg, rem string, line int) {
	c.emit(KindOpenAPI, id, sev, file, line, msg, rem)
}

// Results returns accumulated findings.
func (c *Collector) Results() []ConfigFinding {
	return c.items
}

// walkLines scans text lines passing 1-based line number.
func walkLines(text string, step func(int, string)) {
	s := bufio.NewScanner(strings.NewReader(text))
	idx := 0
	for s.Scan() {
		idx++
		step(idx, s.Text())
	}
}

// ConfigFinding records a security or reliability defect in configuration or IaC.
type ConfigFinding struct {
	RuleID         string       `json:"rule_id"`
	Category       string       `json:"category"`
	Severity       string       `json:"severity"`
	Confidence     string       `json:"confidence"`
	File           string       `json:"file"`
	Line           int          `json:"line"`
	Message        string       `json:"message"`
	Remediation    string       `json:"remediation,omitempty"`
	ArtifactKind   ArtifactKind `json:"artifact_kind"`
	IsHeuristic    bool         `json:"is_heuristic,omitempty"`
	CoverageStatus string       `json:"coverage_status,omitempty"`
}

// CoReviewCorrelation connects configuration properties across multiple artifacts.
type CoReviewCorrelation struct {
	ID          string   `json:"id"`
	RuleID      string   `json:"rule_id"`
	Files       []string `json:"files"`
	Message     string   `json:"message"`
	Severity    string   `json:"severity"`
	Explanation string   `json:"explanation"`
}

// CoReviewReport aggregates single-artifact and cross-artifact findings.
type CoReviewReport struct {
	Findings     []ConfigFinding       `json:"findings"`
	Correlations []CoReviewCorrelation `json:"correlations,omitempty"`
	Diagnostics  []string              `json:"diagnostics,omitempty"`
}
