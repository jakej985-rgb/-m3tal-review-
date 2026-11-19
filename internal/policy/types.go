package policy

import "time"

// GateStatus classifies the outcome of a quality gate evaluation.
type GateStatus string

const (
	GatePassed     GateStatus = "passed"
	GateFailed     GateStatus = "failed"
	GateWarning    GateStatus = "warning"
	GateIncomplete GateStatus = "incomplete"
)

// SuppressionRule configures policy requirements for suppressing findings.
type SuppressionRule struct {
	RequireReason bool `json:"require_reason" yaml:"require_reason"`
	RequireOwner  bool `json:"require_owner" yaml:"require_owner"`
	RequireExpiry bool `json:"require_expiry" yaml:"require_expiry"`
	MaxExpiryDays int  `json:"max_expiry_days" yaml:"max_expiry_days"`
}

// PathOverride allows custom severity and rule rules for specific file patterns.
type PathOverride struct {
	Pattern       string   `json:"pattern" yaml:"pattern"`
	MaxSeverity   string   `json:"max_severity,omitempty" yaml:"max_severity,omitempty"`
	DisabledRules []string `json:"disabled_rules,omitempty" yaml:"disabled_rules,omitempty"`
}

// QualityGatePolicy defines complete, versioned quality gate enforcement rules.
type QualityGatePolicy struct {
	Version           string          `json:"version" yaml:"version"`
	MaxSeverity       string          `json:"max_severity" yaml:"max_severity"`
	MinConfidence     string          `json:"min_confidence" yaml:"min_confidence"`
	FailOnIncomplete  bool            `json:"fail_on_incomplete" yaml:"fail_on_incomplete"`
	RequiredAnalyzers []string        `json:"required_analyzers,omitempty" yaml:"required_analyzers,omitempty"`
	MaxRiskScore      float64         `json:"max_risk_score,omitempty" yaml:"max_risk_score,omitempty"`
	PathOverrides     []PathOverride  `json:"path_overrides,omitempty" yaml:"path_overrides,omitempty"`
	Suppression       SuppressionRule `json:"suppression" yaml:"suppression"`
}

// GateViolation records a specific rule, threshold, or analyzer failure in a quality gate.
type GateViolation struct {
	Category   string `json:"category"` // "severity", "confidence", "analyzer", "suppression", "risk"
	FindingID  string `json:"finding_id,omitempty"`
	Rule       string `json:"rule,omitempty"`
	Message    string `json:"message"`
	Precedence string `json:"precedence"` // "path_override", "repository_default"
}

// NewGateViolation constructs a GateViolation with default or specified precedence.
func NewGateViolation(cat, findingID, rule, msg, prec string) GateViolation {
	if prec == "" {
		prec = "repository_default"
	}
	return GateViolation{
		Category:   cat,
		FindingID:  findingID,
		Rule:       rule,
		Message:    msg,
		Precedence: prec,
	}
}

// GateEvaluation is the final, explainable result of a quality gate run.
type GateEvaluation struct {
	Status      GateStatus      `json:"status"`
	ExitCode    int             `json:"exit_code"`
	Violations  []GateViolation `json:"violations,omitempty"`
	Warnings    []GateViolation `json:"warnings,omitempty"`
	Explanation []string        `json:"explanation"`
	DryRun      bool            `json:"dry_run"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
}

// SuppressionRecord represents suppression metadata attached to a finding or code comment.
type SuppressionRecord struct {
	FindingID string     `json:"finding_id"`
	Rule      string     `json:"rule"`
	Reason    string     `json:"reason"`
	Owner     string     `json:"owner,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}
