package model

// RiskBreakdown explains the individual factor contributions to a finding's risk score.
type RiskBreakdown struct {
	BaseSeverity       float64 `json:"base_severity"`
	ConfidenceFactor   float64 `json:"confidence_factor"`
	ReachabilityFactor float64 `json:"reachability_factor"`
	ExposureFactor     float64 `json:"exposure_factor"`
	EvidenceMultiplier float64 `json:"evidence_multiplier"`
	Explanation        string  `json:"explanation,omitempty"`
}

type Finding struct {
	ID            string            `json:"id,omitempty"`
	Category      string            `json:"category,omitempty"`
	Rule          string            `json:"rule"`
	Rules         []string          `json:"rules,omitempty"`
	Analyzers     []string          `json:"analyzers,omitempty"`
	Severity      string            `json:"severity"`
	RawSeverity   string            `json:"raw_severity,omitempty"`
	Confidence    string            `json:"confidence,omitempty"`
	RiskScore     float64           `json:"risk_score,omitempty"`
	Risk          *RiskBreakdown    `json:"risk,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	AdvisoryID    string            `json:"advisory_id,omitempty"`
	AdvisoryIDs   []string          `json:"advisory_ids,omitempty"`
	File          string            `json:"file"`
	Line          int               `json:"line"`
	Message       string            `json:"message"`
	Remediation   string            `json:"remediation,omitempty"`
	Signature     string            `json:"signature,omitempty"`
	Snippet       string            `json:"snippet,omitempty"`
	Evidence      []FindingEvidence `json:"evidence,omitempty"`
	Reachability  string            `json:"reachability,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type FindingEvidence struct {
	Analyzer    string `json:"analyzer,omitempty"`
	Rule        string `json:"rule,omitempty"`
	Severity    string `json:"severity,omitempty"`
	RawSeverity string `json:"raw_severity,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
	Message     string `json:"message,omitempty"`
	Line        int    `json:"line,omitempty"`
}
