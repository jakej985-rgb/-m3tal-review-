package model

type Finding struct {
	ID          string            `json:"id,omitempty"`
	Category    string            `json:"category,omitempty"`
	Rule        string            `json:"rule"`
	Rules       []string          `json:"rules,omitempty"`
	Analyzers   []string          `json:"analyzers,omitempty"`
	Severity    string            `json:"severity"`
	RawSeverity string            `json:"raw_severity,omitempty"`
	Confidence  string            `json:"confidence,omitempty"`
	AdvisoryID  string            `json:"advisory_id,omitempty"`
	AdvisoryIDs []string          `json:"advisory_ids,omitempty"`
	File        string            `json:"file"`
	Line        int               `json:"line"`
	Message     string            `json:"message"`
	Remediation string            `json:"remediation,omitempty"`
	Signature   string            `json:"signature,omitempty"`
	Snippet     string            `json:"snippet,omitempty"`
	Evidence    []FindingEvidence `json:"evidence,omitempty"`
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
