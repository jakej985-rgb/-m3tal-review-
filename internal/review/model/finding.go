package model

type Finding struct {
	ID          string `json:"id,omitempty"`
	Category    string `json:"category,omitempty"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}
