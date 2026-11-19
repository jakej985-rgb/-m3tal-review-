package differential

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// NormalizedFinding provides an engine-agnostic representation of a defect finding
// for cross-tool comparison and adjudication.
type NormalizedFinding struct {
	Tool     string `json:"tool"`
	Rule     string `json:"rule"`
	Category string `json:"category"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// Key computes a line-invariant matching key for correlating findings across tools.
func (f NormalizedFinding) Key() string {
	normFile := strings.ReplaceAll(f.File, "\\", "/")
	normFile = strings.TrimPrefix(normFile, "./")
	return fmt.Sprintf("%s:%s", normFile, strings.ToLower(f.Rule))
}

// DisagreementKind classifies the nature of divergence between analyzers.
type DisagreementKind string

const (
	DisagreementNone          DisagreementKind = "agreement"
	DisagreementM3talOnly     DisagreementKind = "m3tal_only"
	DisagreementReferenceOnly DisagreementKind = "reference_only"
)

// ComparisonResult captures the differential analysis between m3tal-review and a reference tool.
type ComparisonResult struct {
	CaseID        string              `json:"case_id"`
	Agreements    []NormalizedFinding `json:"agreements,omitempty"`
	M3talOnly     []NormalizedFinding `json:"m3tal_only,omitempty"`
	ReferenceOnly []NormalizedFinding `json:"reference_only,omitempty"`
}

// Metrics computes precision, recall, and F1 relative to ground truth.
type Metrics struct {
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	FalseNegatives int     `json:"false_negatives"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	F1Score        float64 `json:"f1_score"`
}

// NormalizeM3talFindings converts review.Finding items into NormalizedFindings.
func NormalizeM3talFindings(findings []review.Finding) []NormalizedFinding {
	out := make([]NormalizedFinding, 0, len(findings))
	for _, f := range findings {
		out = append(out, NormalizedFinding{
			Tool:     "m3tal-review",
			Rule:     f.Rule,
			Category: f.Category,
			File:     f.File,
			Line:     f.Line,
			Message:  f.Message,
		})
	}
	return out
}

// Compare computes agreements and disagreements between two finding sets.
func Compare(caseID string, m3talFindings, refFindings []NormalizedFinding) ComparisonResult {
	res := ComparisonResult{
		CaseID: caseID,
	}

	m3talMap := make(map[string]NormalizedFinding, len(m3talFindings))
	for _, f := range m3talFindings {
		m3talMap[f.Key()] = f
	}

	refMap := make(map[string]NormalizedFinding, len(refFindings))
	for _, f := range refFindings {
		refMap[f.Key()] = f
	}

	for k, mf := range m3talMap {
		if _, ok := refMap[k]; ok {
			res.Agreements = append(res.Agreements, mf)
		} else {
			res.M3talOnly = append(res.M3talOnly, mf)
		}
	}

	for k, rf := range refMap {
		if _, ok := m3talMap[k]; !ok {
			res.ReferenceOnly = append(res.ReferenceOnly, rf)
		}
	}

	sort.Slice(res.Agreements, func(i, j int) bool { return res.Agreements[i].Key() < res.Agreements[j].Key() })
	sort.Slice(res.M3talOnly, func(i, j int) bool { return res.M3talOnly[i].Key() < res.M3talOnly[j].Key() })
	sort.Slice(res.ReferenceOnly, func(i, j int) bool { return res.ReferenceOnly[i].Key() < res.ReferenceOnly[j].Key() })

	return res
}

// EvaluateAgainstGroundTruth scores candidate findings against an adjudicated expected set.
func EvaluateAgainstGroundTruth(actual, groundTruth []NormalizedFinding) Metrics {
	gtMap := make(map[string]bool, len(groundTruth))
	for _, gt := range groundTruth {
		gtMap[gt.Key()] = true
	}

	actMap := make(map[string]bool, len(actual))
	for _, act := range actual {
		actMap[act.Key()] = true
	}

	var tp, fp, fn int
	for k := range actMap {
		if gtMap[k] {
			tp++
		} else {
			fp++
		}
	}
	for k := range gtMap {
		if !actMap[k] {
			fn++
		}
	}

	var prec, rec, f1 float64
	if tp+fp > 0 {
		prec = float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		rec = float64(tp) / float64(tp+fn)
	}
	if prec+rec > 0 {
		f1 = 2 * (prec * rec) / (prec + rec)
	}

	// Round to 4 decimal places
	round := func(v float64) float64 {
		return math.Round(v*10000) / 10000
	}

	return Metrics{
		TruePositives:  tp,
		FalsePositives: fp,
		FalseNegatives: fn,
		Precision:      round(prec),
		Recall:         round(rec),
		F1Score:        round(f1),
	}
}
