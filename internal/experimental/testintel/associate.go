package testintel

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// extractTargetSymbol attempts to guess the function name from message or metadata.
func extractTargetSymbol(msg string, metadata map[string]string) string {
	if fn, ok := metadata["function"]; ok && fn != "" {
		return fn
	}
	parts := strings.Fields(msg)
	for i, part := range parts {
		if (part == "in" || part == "from" || part == "function") && i+1 < len(parts) {
			cand := strings.Trim(parts[i+1], "`:(),.")
			if cand != "" && !strings.Contains(cand, "/") {
				return cand
			}
		}
	}
	return ""
}

// matchDirectSymbol checks if testName directly targets the given symbol.
func matchDirectSymbol(testName, symbol string) bool {
	if symbol == "" {
		return false
	}
	lowerTest := strings.ToLower(testName)
	lowerSym := strings.ToLower(symbol)
	return strings.Contains(lowerTest, lowerSym)
}

// scoreAssociation assesses association strength between finding context and test target.
func scoreAssociation(
	fFile string,
	symbol string,
	evFiles map[string]bool,
	t TestTarget,
) (AssociationKind, string, string, bool) {
	testBase := filepath.Base(t.File)
	fBase := filepath.Base(fFile)
	testDir := filepath.Dir(t.File)
	fDir := filepath.Dir(fFile)

	// 1. Direct symbol target
	if symbol != "" && matchDirectSymbol(t.Name, symbol) {
		rationale := fmt.Sprintf("Test %s directly references affected symbol %s", t.Name, symbol)
		return AssocDirectSymbol, "high", rationale, true
	}

	// 2. Co-located file pair (foo.go <-> foo_test.go)
	expectedTestBase := strings.TrimSuffix(fBase, filepath.Ext(fBase)) + "_test.go"
	if fDir == testDir && testBase == expectedTestBase {
		rationale := fmt.Sprintf("Test is in co-located pair file %s for %s", testBase, fBase)
		return AssocPackageColocate, "high", rationale, true
	}

	// 3. Evidence trace match
	if evFiles[t.File] || evFiles[testBase] {
		rationale := fmt.Sprintf("Test file %s appears in finding evidence trace", testBase)
		return AssocEvidenceTrace, "medium", rationale, true
	}

	// 4. Same directory package test
	if fDir == testDir {
		rationale := fmt.Sprintf("Test %s is co-located in the same package directory", t.Name)
		return AssocPackageColocate, "low", rationale, true
	}

	return "", "", "", false
}

func buildAssociations(
	findingID, fFile, sym string,
	evFiles map[string]bool,
	tests []TestTarget,
) []TestAssociation {
	var assocs []TestAssociation
	for _, t := range tests {
		kind, conf, rat, ok := scoreAssociation(fFile, sym, evFiles, t)
		if !ok {
			continue
		}
		assocs = append(assocs, TestAssociation{
			FindingID:  findingID,
			Test:       t,
			Kind:       kind,
			Confidence: conf,
			Rationale:  rat,
		})
	}
	sortAssociations(assocs)
	return assocs
}

// MapFindingToTests associates a review.Finding with relevant tests from targets.
func MapFindingToTests(f review.Finding, tests []TestTarget) []TestAssociation {
	evFiles := make(map[string]bool)
	if f.Explanation != nil {
		for _, step := range f.Explanation.EvidenceSteps {
			if step.Location != "" {
				filePart := strings.Split(step.Location, ":")[0]
				evFiles[filePart] = true
				evFiles[filepath.Base(filePart)] = true
			}
		}
	}
	sym := extractTargetSymbol(f.Message, f.Metadata)
	return buildAssociations(f.ID, f.File, sym, evFiles, tests)
}

// MapAnalysisFindingToTests associates an analysis.Finding with relevant tests.
func MapAnalysisFindingToTests(f analysis.Finding, tests []TestTarget) []TestAssociation {
	evFiles := make(map[string]bool)
	for _, step := range f.Evidence {
		if step.Span.File != "" {
			evFiles[step.Span.File] = true
			evFiles[filepath.Base(step.Span.File)] = true
		}
	}
	fFile := ""
	if len(f.Spans) > 0 {
		fFile = f.Spans[0].File
	}
	sym := extractTargetSymbol(f.Message, nil)
	return buildAssociations(f.ID, fFile, sym, evFiles, tests)
}

func sortAssociations(assocs []TestAssociation) {
	rank := map[string]int{"high": 3, "medium": 2, "low": 1}
	sort.Slice(assocs, func(i, j int) bool {
		rI, rJ := rank[assocs[i].Confidence], rank[assocs[j].Confidence]
		if rI != rJ {
			return rI > rJ
		}
		return assocs[i].Test.Name < assocs[j].Test.Name
	})
}
