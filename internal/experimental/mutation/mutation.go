package mutation

import (
	"context"
	"fmt"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis/concurrency"
	"github.com/jakej985-rgb/m3tal-review/internal/semantic/golang"
)

// Mutant represents a synthetically altered program variant.
type Mutant struct {
	ID          string
	Description string
	SourceFile  string
	MutatedCode string
}

// MutationResult captures whether a mutant was killed (detected) by analysis.
type MutationResult struct {
	MutantID string
	Killed   bool
	Reason   string
}

// MutationSuite evaluates a set of mutants against an analyzer.
type MutationSuite struct {
	Mutants []Mutant
}

// Run executes the mutation test suite using the concurrency analyzer.
func (s *MutationSuite) Run(
	ctx context.Context,
	dirWriter func(files map[string]string) string,
) ([]MutationResult, float64) {
	var results []MutationResult
	var killedCount int

	for _, m := range s.Mutants {
		dir := dirWriter(map[string]string{
			"go.mod":  "module mutfixture\n\ngo 1.23\n",
			"main.go": m.MutatedCode,
		})

		prog, err := golang.Load(ctx, golang.Options{Dir: dir})
		if err != nil {
			// A mutant that breaks build/parse is also considered killed
			results = append(results, MutationResult{
				MutantID: m.ID,
				Killed:   true,
				Reason:   fmt.Sprintf("build failed: %v", err),
			})
			killedCount++
			continue
		}

		res := concurrency.NewAnalyzer(prog, concurrency.Options{}).Analyze(ctx)
		// Mutant is killed if any defect finding or diagnostic is triggered
		killed := len(res.Findings) > 0 || len(res.Diagnostics) > 0
		var reason string
		if killed {
			killedCount++
			if len(res.Findings) > 0 {
				reason = fmt.Sprintf("killed by finding: %s", res.Findings[0].RuleID)
			} else {
				reason = fmt.Sprintf("killed by diagnostic: %s", res.Diagnostics[0].Message)
			}
		} else {
			reason = "survived (no findings or diagnostics emitted)"
		}

		results = append(results, MutationResult{
			MutantID: m.ID,
			Killed:   killed,
			Reason:   reason,
		})
	}

	score := 0.0
	if len(s.Mutants) > 0 {
		score = float64(killedCount) / float64(len(s.Mutants))
	}
	return results, score
}

// ApplyReplacementMutator substitutes the first occurrence of oldStr with newStr.
func ApplyReplacementMutator(id, desc, code, oldStr, newStr string) Mutant {
	mutated := strings.Replace(code, oldStr, newStr, 1)
	return Mutant{
		ID:          id,
		Description: desc,
		SourceFile:  "main.go",
		MutatedCode: mutated,
	}
}
