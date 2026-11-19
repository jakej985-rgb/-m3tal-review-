package benchmark

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func generateSyntheticDiff(numFiles, linesPerFile int) string {
	var b strings.Builder
	for i := 0; i < numFiles; i++ {
		filename := fmt.Sprintf("pkg/service%03d/handler.go", i)
		b.WriteString(fmt.Sprintf("diff --git a/%s b/%s\n", filename, filename))
		b.WriteString(fmt.Sprintf("--- a/%s\n+++ b/%s\n", filename, filename))
		b.WriteString(fmt.Sprintf("@@ -1,1 +1,%d @@\n", linesPerFile))
		b.WriteString(fmt.Sprintf(" package service%03d\n", i))
		for l := 0; l < linesPerFile-1; l++ {
			b.WriteString(fmt.Sprintf("+func Handle%d() { /* payload */ }\n", l))
		}
	}
	return b.String()
}

func runBenchmarkTier(b *testing.B, numFiles, linesPerFile int) {
	b.Helper()
	diff := generateSyntheticDiff(numFiles, linesPerFile)
	engine := review.NewEngine(review.ExtraRules("/tmp/benchmark-nonexistent")...)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		findings := engine.Run(diff)
		if len(findings) < 0 {
			b.Fatal("unexpected negative findings")
		}
	}
}

func BenchmarkScalability_SmallRepo(b *testing.B) {
	runBenchmarkTier(b, 10, 50)
}

func BenchmarkScalability_MediumRepo(b *testing.B) {
	runBenchmarkTier(b, 50, 100)
}

func BenchmarkScalability_LargeRepo(b *testing.B) {
	runBenchmarkTier(b, 200, 100)
}

func TestScalability_DeterminismAcrossRuns(t *testing.T) {
	diff := generateSyntheticDiff(20, 30)
	engine := review.NewEngine(review.ExtraRules("/tmp/benchmark-nonexistent")...)

	run1 := engine.Run(diff)
	run2 := engine.Run(diff)

	if len(run1) != len(run2) {
		t.Fatalf("nondeterministic finding counts: run1=%d, run2=%d", len(run1), len(run2))
	}
	for i := range run1 {
		if run1[i].File != run2[i].File || run1[i].Rule != run2[i].Rule {
			t.Errorf("finding divergence at index %d: %+v vs %+v", i, run1[i], run2[i])
		}
	}
}
