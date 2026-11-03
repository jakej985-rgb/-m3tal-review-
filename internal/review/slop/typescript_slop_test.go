package slop_test

import (
	"testing"

	review "github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestTypeScriptSyntaxAnalyzerIgnoresStringsAndComments(t *testing.T) {
	source := "const sample = 'if (x) { if (y) {} }';\n// if (a) {\n"
	repo := stageNonGoSlopSource(t, "main.ts", source)
	diff := "diff --git a/main.ts b/main.ts\n--- a/main.ts\n+++ b/main.ts\n@@ -0,0 +1,2 @@\n+const sample = 'if (x) { if (y) {} }';\n+// if (a) {\n"
	findings := (review.SlopRule{RepositoryRoot: repo}).Check(diff)
	if len(findings) != 0 {
		t.Fatalf("strings/comments produced TypeScript findings: %+v", findings)
	}
}
