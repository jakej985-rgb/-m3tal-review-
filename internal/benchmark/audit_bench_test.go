package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// auditHandlerBody is deliberately ordinary application code: SQL built by
// concatenation, a shell command, string literals, comments and an error
// path. Rules have to mask, scan and score it rather than skip it.
const auditHandlerBody = `// Handle%d serves the item endpoint.
func Handle%d(db *sql.DB, w http.ResponseWriter, r *http.Request) {
	query := "SELECT id, name FROM items WHERE id = " + r.URL.Query().Get("id")
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	out, err := exec.Command("sh", "-c", "echo "+r.URL.Query().Get("name")).Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_, _ = w.Write(out)
}

`

func auditCorpusSource(i int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "package service%03d\n\nimport (\n\t\"database/sql\"\n\t\"fmt\"\n\t\"net/http\"\n\t\"os/exec\"\n)\n\n", i)
	for h := 0; h < 8; h++ {
		fmt.Fprintf(&b, auditHandlerBody, h, h)
	}
	return b.String()
}

// auditCorpus writes files new Go files under a temporary root and returns a
// diff that adds every line of each one, which is what an audit of
// untracked/changed files looks like to the rule engine.
func auditCorpus(b *testing.B, files int) (root, diff string) {
	b.Helper()
	root = b.TempDir()
	var out strings.Builder
	for i := 0; i < files; i++ {
		file := filepath.ToSlash(filepath.Join("pkg", fmt.Sprintf("service%03d", i), "handler.go"))
		source := auditCorpusSource(i)
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(file)), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, file), []byte(source), 0o644); err != nil {
			b.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(source, "\n"), "\n")
		fmt.Fprintf(&out, "diff --git a/%s b/%s\nnew file mode 100644\n--- /dev/null\n+++ b/%s\n@@ -0,0 +1,%d @@\n", file, file, file, len(lines))
		for _, line := range lines {
			out.WriteString("+" + line + "\n")
		}
	}
	return root, out.String()
}

// BenchmarkAudit measures the per-file rule pass an audit performs over a
// small synthetic repository, at the default parallelism and under the
// --jobs cap. It covers the ExtraRules set, which is the bulk of audit's
// per-file work; the CLI-only default rules are not included here.
//
// Iterations are warm: the first one populates the mask and source caches,
// so this reports steady-state cost. Pipe -cpuprofile for CPU time.
//
//	go test ./internal/benchmark/ -run XXX -bench BenchmarkAudit -benchmem
func BenchmarkAudit(b *testing.B) {
	root, diff := auditCorpus(b, 40)
	tiers := []struct {
		name string
		jobs int
	}{
		{"auto", 0},
		{"jobs-1", 1},
		{"jobs-4", 4},
	}
	for _, tier := range tiers {
		b.Run(tier.name, func(b *testing.B) {
			rules := review.ExtraRules(root)
			for _, rule := range rules {
				if aware, ok := rule.(review.WorkingTreeAware); ok {
					aware.EnableWorkingTree()
				}
			}
			engine := review.NewEngine(rules...)
			engine.SetMaxParallel(tier.jobs)
			b.ReportAllocs()
			b.SetBytes(int64(len(diff)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.Run(diff)
			}
		})
	}
}
