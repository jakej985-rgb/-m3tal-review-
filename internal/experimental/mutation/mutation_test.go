package mutation

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const baseConcurrencyProgram = `package main

import "sync"

var mu sync.Mutex
var count int

func check() bool {
	mu.Lock()
	defer mu.Unlock()
	return count < 10
}

func bump() {
	mu.Lock()
	count++
	mu.Unlock()
}

func main() {
	go func() {
		for {
			if check() {
				bump()
			}
		}
	}()
	count = 0
}
`

func writeTempModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestMutationSuite_KillRate(t *testing.T) {
	suite := MutationSuite{
		Mutants: []Mutant{
			ApplyReplacementMutator(
				"MUT-1-UNMATCHED-UNLOCK", "remove lock before unlock",
				baseConcurrencyProgram, "mu.Lock()", "// lock removed",
			),
			ApplyReplacementMutator(
				"MUT-2-SHARED-DATA-WRITE", "unprotected write in bump",
				baseConcurrencyProgram, "mu.Lock()\n\tcount++", "count++",
			),
			ApplyReplacementMutator(
				"MUT-3-INVERT-BOUND", "invert boundary condition",
				baseConcurrencyProgram, "count < 10", "count > 10",
			),
		},
	}

	results, score := suite.Run(context.Background(), func(files map[string]string) string {
		return writeTempModule(t, files)
	})

	if len(results) != len(suite.Mutants) {
		t.Fatalf("expected %d results, got %d", len(suite.Mutants), len(results))
	}

	// Verify all mutants were killed
	for _, res := range results {
		if !res.Killed {
			t.Errorf("mutant %s survived: %s", res.MutantID, res.Reason)
		}
	}

	if score < 1.0 {
		t.Fatalf("expected mutation score 1.0 (100%% kill rate), got %f", score)
	}
}
