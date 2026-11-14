package pipeline

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestOrderAnalyzersDependencies(t *testing.T) {
	defs := []analyzerDef{
		{Name: "c", DependsOn: []string{"a"}},
		{Name: "a"},
		{Name: "b", DependsOn: []string{"a"}},
	}
	got := orderAnalyzers(defs)
	var names []string
	for _, d := range got {
		names = append(names, d.Name)
	}
	// a must precede both b and c; b and c keep registration order.
	want := []string{"a", "c", "b"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("orderAnalyzers = %v, want %v", names, want)
	}
}

func TestOrderAnalyzersCycleDoesNotDeadlock(t *testing.T) {
	defs := []analyzerDef{
		{Name: "x", DependsOn: []string{"y"}},
		{Name: "y", DependsOn: []string{"x"}},
		{Name: "z"},
	}
	done := make(chan []analyzerDef, 1)
	go func() { done <- orderAnalyzers(defs) }()
	select {
	case got := <-done:
		if len(got) != 3 {
			t.Fatalf("orderAnalyzers returned %d defs, want 3", len(got))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("orderAnalyzers deadlocked on dependency cycle")
	}
}

func TestSelectAnalyzersUnknown(t *testing.T) {
	if _, err := selectAnalyzers([]string{"nope"}); err == nil {
		t.Fatal("expected error for unknown analyzer")
	}
	defs, err := selectAnalyzers([]string{AnalyzerConcurrency, AnalyzerFlow})
	if err != nil {
		t.Fatalf("selectAnalyzers: %v", err)
	}
	if len(defs) != 2 {
		t.Fatalf("got %d defs, want 2", len(defs))
	}
}

func TestRunAnalyzersBoundedAndDeterministic(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	mkDef := func(name string, delay time.Duration) analyzerDef {
		return analyzerDef{
			Name: name,
			Run: func(ctx context.Context, env *Env) analyzerOutcome {
				cur := inFlight.Add(1)
				for {
					old := maxInFlight.Load()
					if cur <= old || maxInFlight.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(delay)
				inFlight.Add(-1)
				return analyzerOutcome{}
			},
		}
	}
	defs := []analyzerDef{
		mkDef("slow-a", 60*time.Millisecond),
		mkDef("fast-b", time.Millisecond),
		mkDef("slow-c", 60*time.Millisecond),
		mkDef("fast-d", time.Millisecond),
	}
	opts := Options{MaxParallel: 2}
	results := runAnalyzers(context.Background(), defs, &Env{}, opts)

	if len(results) != 4 {
		t.Fatalf("got %d results, want 4", len(results))
	}
	// Results stay in definition order even though fast analyzers finish first.
	wantOrder := []string{"slow-a", "fast-b", "slow-c", "fast-d"}
	for i, r := range results {
		if r.Name != wantOrder[i] {
			t.Fatalf("results[%d].Name = %q, want %q (order must be deterministic)", i, r.Name, wantOrder[i])
		}
		if r.Status != "completed" {
			t.Fatalf("results[%d].Status = %q, want completed", i, r.Status)
		}
	}
	if got := maxInFlight.Load(); got > 2 {
		t.Fatalf("max in-flight analyzers = %d, want <= 2", got)
	}
}

func TestRunAnalyzersFailureIsolation(t *testing.T) {
	defs := []analyzerDef{
		{Name: "panic-er", Run: func(ctx context.Context, env *Env) analyzerOutcome {
			panic("boom")
		}},
		{Name: "error-er", Run: func(ctx context.Context, env *Env) analyzerOutcome {
			return analyzerOutcome{err: fmt.Errorf("engine exploded")}
		}},
		{Name: "fine", Run: func(ctx context.Context, env *Env) analyzerOutcome {
			return analyzerOutcome{}
		}},
		{Name: "skipper", Run: func(ctx context.Context, env *Env) analyzerOutcome {
			return analyzerOutcome{Skipped: true, SkipReason: "no contracts"}
		}},
	}
	results := runAnalyzers(context.Background(), defs, &Env{}, Options{MaxParallel: 4})

	statuses := map[string]string{}
	for _, r := range results {
		statuses[r.Name] = r.Status
	}
	if statuses["panic-er"] != "failed" {
		t.Fatalf("panic-er status = %q, want failed", statuses["panic-er"])
	}
	if statuses["error-er"] != "failed" {
		t.Fatalf("error-er status = %q, want failed", statuses["error-er"])
	}
	if statuses["fine"] != "completed" {
		t.Fatalf("fine status = %q, want completed (failures must be isolated)", statuses["fine"])
	}
	if statuses["skipper"] != "skipped" {
		t.Fatalf("skipper status = %q, want skipped", statuses["skipper"])
	}
	// Each failure produced an error diagnostic.
	for _, r := range results {
		if (r.Name == "panic-er" || r.Name == "error-er") && len(r.Diagnostics) == 0 {
			t.Fatalf("%s produced no failure diagnostic", r.Name)
		}
	}
}

func TestRunAnalyzersCancellation(t *testing.T) {
	defs := []analyzerDef{
		{Name: "hang", Run: func(ctx context.Context, env *Env) analyzerOutcome {
			<-ctx.Done()
			return analyzerOutcome{err: ctx.Err()}
		}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := runAnalyzers(ctx, defs, &Env{}, Options{MaxParallel: 1})
	if results[0].Status != "failed" {
		t.Fatalf("status = %q, want failed on canceled context", results[0].Status)
	}
}

func TestRunOneTimeout(t *testing.T) {
	def := analyzerDef{
		Name: "slow",
		Run: func(ctx context.Context, env *Env) analyzerOutcome {
			time.Sleep(200 * time.Millisecond)
			return analyzerOutcome{}
		},
	}
	opts := Options{MaxParallel: 1, AnalyzerTimeout: 20 * time.Millisecond}
	results := runAnalyzers(context.Background(), []analyzerDef{def}, &Env{}, opts)
	if results[0].Status != "timeout" {
		t.Fatalf("status = %q, want timeout", results[0].Status)
	}
	if len(results[0].Diagnostics) == 0 {
		t.Fatal("timeout produced no diagnostic")
	}
}

func TestRunLoadFailureSkipsAnalyzers(t *testing.T) {
	res, err := Run(context.Background(), Options{
		Dir:         filepath.Join(t.TempDir(), "does-not-exist"), // unloadable -> frontend error
		Analyzers:   []string{AnalyzerFlow, AnalyzerConcurrency},
		LoadTimeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.LoadError == "" {
		t.Fatal("expected LoadError for unloadable directory")
	}
	if len(res.Analyzers) != 2 {
		t.Fatalf("got %d analyzer results, want 2", len(res.Analyzers))
	}
	for _, a := range res.Analyzers {
		if a.Status != "skipped" {
			t.Fatalf("analyzer %s status = %q, want skipped", a.Name, a.Status)
		}
	}
	if len(res.Diagnostics) == 0 {
		t.Fatal("expected load-error diagnostic")
	}
}

func TestRunUnknownAnalyzerOption(t *testing.T) {
	_, err := Run(context.Background(), Options{
		Dir:       t.TempDir(),
		Analyzers: []string{"bogus"},
	})
	if err == nil {
		t.Fatal("expected error for unknown analyzer")
	}
}

func TestRunRequiresDir(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Fatal("expected error for empty Dir")
	}
}
