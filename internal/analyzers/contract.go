package analyzers

import (
	"context"
	"sort"
	"sync"

	"github.com/jakej985-rgb/m3tal-review/internal/detection/language"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// TargetFile represents a single file handed to an analyzer.
type TargetFile struct {
	Path      string
	Language  string
	Secondary []string
	Content   string
}

// Request is the input passed to an Analyzer.
type Request struct {
	Root  string
	Files []TargetFile
}

// Result is the output produced by an Analyzer.
type Result struct {
	AnalyzerID string
	Findings   []review.Finding
}

// Analyzer is the uniform contract implemented by all language, framework,
// infrastructure, and cross-language analyzers.
type Analyzer interface {
	Metadata() planning.AnalyzerMetadata
	Analyze(ctx context.Context, req Request) (Result, error)
}

// Registry stores registered analyzers keyed by ID.
type Registry struct {
	mu        sync.RWMutex
	analyzers map[string]Analyzer
}

// NewRegistry creates an empty analyzer registry.
func NewRegistry() *Registry {
	return &Registry{
		analyzers: make(map[string]Analyzer),
	}
}

// Register adds an analyzer to the registry.
func (r *Registry) Register(a Analyzer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.analyzers[a.Metadata().ID] = a
}

// Lookup returns an analyzer by ID.
func (r *Registry) Lookup(id string) (Analyzer, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.analyzers[id]
	return a, ok
}

// Catalog returns metadata for all registered analyzers sorted by ID.
func (r *Registry) Catalog() []planning.AnalyzerMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]planning.AnalyzerMetadata, 0, len(r.analyzers))
	for _, a := range r.analyzers {
		out = append(out, a.Metadata())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID < out[j].ID
	})
	return out
}

// RunPlan executes all selected analyzers in parallel and returns deterministic,
// deduplicated findings.
func (r *Registry) RunPlan(ctx context.Context, plan planning.ExecutionPlan, root string, files []TargetFile, det language.RepositoryDetection, cache *ResultCache) ([]review.Finding, []string) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allFindings []review.Finding
	var ranIDs []string

	byLang := make(map[string][]TargetFile)
	for _, f := range files {
		byLang[f.Language] = append(byLang[f.Language], f)
		for _, sec := range f.Secondary {
			byLang[sec] = append(byLang[sec], f)
		}
	}

	for _, planned := range plan.Selected {
		a, ok := r.Lookup(planned.Analyzer.ID)
		if !ok {
			continue
		}
		targetFiles := selectFilesForAnalyzer(planned.Analyzer, files, byLang)
		wg.Add(1)
		go func(an Analyzer, tf []TargetFile) {
			defer wg.Done()
			id := an.Metadata().ID
			if cache != nil {
				if cached, hit := cache.Get(id, tf); hit {
					mu.Lock()
					allFindings = append(allFindings, cached...)
					ranIDs = append(ranIDs, id)
					mu.Unlock()
					return
				}
			}
			res, err := an.Analyze(ctx, Request{Root: root, Files: tf})
			if err != nil {
				return
			}
			if cache != nil {
				cache.Put(id, tf, res.Findings)
			}
			mu.Lock()
			allFindings = append(allFindings, res.Findings...)
			ranIDs = append(ranIDs, id)
			mu.Unlock()
		}(a, targetFiles)
	}
	wg.Wait()

	sort.Strings(ranIDs)
	allFindings = review.PrioritizeFindings(review.AssignFindingIDs(allFindings))
	return allFindings, ranIDs
}

func selectFilesForAnalyzer(meta planning.AnalyzerMetadata, all []TargetFile, byLang map[string][]TargetFile) []TargetFile {
	if len(meta.Languages) == 0 {
		return all
	}
	seen := make(map[string]bool)
	var out []TargetFile
	for _, lang := range meta.Languages {
		for _, f := range byLang[lang] {
			if !seen[f.Path] {
				seen[f.Path] = true
				out = append(out, f)
			}
		}
	}
	return out
}
