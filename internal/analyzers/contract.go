package analyzers

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/jakej985-rgb/m3tal-review/internal/detection/framework"
	"github.com/jakej985-rgb/m3tal-review/internal/detection/language"
	"github.com/jakej985-rgb/m3tal-review/internal/planning"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// AnalyzerState represents the execution outcome of a single planned analyzer.
type AnalyzerState string

const (
	StateCompleted AnalyzerState = "completed"
	StateCached    AnalyzerState = "cached"
	StateMissing   AnalyzerState = "missing"
	StateFailed    AnalyzerState = "failed"
	StateCanceled  AnalyzerState = "canceled"
)

// AnalyzerStatus records an analyzer's execution outcome and any failure details.
type AnalyzerStatus struct {
	ID    string        `json:"id"`
	State AnalyzerState `json:"state"`
	Error string        `json:"error,omitempty"`
}

// ExecutionReport summarizes all findings and per-analyzer statuses from RunPlan.
type ExecutionReport struct {
	Findings   []review.Finding `json:"findings"`
	Statuses   []AnalyzerStatus `json:"statuses"`
	RanIDs     []string         `json:"ran_ids"`
	Incomplete bool             `json:"incomplete"`
}

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

// RunPlan executes all selected analyzers in parallel and returns an ExecutionReport
// preserving per-analyzer status, failures, and deterministic findings.
func (r *Registry) RunPlan(ctx context.Context, plan planning.ExecutionPlan, root string, files []TargetFile, _ language.RepositoryDetection, frameworks []framework.FrameworkInfo, configKey string, cache *ResultCache) ExecutionReport {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var rep ExecutionReport

	byLang := make(map[string][]TargetFile)
	for _, f := range files {
		byLang[f.Language] = append(byLang[f.Language], f)
		for _, sec := range f.Secondary {
			byLang[sec] = append(byLang[sec], f)
		}
	}
	fwRoots := make(map[string][]string, len(frameworks))
	for _, fw := range frameworks {
		fwRoots[strings.ToLower(fw.Name)] = fw.Roots
	}

	for _, planned := range plan.Selected {
		a, ok := r.Lookup(planned.Analyzer.ID)
		if !ok {
			mu.Lock()
			rep.Statuses = append(rep.Statuses, AnalyzerStatus{
				ID:    planned.Analyzer.ID,
				State: StateMissing,
				Error: "analyzer not registered",
			})
			rep.Incomplete = true
			mu.Unlock()
			continue
		}
		targetFiles := selectFilesForAnalyzer(planned.Analyzer, files, byLang, fwRoots)
		wg.Add(1)
		go func(an Analyzer, tf []TargetFile) {
			defer wg.Done()
			id := an.Metadata().ID
			if cache != nil {
				if cached, hit := cache.Get(id, configKey, tf); hit {
					mu.Lock()
					rep.Findings = append(rep.Findings, cached...)
					rep.RanIDs = append(rep.RanIDs, id)
					rep.Statuses = append(rep.Statuses, AnalyzerStatus{ID: id, State: StateCached})
					mu.Unlock()
					return
				}
			}
			res, err := an.Analyze(ctx, Request{Root: root, Files: tf})
			if err != nil {
				state := StateFailed
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					state = StateCanceled
				}
				mu.Lock()
				rep.Statuses = append(rep.Statuses, AnalyzerStatus{ID: id, State: state, Error: err.Error()})
				rep.Incomplete = true
				mu.Unlock()
				return
			}
			if cache != nil {
				cache.Put(id, configKey, tf, res.Findings)
			}
			mu.Lock()
			rep.Findings = append(rep.Findings, res.Findings...)
			rep.RanIDs = append(rep.RanIDs, id)
			rep.Statuses = append(rep.Statuses, AnalyzerStatus{ID: id, State: StateCompleted})
			mu.Unlock()
		}(a, targetFiles)
	}
	wg.Wait()

	sort.Strings(rep.RanIDs)
	sort.Slice(rep.Statuses, func(i, j int) bool {
		return rep.Statuses[i].ID < rep.Statuses[j].ID
	})
	rep.Findings = review.PrioritizeFindings(review.AssignFindingIDs(rep.Findings))
	return rep
}

func selectFilesForAnalyzer(meta planning.AnalyzerMetadata, all []TargetFile, byLang map[string][]TargetFile, fwRoots map[string][]string) []TargetFile {
	if len(meta.Languages) == 0 {
		return all
	}
	var roots []string
	if meta.Kind == planning.KindFramework {
		for _, fw := range meta.Frameworks {
			roots = append(roots, fwRoots[strings.ToLower(fw)]...)
		}
	}

	seen := make(map[string]bool)
	var out []TargetFile
	for _, lang := range meta.Languages {
		for _, f := range byLang[lang] {
			if seen[f.Path] {
				continue
			}
			if len(roots) > 0 && !matchesAnyRoot(f.Path, roots) {
				continue
			}
			seen[f.Path] = true
			out = append(out, f)
		}
	}
	return out
}

func matchesAnyRoot(filePath string, roots []string) bool {
	for _, r := range roots {
		if r == "." || r == "" {
			return true
		}
		if filePath == r || strings.HasPrefix(filePath, r+"/") {
			return true
		}
	}
	return false
}
