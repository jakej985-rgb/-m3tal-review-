package arch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempModule(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for relPath, content := range files {
		fullPath := filepath.Join(dir, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("failed to create directory: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("failed to write file %s: %v", relPath, err)
		}
	}
	return dir
}

func TestBuildArchitectureGraph(t *testing.T) {
	files := map[string]string{
		"go.mod": "module testmod\n\ngo 1.22\n",
		"pkgA/a.go": `package pkgA

func ExportedA() string { return "A" }
`,
		"pkgB/b.go": `package pkgB

import "testmod/pkgA"

func ExportedB() string { return pkgA.ExportedA() }
`,
	}
	dir := writeTempModule(t, files)

	graph, err := BuildArchitectureGraph(dir, GraphOptions{ModulePath: "testmod"})
	if err != nil {
		t.Fatalf("BuildArchitectureGraph failed: %v", err)
	}

	if len(graph.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(graph.Nodes))
	}
	if graph.Nodes["pkgA"] == nil || graph.Nodes["pkgB"] == nil {
		t.Fatalf("missing expected packages in graph")
	}

	nodeB := graph.Nodes["pkgB"]
	if len(nodeB.Imports) == 0 {
		t.Fatalf("expected pkgB to import pkgA")
	}
	if nodeB.Imports[0].ToPkg != "pkgA" {
		t.Errorf("expected import to pkgA, got %s", nodeB.Imports[0].ToPkg)
	}
	if len(graph.Cycles) != 0 {
		t.Errorf("expected no cycles, got %v", graph.Cycles)
	}
}

func makeEdge(from, to, file string, line int) ImportEdge {
	return ImportEdge{
		EdgeLocation: EdgeLocation{
			FromPkg: from,
			ToPkg:   to,
			File:    file,
			Line:    line,
		},
	}
}

func TestCycleDetection(t *testing.T) {
	nodes := map[string]*PackageNode{
		"pkg1": {
			Path:    "pkg1",
			Imports: []ImportEdge{makeEdge("pkg1", "pkg2", "", 0)},
		},
		"pkg2": {
			Path:    "pkg2",
			Imports: []ImportEdge{makeEdge("pkg2", "pkg1", "", 0)},
		},
	}

	cycles := detectGraphCycles(nodes)
	if len(cycles) == 0 {
		t.Fatalf("expected cycle to be detected")
	}
	cycleStr := strings.Join(cycles[0], "->")
	if !strings.Contains(cycleStr, "pkg1") || !strings.Contains(cycleStr, "pkg2") {
		t.Errorf("expected cycle between pkg1 and pkg2, got %s", cycleStr)
	}
}

func TestCheckPolicy(t *testing.T) {
	graph := &ArchitectureGraph{
		Nodes: map[string]*PackageNode{
			"internal/semantic": {
				Path: "internal/semantic",
				Imports: []ImportEdge{
					makeEdge("internal/semantic", "internal/analysis", "internal/semantic/model.go", 12),
				},
			},
		},
	}

	policy := DefaultPolicy()
	violations := CheckPolicy(graph, policy)
	if len(violations) == 0 {
		t.Fatalf("expected policy boundary violation")
	}

	v := violations[0]
	if v.RuleName != "semantic-isolation" {
		t.Errorf("expected semantic-isolation rule, got %s", v.RuleName)
	}
	if !strings.Contains(v.Message, "Architectural boundary violation") {
		t.Errorf("expected boundary violation message, got %s", v.Message)
	}
}

func TestEstimateImpact(t *testing.T) {
	graph := &ArchitectureGraph{
		Nodes: map[string]*PackageNode{
			"pkgCore": {
				Path:  "pkgCore",
				Files: []string{"pkgCore/core.go", "pkgCore/core_test.go"},
			},
			"pkgMiddle": {
				Path:    "pkgMiddle",
				Files:   []string{"pkgMiddle/mid.go"},
				Imports: []ImportEdge{makeEdge("pkgMiddle", "pkgCore", "", 0)},
			},
			"pkgTop": {
				Path:    "pkgTop",
				Files:   []string{"pkgTop/top.go"},
				Imports: []ImportEdge{makeEdge("pkgTop", "pkgMiddle", "", 0)},
			},
		},
	}

	impact := EstimateImpact(graph, []string{"pkgCore/core.go"})
	if len(impact.DirectlyAffected) != 1 {
		t.Fatalf("expected 1 directly affected package, got %d", len(impact.DirectlyAffected))
	}
	if impact.DirectlyAffected[0].Package != "pkgMiddle" {
		t.Errorf("expected pkgMiddle directly affected, got %s", impact.DirectlyAffected[0].Package)
	}
	if impact.DirectlyAffected[0].Relation != ImpactExact {
		t.Errorf("expected ImpactExact for direct dependent")
	}

	if len(impact.TransitivelyAffect) != 1 {
		t.Fatalf("expected 1 transitively affected package, got %d", len(impact.TransitivelyAffect))
	}
	if impact.TransitivelyAffect[0].Package != "pkgTop" {
		t.Errorf("expected pkgTop transitively affected, got %s", impact.TransitivelyAffect[0].Package)
	}
	if impact.TransitivelyAffect[0].Relation != ImpactHeuristic {
		t.Errorf("expected ImpactHeuristic for transitive dependent")
	}
}

func TestGraphCacheInvalidation(t *testing.T) {
	graph := &ArchitectureGraph{
		Nodes: map[string]*PackageNode{
			"pkgA": {Path: "pkgA", ContentHash: "hashA"},
			"pkgB": {Path: "pkgB", ContentHash: "hashB"},
		},
	}
	cache := NewGraphCache(graph, "config-v1")

	hashes := map[string]string{
		"pkgA": "hashA",
		"pkgB": "hashB",
	}

	// 1. Valid state
	if !cache.IsValid(hashes, "config-v1") {
		t.Errorf("expected cache to be valid")
	}

	// 2. Config change invalidates
	if cache.IsValid(hashes, "config-v2") {
		t.Errorf("expected cache to be invalid on config change")
	}

	// 3. Package hash change invalidates
	modifiedHashes := map[string]string{
		"pkgA": "hashA-modified",
		"pkgB": "hashB",
	}
	if cache.IsValid(modifiedHashes, "config-v1") {
		t.Errorf("expected cache to be invalid on content hash change")
	}
}

func TestResourceLimitDiagnostics(t *testing.T) {
	files := map[string]string{
		"go.mod":    "module testmod\n\ngo 1.22\n",
		"pkg1/1.go": "package pkg1\n",
		"pkg2/2.go": "package pkg2\n",
	}
	dir := writeTempModule(t, files)

	// Set MaxNodes to 1 to force truncation diagnostic
	opts := GraphOptions{ModulePath: "testmod", MaxNodes: 1}
	graph, err := BuildArchitectureGraph(dir, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !graph.Truncated {
		t.Errorf("expected graph to be truncated with MaxNodes=1")
	}
	if len(graph.Diagnostics) == 0 {
		t.Fatalf("expected diagnostics on truncation")
	}
	if graph.Diagnostics[0].Category != "limit" {
		t.Errorf("expected limit diagnostic, got %s", graph.Diagnostics[0].Category)
	}
}
