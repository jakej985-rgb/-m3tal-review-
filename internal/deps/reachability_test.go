package deps

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestGoReachabilityAnalysis(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Setup go.mod with direct and indirect deps
	goModContent := `module example.com/testapp

go 1.22

require (
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/unused/direct v1.0.0
	github.com/blank/imported v1.0.0
)
`
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	// 2. Setup source file using github.com/google/uuid with symbol calls and blank import
	srcContent := `package main

import (
	"fmt"
	_ "github.com/blank/imported"
	"github.com/google/uuid"
)

func main() {
	id := uuid.New()
	fmt.Println("Generated:", id.String())
}
`
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(srcContent), 0644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	// Case 1: Direct dependency with active call expressions -> Reachable
	uuidCtx := AssessReachability(tempDir, "github.com/google/uuid", "Go", true)
	if uuidCtx.Status != ReachabilityReachable {
		t.Errorf("expected status %s for uuid, got %s (rationale: %s)", ReachabilityReachable, uuidCtx.Status, uuidCtx.Rationale)
	}
	if uuidCtx.DependencyType != DependencyTypeDirect {
		t.Errorf("expected dependency type %s, got %s", DependencyTypeDirect, uuidCtx.DependencyType)
	}
	if len(uuidCtx.ReferencedSymbols) == 0 {
		t.Errorf("expected referenced symbols for uuid, got none")
	}
	hasNew := false
	for _, s := range uuidCtx.ReferencedSymbols {
		if s == "New" {
			hasNew = true
		}
	}
	if !hasNew {
		t.Errorf("expected referenced symbol 'New' in uuid symbols, got %v", uuidCtx.ReferencedSymbols)
	}

	// Case 2: Blank import -> Potentially Reachable
	blankCtx := AssessReachability(tempDir, "github.com/blank/imported", "Go", true)
	if blankCtx.Status != ReachabilityPotentiallyReachable {
		t.Errorf("expected status %s for blank import, got %s", ReachabilityPotentiallyReachable, blankCtx.Status)
	}
	if !strings.Contains(blankCtx.Rationale, "blank import") {
		t.Errorf("expected rationale to mention blank import, got: %s", blankCtx.Rationale)
	}

	// Case 3: Unused direct dependency -> Unreachable
	unusedCtx := AssessReachability(tempDir, "github.com/unused/direct", "Go", true)
	if unusedCtx.Status != ReachabilityUnreachable {
		t.Errorf("expected status %s for unused direct dep, got %s", ReachabilityUnreachable, unusedCtx.Status)
	}
	if unusedCtx.DependencyType != DependencyTypeDirect {
		t.Errorf("expected DependencyTypeDirect for unused direct dep, got %s", unusedCtx.DependencyType)
	}

	// Case 4: Transitive dependency not imported -> Unreachable
	transCtx := AssessReachability(tempDir, "github.com/stretchr/testify", "Go", false)
	if transCtx.Status != ReachabilityUnreachable {
		t.Errorf("expected status %s for unused transitive dep, got %s", ReachabilityUnreachable, transCtx.Status)
	}
	if transCtx.DependencyType != DependencyTypeTransitive {
		t.Errorf("expected DependencyTypeTransitive, got %s", transCtx.DependencyType)
	}
}

func TestNpmReachabilityAnalysis(t *testing.T) {
	tempDir := t.TempDir()

	packageJSON := `{
  "name": "web-app",
  "dependencies": {
    "lodash": "^4.17.21",
    "left-pad": "^1.3.0"
  }
}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJSON), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	indexJs := `import { map } from 'lodash';
const result = map([1, 2, 3], n => n * 2);
console.log(result);
`
	if err := os.WriteFile(filepath.Join(tempDir, "index.js"), []byte(indexJs), 0644); err != nil {
		t.Fatalf("write index.js: %v", err)
	}

	// lodash is imported -> Reachable
	lodashCtx := AssessReachability(tempDir, "lodash", "npm", true)
	if lodashCtx.Status != ReachabilityReachable {
		t.Errorf("expected Reachable for lodash, got %s", lodashCtx.Status)
	}

	// left-pad is not imported -> Unreachable
	leftPadCtx := AssessReachability(tempDir, "left-pad", "npm", true)
	if leftPadCtx.Status != ReachabilityUnreachable {
		t.Errorf("expected Unreachable for left-pad, got %s", leftPadCtx.Status)
	}
}

func TestPythonReachabilityAnalysis(t *testing.T) {
	tempDir := t.TempDir()

	reqs := `requests==2.31.0
flask==3.0.0
`
	if err := os.WriteFile(filepath.Join(tempDir, "requirements.txt"), []byte(reqs), 0644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}

	appPy := `import requests

resp = requests.get('https://example.com')
print(resp.status_code)
`
	if err := os.WriteFile(filepath.Join(tempDir, "app.py"), []byte(appPy), 0644); err != nil {
		t.Fatalf("write app.py: %v", err)
	}

	// requests is imported -> Reachable
	reqCtx := AssessReachability(tempDir, "requests", "PyPI", true)
	if reqCtx.Status != ReachabilityReachable {
		t.Errorf("expected Reachable for requests, got %s", reqCtx.Status)
	}

	// flask is not imported -> Unreachable
	flaskCtx := AssessReachability(tempDir, "flask", "PyPI", true)
	if flaskCtx.Status != ReachabilityUnreachable {
		t.Errorf("expected Unreachable for flask, got %s", flaskCtx.Status)
	}
}

func TestEnrichFindingWithReachability(t *testing.T) {
	finding := review.Finding{
		Rule:     "dependency-cve",
		Severity: "high",
		File:     "go.mod",
		Message:  "CVE-2024-1234 in github.com/example/lib",
	}

	ctx := ReachabilityContext{
		Package:           "github.com/example/lib",
		Ecosystem:         "Go",
		DependencyType:    DependencyTypeDirect,
		Status:            ReachabilityReachable,
		Rationale:         "Direct dependency imported in main.go with symbol calls: Client, Connect",
		ImportedBy:        []string{"main.go"},
		ReferencedSymbols: []string{"Client", "Connect"},
		CallSitesCount:    2,
	}

	EnrichFindingWithReachability(&finding, ctx)

	if finding.Reachability != "Reachable" {
		t.Errorf("expected finding.Reachability to be 'Reachable', got %q", finding.Reachability)
	}
	if finding.Metadata == nil {
		t.Fatalf("expected finding.Metadata to be non-nil")
	}
	if finding.Metadata["reachability"] != "Reachable" {
		t.Errorf("metadata reachability = %q, want 'Reachable'", finding.Metadata["reachability"])
	}
	if finding.Metadata["dependency_type"] != "direct" {
		t.Errorf("metadata dependency_type = %q, want 'direct'", finding.Metadata["dependency_type"])
	}
	if finding.Metadata["referenced_symbols"] != "Client,Connect" {
		t.Errorf("metadata referenced_symbols = %q, want 'Client,Connect'", finding.Metadata["referenced_symbols"])
	}

	if len(finding.Evidence) == 0 {
		t.Fatalf("expected evidence to be attached")
	}
	ev := finding.Evidence[0]
	if ev.Analyzer != "reachability-analyzer" {
		t.Errorf("evidence analyzer = %q, want 'reachability-analyzer'", ev.Analyzer)
	}
}
