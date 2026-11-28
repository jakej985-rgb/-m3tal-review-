package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/apps"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/golang"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/ts"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
	"github.com/jakej985-rgb/m3tal-review/protocol"
)

func TestDetectionAndPlanningCLICommands(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := runScanCommand([]string{root, "--format", "json"}); err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if err := runDetectCommand([]string{root, "--format", "json"}); err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if err := runLanguagesCommand([]string{"--format", "json"}); err != nil {
		t.Fatalf("languages failed: %v", err)
	}
	if err := runAnalyzersCommand([]string{"--language", "go", "--format", "json"}); err != nil {
		t.Fatalf("analyzers failed: %v", err)
	}
	if err := runExplainCommand([]string{root, "--profile", "security", "--format", "json"}); err != nil {
		t.Fatalf("explain failed: %v", err)
	}
	if err := runMultiLangCheckCommand([]string{root, "--profile", "security", "--format", "json"}); err != nil {
		t.Fatalf("check failed on clean repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "bad.go"), []byte("package main\nfunc f() {\n\tif true {\n\t}\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := runMultiLangCheckCommand([]string{root, "--profile", "fast", "--format", "json"}); err == nil {
		t.Fatalf("expected check to return error when findings exist")
	}
}

func TestCheckMarksOversizedSkippedFilesIncomplete(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.com/big\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	huge := append([]byte("package main\n// "), make([]byte, (2<<20)+1024)...)
	for i := 16; i < len(huge); i++ {
		huge[i] = 'a'
	}
	if err := os.WriteFile(filepath.Join(root, "huge.go"), huge, 0644); err != nil {
		t.Fatal(err)
	}
	err := runMultiLangCheckCommand([]string{root, "--profile", "fast", "--format", "json"})
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("expected incomplete error when oversized file is skipped, got %v", err)
	}
}

func TestCollectAppOutputsAndDeduplication(t *testing.T) {
	rep := apps.RunReport{
		Findings: []protocol.Finding{
			{Rule: "ts/security/eval-injection", Category: protocol.CategorySecurity, File: "app.ts", Line: 2},
			{Rule: "ts/security/eval-injection", Category: protocol.CategorySecurity, File: "app.ts", Line: 99},
		},
	}
	added := map[string][]int{"app.ts": {2}}
	appFindings, _, _, _, _ := collectAppOutputs(rep, nil, nil, added)
	if len(appFindings) != 1 || appFindings[0].Line != 2 {
		t.Fatalf("expected AddedLines enforcement to keep only line 2, got %+v", appFindings)
	}

	legacy := []review.Finding{
		{Rule: "eval-injection", Category: "security", File: "app.ts", Line: 2},
		{Rule: "hardcoded-credential", Category: "security", File: "app.ts", Line: 2},
		{Rule: "tls-verification", Category: "security", File: "app.ts", Line: 5},
	}
	merged := dedupeAppAndLegacyFindings(legacy, appFindings)
	if len(merged) != 3 {
		t.Fatalf("expected 3 merged findings (hardcoded-credential + tls-verification + app eval-call), got %+v", merged)
	}
	if merged[0].Rule != "hardcoded-credential" || merged[1].Rule != "tls-verification" || merged[2].Rule != "ts/security/eval-injection" {
		t.Fatalf("unexpected merged order/rules: %+v", merged)
	}
}

func TestDedupeRealLegacyAndAppOutputs(t *testing.T) {
	tsSrc := "eval(input)\n"
	goSrc := "package main\nimport \"crypto/tls\"\nvar c = &tls.Config{InsecureSkipVerify: true}\n"
	diff := "diff --git a/app.ts b/app.ts\nnew file mode 100644\n--- /dev/null\n+++ b/app.ts\n@@ -0,0 +1 @@\n+eval(input)\n" +
		"diff --git a/tls.go b/tls.go\nnew file mode 100644\n--- /dev/null\n+++ b/tls.go\n@@ -0,0 +1,3 @@\n+package main\n+import \"crypto/tls\"\n+var c = &tls.Config{InsecureSkipVerify: true}\n"

	engine := review.NewEngine(review.EvalRule{}, review.TLSRule{})
	legacyFindings := engine.Run(diff)

	var appFindings []review.Finding
	tsOut := (ts.App{}).Run(protocol.Input{
		Protocol: protocol.Version,
		Files:    []protocol.File{{Path: "app.ts", Status: "added", Content: tsSrc}},
	})
	for _, f := range tsOut.Findings {
		appFindings = append(appFindings, protocolToReviewFinding(f))
	}
	goOut := golang.Run(protocol.Input{
		Protocol: protocol.Version,
		Files:    []protocol.File{{Path: "tls.go", Status: "added", Content: goSrc}},
	})
	for _, f := range goOut.Findings {
		appFindings = append(appFindings, protocolToReviewFinding(f))
	}

	merged := dedupeAppAndLegacyFindings(legacyFindings, appFindings)
	if len(merged) != 2 {
		t.Fatalf("expected 2 deduplicated findings (ts/security/eval-call and go/security/tls-insecure-skip-verify), got %+v", merged)
	}
	for _, f := range merged {
		if f.Rule == "dangerous-eval" || f.Rule == "insecure-tls-verification" {
			t.Fatalf("expected legacy alias %q to be deduplicated, got %+v", f.Rule, merged)
		}
	}
}
