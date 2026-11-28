//go:build !windows

package apps

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

func TestDeletionGateMissingGoApp(t *testing.T) {
	emptyDir := t.TempDir()
	rep, err := Run(context.Background(), RunConfig{
		Root:     t.TempDir(),
		AppPaths: []string{emptyDir},
	}, []protocol.File{
		{Path: "main.go", Status: "added", Content: "package main\n"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.ExitCode != protocol.ExitError {
		t.Fatalf("expected exit %d, got %d", protocol.ExitError, rep.ExitCode)
	}
	if len(rep.MissingClaims) != 1 || !strings.Contains(rep.MissingClaims[0].String(), "no app for .go files") {
		t.Fatalf("expected missing claim for .go files, got %+v", rep.MissingClaims)
	}
	if len(rep.UnanalyzedFiles) != 1 || rep.UnanalyzedFiles[0] != "main.go" {
		t.Fatalf("expected main.go in unanalyzed_files, got %+v", rep.UnanalyzedFiles)
	}
}

func TestDiscoveryRefusesRepoLocalApp(t *testing.T) {
	repoDir := t.TempDir()
	writeFakeApp(t, repoDir, "review-fake", `#!/bin/sh
if [ "$1" = "--describe" ]; then
  echo '{"protocol":"review-app/1","kind":"review-app","app":{"name":"review-fake","version":"0.1.0"},"extensions":[".fake"],"inputs":["content"]}'
  exit 0
fi
`)
	discovered, diags, err := Discover(context.Background(), RunConfig{
		Root:     repoDir,
		AppPaths: []string{repoDir},
	})
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if len(discovered) != 0 {
		t.Fatalf("expected 0 discovered apps (repo-local refused), got %d", len(discovered))
	}
	if len(diags) == 0 || !strings.Contains(diags[0].Message, "refused repo-local app") {
		t.Fatalf("expected refused repo-local diagnostic, got %+v", diags)
	}
}

func TestDiscoveryRefusesRelativeRepoAppPath(t *testing.T) {
	repoDir := t.TempDir()
	toolsDir := filepath.Join(repoDir, "tools")
	if err := os.MkdirAll(toolsDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFakeApp(t, toolsDir, "review-fake", "#!/bin/sh\necho ok\n")
	origWD, _ := os.Getwd()
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })
	t.Setenv("REVIEW_APPS_PATH", "tools")

	discovered, diags, err := Discover(context.Background(), RunConfig{Root: repoDir})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(discovered) != 0 {
		t.Fatalf("expected 0 discovered apps for relative repo path, got %d", len(discovered))
	}
	if len(diags) == 0 || !strings.Contains(diags[0].Message, "refused repo-local app") {
		t.Fatalf("expected refused repo-local diagnostic, got %+v", diags)
	}
}

func TestHostileAppsAndPartialResults(t *testing.T) {
	appDir := t.TempDir()
	// Good app for .good files
	writeFakeApp(t, appDir, "review-good", `#!/bin/sh
if [ "$1" = "--describe" ]; then
  echo '{"protocol":"review-app/1","kind":"review-app","app":{"name":"review-good","version":"0.1.0"},"extensions":[".good"],"inputs":["content"]}'
  exit 0
fi
cat >/dev/null
echo '{"protocol":"review-app/1","app":{"name":"review-good","version":"0.1.0"},"findings":[{"rule":"good/bug/one","category":"bug","severity":"medium","file":"a.good","line":1,"message":"found one"}],"stats":{"files":1,"rules":1}}'
exit 1
`)
	// Crashing app for .crash files
	writeFakeApp(t, appDir, "review-crash", `#!/bin/sh
if [ "$1" = "--describe" ]; then
  echo '{"protocol":"review-app/1","kind":"review-app","app":{"name":"review-crash","version":"0.1.0"},"extensions":[".crash"],"inputs":["content"]}'
  exit 0
fi
echo "boom" >&2
exit 2
`)
	// Bad protocol app for .badproto files
	writeFakeApp(t, appDir, "review-badproto", `#!/bin/sh
if [ "$1" = "--describe" ]; then
  echo '{"protocol":"review-app/1","kind":"review-app","app":{"name":"review-badproto","version":"0.1.0"},"extensions":[".badproto"],"inputs":["content"]}'
  exit 0
fi
echo 'not json'
exit 0
`)

	rep, err := Run(context.Background(), RunConfig{
		Root:     t.TempDir(),
		AppPaths: []string{appDir},
		Timeout:  2 * time.Second,
	}, []protocol.File{
		{Path: "a.good", Status: "added", Content: "x"},
		{Path: "b.crash", Status: "added", Content: "x"},
		{Path: "c.badproto", Status: "added", Content: "x"},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if rep.ExitCode != protocol.ExitProtocol {
		t.Fatalf("expected exit precedence 4 (protocol), got %d", rep.ExitCode)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Rule != "good/bug/one" {
		t.Fatalf("expected partial result from review-good, got %+v", rep.Findings)
	}
}

func TestEndToEndWithRealReviewGoBinary(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "m3tal-review-go")
	cmd := exec.Command("go", "build", "-o", binPath, "../../cmd/m3tal-review-go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build m3tal-review-go: %v\n%s", err, string(out))
	}

	rep, err := Run(context.Background(), RunConfig{
		Root:     t.TempDir(),
		AppPaths: []string{binDir},
	}, []protocol.File{
		{
			Path:    "main.go",
			Status:  "added",
			Content: "package main\nfunc f() {\n\tif true {\n\t}\n}\n",
		},
	})
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if rep.ExitCode != protocol.ExitFindings {
		t.Fatalf("expected exit 1 (findings), got %d", rep.ExitCode)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Rule != "go/bug/empty-branch" {
		t.Fatalf("expected go/bug/empty-branch, got %+v", rep.Findings)
	}
}

func writeFakeApp(t *testing.T, dir, name, script string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(script), 0755); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}
