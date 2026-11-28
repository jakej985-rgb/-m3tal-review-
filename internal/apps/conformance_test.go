//go:build !windows

package apps

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

func TestLanguageAppsConformance(t *testing.T) {
	binDir := t.TempDir()

	type appCase struct {
		name         string
		pkg          string
		manifestPath string
		cleanFile    protocol.File
		badFile      protocol.File
		wantRule     string
	}

	cases := []appCase{
		{
			name:         "review-go",
			pkg:          "../../cmd/m3tal-review-go",
			manifestPath: "../../internal/apps/golang/review-app.json",
			cleanFile:    protocol.File{Path: "clean.go", Status: "added", Content: "package clean\nfunc ok() int { return 1 }\n"},
			badFile:      protocol.File{Path: "bad.go", Status: "added", Content: "package bad\nfunc f() {\n\tif true {\n\t}\n}\n"},
			wantRule:     "go/bug/empty-branch",
		},
		{
			name:         "review-ts",
			pkg:          "../../cmd/m3tal-review-ts",
			manifestPath: "../../internal/apps/ts/review-app.json",
			cleanFile:    protocol.File{Path: "clean.ts", Status: "added", Content: "export const ok = (x: number): number => x + 1;\n"},
			badFile:      protocol.File{Path: "bad.ts", Status: "added", Content: "export const x: any = 1;\n"},
			wantRule:     "ts/slop/explicit-any",
		},
		{
			name:         "review-python",
			pkg:          "../../cmd/m3tal-review-python",
			manifestPath: "../../internal/apps/python/review-app.json",
			cleanFile:    protocol.File{Path: "clean.py", Status: "added", Content: "def ok(x: int) -> int:\n    return x + 1\n"},
			badFile:      protocol.File{Path: "bad.py", Status: "added", Content: "def f(x=[]):\n    return x\n"},
			wantRule:     "py/bug/mutable-default-arg",
		},
		{
			name:         "review-shell",
			pkg:          "../../cmd/m3tal-review-shell",
			manifestPath: "../../internal/apps/shell/review-app.json",
			cleanFile:    protocol.File{Path: "clean.sh", Status: "added", Content: "#!/usr/bin/env bash\nset -euo pipefail\necho ok\n"},
			badFile:      protocol.File{Path: ".github/workflows/ci.yml", Status: "added", Content: "permissions: write-all\n"},
			wantRule:     "shell/security/actions-write-all",
		},
		{
			name:         "review-repo",
			pkg:          "../../cmd/m3tal-review-repo",
			manifestPath: "../../internal/apps/repo/review-app.json",
			cleanFile:    protocol.File{Path: ".env.example", Status: "added", Content: "API_KEY=changeme\n"},
			badFile:      protocol.File{Path: ".env", Status: "added", Content: "API_KEY=supersecret12345\n"},
			wantRule:     "repo/security/env-secret-committed",
		},
		{
			name:         "review-rust",
			pkg:          "../../cmd/m3tal-review-rust",
			manifestPath: "../../internal/apps/rust/review-app.json",
			cleanFile:    protocol.File{Path: "src/lib.rs", Status: "added", Content: "pub fn ok(x: i32) -> i32 { x + 1 }\n"},
			badFile:      protocol.File{Path: "src/lib.rs", Status: "added", Content: "pub fn bad() { unsafe { let _ = 1; } }\n"},
			wantRule:     "rust/security/unsafe-without-safety",
		},
		{
			name:         "review-cpp",
			pkg:          "../../cmd/m3tal-review-cpp",
			manifestPath: "../../internal/apps/cpp/review-app.json",
			cleanFile:    protocol.File{Path: "src/ok.cpp", Status: "added", Content: "int ok(int x) { return x + 1; }\n"},
			badFile:      protocol.File{Path: "src/bad.c", Status: "added", Content: "void f(char *dst, const char *src) { strcpy(dst, src); }\n"},
			wantRule:     "cpp/security/unbounded-buffer",
		},
		{
			name:         "review-jvm",
			pkg:          "../../cmd/m3tal-review-jvm",
			manifestPath: "../../internal/apps/jvm/review-app.json",
			cleanFile:    protocol.File{Path: "App.kt", Status: "added", Content: "fun ok(x: Int): Int = x + 1\n"},
			badFile:      protocol.File{Path: "App.kt", Status: "added", Content: "fun bad() { GlobalScope.launch { } }\n"},
			wantRule:     "jvm/bug/coroutine-global-scope",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			binPath := filepath.Join(binDir, "m3tal-"+tc.name)
			if out, err := exec.Command("go", "build", "-o", binPath, tc.pkg).CombinedOutput(); err != nil {
				t.Fatalf("build %s: %v\n%s", tc.pkg, err, string(out))
			}

			// 1. Describe handshake & manifest parity
			app, err := Describe(context.Background(), binPath)
			if err != nil {
				t.Fatalf("Describe failed: %v", err)
			}
			m, err := LoadManifest(tc.manifestPath)
			if err != nil {
				t.Fatalf("LoadManifest failed: %v", err)
			}
			if app.Name != m.Name || app.Version != m.Version {
				t.Fatalf("describe (%s %s) != manifest (%s %s)", app.Name, app.Version, m.Name, m.Version)
			}

			// 2. Clean input -> exit 0
			cleanPayload, _ := json.Marshal(protocol.Input{
				Protocol: protocol.Version,
				Run:      protocol.RunInfo{Root: ".", Scope: "staged", Mode: "review"},
				Files:    []protocol.File{tc.cleanFile},
			})
			stdout, stderr, code, _ := runProcess(context.Background(), binPath, nil, cleanPayload, protocol.MaxStdoutBytes, DefaultTimeout)
			if code != protocol.ExitClean {
				t.Fatalf("clean input expected exit 0, got %d (stderr: %s)", code, stderr)
			}
			out, err := protocol.DecodeOutput(stdout, app.Name, map[string]struct{}{tc.cleanFile.Path: {}})
			if err != nil {
				t.Fatalf("clean DecodeOutput failed: %v", err)
			}
			if len(out.Findings) != 0 {
				t.Fatalf("expected 0 findings on clean input, got %+v", out.Findings)
			}

			// 3. Bad input -> exit 1 + expected rule
			badPayload, _ := json.Marshal(protocol.Input{
				Protocol: protocol.Version,
				Run:      protocol.RunInfo{Root: ".", Scope: "staged", Mode: "review"},
				Files:    []protocol.File{tc.badFile},
			})
			stdout, stderr, code, _ = runProcess(context.Background(), binPath, nil, badPayload, protocol.MaxStdoutBytes, DefaultTimeout)
			if code != protocol.ExitFindings {
				t.Fatalf("bad input expected exit 1, got %d (stderr: %s)", code, stderr)
			}
			out, err = protocol.DecodeOutput(stdout, app.Name, map[string]struct{}{tc.badFile.Path: {}})
			if err != nil {
				t.Fatalf("bad DecodeOutput failed: %v", err)
			}
			found := false
			for _, f := range out.Findings {
				if f.Rule == tc.wantRule {
					found = true
				}
			}
			if !found {
				t.Fatalf("expected rule %q in findings, got %+v", tc.wantRule, out.Findings)
			}

			// 4. Malformed stdin -> exit 4
			_, _, code, _ = runProcess(context.Background(), binPath, nil, []byte("not-json"), protocol.MaxStdoutBytes, DefaultTimeout)
			if code != protocol.ExitProtocol {
				t.Fatalf("malformed stdin expected exit 4, got %d", code)
			}
		})
	}
}

func TestRouteFilePatternsForShellWorkflow(t *testing.T) {
	reg, err := LoadRegistry()
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	appsList := []App{
		{
			Name:         "review-shell",
			Extensions:   []string{".sh"},
			FilePatterns: []string{".github/workflows/*.yml", "Dockerfile"},
		},
	}
	files := []protocol.File{
		{Path: ".github/workflows/ci.yml", Status: "added", Content: "permissions: write-all\n"},
		{Path: "Dockerfile", Status: "added", Content: "FROM alpine:3.19\n"},
		{Path: "README.md", Status: "added", Content: "# hi\n"},
	}
	plan := Route(appsList, reg, files)
	routed := plan.ByApp["review-shell"]
	if len(routed) != 2 {
		t.Fatalf("expected 2 files routed to review-shell, got %d: %+v", len(routed), routed)
	}
}
