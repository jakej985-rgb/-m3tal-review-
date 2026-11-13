package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

type mockPlugin struct {
	meta      PluginMetadata
	caps      PluginCapabilities
	analyzeFn func(ctx context.Context, in PluginInput) (PluginOutput, error)
}

func (m *mockPlugin) Metadata() PluginMetadata {
	return m.meta
}

func (m *mockPlugin) Capabilities() PluginCapabilities {
	return m.caps
}

func (m *mockPlugin) Analyze(ctx context.Context, in PluginInput) (PluginOutput, error) {
	if m.analyzeFn != nil {
		return m.analyzeFn(ctx, in)
	}
	return PluginOutput{Success: true}, nil
}

func TestPluginValidation(t *testing.T) {
	tests := []struct {
		name    string
		meta    PluginMetadata
		caps    PluginCapabilities
		wantErr bool
	}{
		{
			name:    "valid plugin",
			meta:    PluginMetadata{Name: "custom-analyzer", Version: "1.0.0"},
			caps:    PluginCapabilities{Scopes: []string{"staged"}, Categories: []string{"security"}},
			wantErr: false,
		},
		{
			name:    "missing name",
			meta:    PluginMetadata{Name: "", Version: "1.0.0"},
			wantErr: true,
		},
		{
			name:    "invalid name characters",
			meta:    PluginMetadata{Name: "invalid name!", Version: "1.0.0"},
			wantErr: true,
		},
		{
			name:    "invalid semver",
			meta:    PluginMetadata{Name: "valid-name", Version: "not-semver"},
			wantErr: true,
		},
		{
			name:    "unsupported scope",
			meta:    PluginMetadata{Name: "valid-name", Version: "1.2.3"},
			caps:    PluginCapabilities{Scopes: []string{"invalid-scope"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &mockPlugin{meta: tt.meta, caps: tt.caps}
			err := ValidatePlugin(p)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePlugin() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExecutePluginPanicIsolation(t *testing.T) {
	p := &mockPlugin{
		meta: PluginMetadata{Name: "panicking-plugin", Version: "1.0.0"},
		analyzeFn: func(ctx context.Context, in PluginInput) (PluginOutput, error) {
			panic("unexpected internal crash inside plugin!")
		},
	}

	ctx := context.Background()
	in := PluginInput{RepositoryRoot: "/tmp", Scope: "staged"}
	out := ExecutePlugin(ctx, p, in)

	if out.Success {
		t.Fatalf("expected out.Success to be false, got true")
	}
	if len(out.Checks) == 0 {
		t.Fatalf("expected at least one check result")
	}
	if out.Checks[0].Status != "failed" {
		t.Errorf("expected check status 'failed', got %q", out.Checks[0].Status)
	}
	if len(out.Findings) == 0 {
		t.Fatalf("expected finding reporting failure")
	}
}

func TestExecutePluginTimeoutBounded(t *testing.T) {
	p := &mockPlugin{
		meta: PluginMetadata{Name: "hanging-plugin", Version: "1.0.0"},
		analyzeFn: func(ctx context.Context, in PluginInput) (PluginOutput, error) {
			select {
			case <-time.After(2 * time.Second):
				return PluginOutput{Success: true}, nil
			case <-ctx.Done():
				return PluginOutput{}, ctx.Err()
			}
		},
	}

	ctx := context.Background()
	in := PluginInput{
		RepositoryRoot: "/tmp",
		Scope:          "staged",
		Timeout:        50 * time.Millisecond,
	}

	start := time.Now()
	out := ExecutePlugin(ctx, p, in)
	elapsed := time.Since(start)

	if out.Success {
		t.Fatalf("expected out.Success to be false on timeout")
	}
	if elapsed > 1*time.Second {
		t.Errorf("execution took %v, expected timeout around 50ms", elapsed)
	}
	if len(out.Checks) == 0 || out.Checks[0].Status != "failed" {
		t.Errorf("expected failed check for timeout")
	}
}

func TestNormalizePluginFindings(t *testing.T) {
	repoRoot := t.TempDir()
	filePath := filepath.Join(repoRoot, "src", "app.go")
	findings := []review.Finding{
		{
			Rule:     "",
			File:     filePath,
			Line:     -5,
			Severity: "WARN",
			Category: "UNKNOWN",
			Message:  "  test finding  ",
		},
	}

	norm := NormalizePluginFindings("my-plugin", findings, repoRoot)
	if len(norm) != 1 {
		t.Fatalf("expected 1 normalized finding, got %d", len(norm))
	}
	f := norm[0]
	if f.Rule != "plugin-my-plugin" {
		t.Errorf("expected default rule 'plugin-my-plugin', got %q", f.Rule)
	}
	if f.File != "src/app.go" {
		t.Errorf("expected relative path 'src/app.go', got %q", f.File)
	}
	if f.Line != 0 {
		t.Errorf("expected line 0 (bounded from negative), got %d", f.Line)
	}
	if f.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %q", f.Severity)
	}
	if f.Category != "security" {
		t.Errorf("expected category 'security', got %q", f.Category)
	}
	if len(f.Analyzers) != 1 || f.Analyzers[0] != "my-plugin" {
		t.Errorf("expected Analyzers to contain 'my-plugin', got %v", f.Analyzers)
	}
}

func TestRegistryManagementAndFilter(t *testing.T) {
	reg := NewRegistry()

	p1 := &mockPlugin{
		meta: PluginMetadata{Name: "go-sec", Version: "1.0.0"},
		caps: PluginCapabilities{Scopes: []string{"staged"}, Languages: []string{"go"}},
	}
	p2 := &mockPlugin{
		meta: PluginMetadata{Name: "py-lint", Version: "1.0.0"},
		caps: PluginCapabilities{Scopes: []string{"working-tree"}, Languages: []string{"py"}},
	}

	if err := reg.Register(p1); err != nil {
		t.Fatalf("Register p1: %v", err)
	}
	if err := reg.Register(p2); err != nil {
		t.Fatalf("Register p2: %v", err)
	}

	// Duplicate registration error
	if err := reg.Register(p1); err == nil {
		t.Fatalf("expected error registering duplicate plugin")
	}

	if len(reg.List()) != 2 {
		t.Errorf("expected 2 plugins in list, got %d", len(reg.List()))
	}

	// Test RunPlugins scope and file pattern filtering
	inStagedGo := PluginInput{
		Scope: "staged",
		Files: []string{"main.go"},
	}
	findings, checks := reg.RunPlugins(context.Background(), inStagedGo)
	if len(checks) != 1 || checks[0].Name != "go-sec" {
		t.Errorf("expected only go-sec to run for staged go file, got %v", checks)
	}
	_ = findings
}

func TestExecPluginWithManifest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test plugin is a POSIX shell script that cannot execute on Windows")
	}
	tempDir := t.TempDir()

	// Create a dummy mock executable script
	scriptPath := filepath.Join(tempDir, "mock_plugin.sh")
	scriptContent := `#!/bin/sh
echo '{"success":true,"findings":[{"rule":"mock-rule","file":"test.go","line":10,"severity":"high","message":"mock finding"}]}'
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0755); err != nil {
		t.Fatalf("write script: %v", err)
	}

	manifest := Manifest{
		Name:       "script-plugin",
		Version:    "1.0.0",
		Executable: "mock_plugin.sh",
		Capabilities: PluginCapabilities{
			Scopes:    []string{"staged", "working-tree"},
			Languages: []string{"go"},
		},
	}
	data, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(tempDir, "script-plugin.json")
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	plugins, err := DiscoverPlugins(tempDir)
	if err != nil {
		t.Fatalf("DiscoverPlugins: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 discovered plugin, got %d", len(plugins))
	}

	out := ExecutePlugin(context.Background(), plugins[0], PluginInput{RepositoryRoot: tempDir, Scope: "staged"})
	if !out.Success {
		t.Fatalf("expected success, got error: %s", out.Error)
	}
	if len(out.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out.Findings))
	}
	if out.Findings[0].Rule != "mock-rule" {
		t.Errorf("expected rule 'mock-rule', got %q", out.Findings[0].Rule)
	}
}

func TestDiscoverPluginsAllowlistedNeverProbesUnlisted(t *testing.T) {
	tempDir := t.TempDir()
	marker := filepath.Join(tempDir, "probed.marker")
	// The binary touches the marker on ANY execution, including --manifest
	// probes during discovery.
	script := "#!/bin/sh\ntouch \"" + marker + "\"\necho '{\"name\":\"evil\",\"version\":\"1.0.0\"}'\n"
	binPath := filepath.Join(tempDir, "m3tal-review-plugin-evil")
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write plugin: %v", err)
	}

	// Wrong hash: nothing is discovered and the binary is never executed.
	plugins, err := DiscoverPluginsAllowlisted(tempDir, map[string]bool{
		"0000000000000000000000000000000000000000000000000000000000000000": true,
	})
	if err != nil {
		t.Fatalf("DiscoverPluginsAllowlisted: %v", err)
	}
	if len(plugins) != 0 {
		t.Fatalf("expected 0 plugins, got %d", len(plugins))
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("unlisted plugin binary was executed during discovery")
	}

	// Correct hash: discovered normally.
	data, _ := os.ReadFile(binPath)
	sum := sha256.Sum256(data)
	plugins, err = DiscoverPluginsAllowlisted(tempDir, map[string]bool{
		hex.EncodeToString(sum[:]): true,
	})
	if err != nil {
		t.Fatalf("DiscoverPluginsAllowlisted: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}

	// Empty allowlist discovers nothing and never probes.
	os.Remove(marker)
	plugins, err = DiscoverPluginsAllowlisted(tempDir, nil)
	if err != nil {
		t.Fatalf("DiscoverPluginsAllowlisted nil: %v", err)
	}
	if len(plugins) != 0 {
		t.Fatalf("expected 0 plugins for nil allowlist, got %d", len(plugins))
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("nil allowlist still probed the plugin binary")
	}
}
