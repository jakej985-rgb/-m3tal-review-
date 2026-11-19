package plugin

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSanitizePluginEnv(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"GITHUB_TOKEN=my_sample_token_val",
		"AWS_SECRET_ACCESS_KEY=my_sample_secret_key",
		"DATABASE_PASSWORD=mypassword",
		"AUTH_HEADER=Bearer token",
		"M3TAL_INTERNAL_KEY=privkey",
		"USER=testuser",
		"LANG=en_US.UTF-8",
	}

	sanitized := sanitizePluginEnv(env)
	joined := strings.Join(sanitized, "\n")

	if strings.Contains(joined, "my_sample_token_val") {
		t.Errorf("sanitized env leaked GITHUB_TOKEN: %s", joined)
	}
	if strings.Contains(joined, "my_sample_secret_key") {
		t.Errorf("sanitized env leaked AWS_SECRET_ACCESS_KEY: %s", joined)
	}
	if strings.Contains(joined, "mypassword") {
		t.Errorf("sanitized env leaked DATABASE_PASSWORD: %s", joined)
	}
	if strings.Contains(joined, "AUTH_HEADER") {
		t.Errorf("sanitized env leaked AUTH_HEADER: %s", joined)
	}
	if strings.Contains(joined, "M3TAL_INTERNAL_KEY") {
		t.Errorf("sanitized env leaked M3TAL_INTERNAL_KEY: %s", joined)
	}

	// Verify safe variables preserved
	if !strings.Contains(joined, "PATH=/usr/bin:/bin") {
		t.Errorf("sanitized env dropped PATH")
	}
	if !strings.Contains(joined, "HOME=/home/user") {
		t.Errorf("sanitized env dropped HOME")
	}
}

func TestExecutePluginTimeout(t *testing.T) {
	mock := &mockHangingPlugin{
		meta: PluginMetadata{Name: "hanging-analyzer", Version: "1.0"},
	}

	ctx := context.Background()
	in := PluginInput{
		Timeout: 50 * time.Millisecond,
	}

	out := ExecutePlugin(ctx, mock, in)
	if out.Success {
		t.Fatalf("expected hanging plugin to fail, got success")
	}
	if !strings.Contains(out.Error, "exceeded timeout") {
		t.Fatalf("expected timeout error message, got: %s", out.Error)
	}
	if len(out.Checks) == 0 || out.Checks[0].Status != "failed" {
		t.Fatalf("expected failed check result on timeout, got: %+v", out.Checks)
	}
}

func TestExecutePluginPanicRecovery(t *testing.T) {
	mock := &mockPanickingPlugin{
		meta: PluginMetadata{Name: "panicking-analyzer", Version: "1.0"},
	}

	ctx := context.Background()
	in := PluginInput{Timeout: 1 * time.Second}

	out := ExecutePlugin(ctx, mock, in)
	if out.Success {
		t.Fatalf("expected panicking plugin to fail, got success")
	}
	if !strings.Contains(out.Error, "panicked") {
		t.Fatalf("expected panic error message, got: %s", out.Error)
	}
}

type mockHangingPlugin struct {
	meta PluginMetadata
}

func (m *mockHangingPlugin) Metadata() PluginMetadata         { return m.meta }
func (m *mockHangingPlugin) Capabilities() PluginCapabilities { return PluginCapabilities{} }
func (m *mockHangingPlugin) Analyze(ctx context.Context, in PluginInput) (PluginOutput, error) {
	<-ctx.Done()
	return PluginOutput{}, ctx.Err()
}

type mockPanickingPlugin struct {
	meta PluginMetadata
}

func (m *mockPanickingPlugin) Metadata() PluginMetadata         { return m.meta }
func (m *mockPanickingPlugin) Capabilities() PluginCapabilities { return PluginCapabilities{} }
func (m *mockPanickingPlugin) Analyze(ctx context.Context, in PluginInput) (PluginOutput, error) {
	panic("unexpected fatal plugin exception")
}
