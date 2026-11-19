package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

// Manifest defines the file-based schema for external plugins.
type Manifest struct {
	Name             string             `json:"name"`
	Version          string             `json:"version"`
	Description      string             `json:"description,omitempty"`
	Author           string             `json:"author,omitempty"`
	License          string             `json:"license,omitempty"`
	MinRunnerVersion string             `json:"min_runner_version,omitempty"`
	Executable       string             `json:"executable"`
	Args             []string           `json:"args,omitempty"`
	Capabilities     PluginCapabilities `json:"capabilities"`
}

// maxPluginOutput bounds captured plugin stdout/stderr. Reviewed
// repositories are untrusted: a plugin flooding output must not exhaust
// memory (mirrors the host runCommand cap in internal/cli/exec.go).
const maxPluginOutput = 1 << 20 // 1 MiB

// cappedBuffer discards bytes past the limit while still reporting the
// full length to the writer contract, so the child never blocks on a
// full pipe.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *cappedBuffer) Bytes() []byte  { return b.buf.Bytes() }
func (b *cappedBuffer) String() string { return b.buf.String() }

// ExecPlugin adapts an external binary into an AnalyzerPlugin.
type ExecPlugin struct {
	meta PluginMetadata
	caps PluginCapabilities
	path string
	args []string
}

// NewExecPlugin creates an executable analyzer plugin.
func NewExecPlugin(meta PluginMetadata, caps PluginCapabilities, path string, args ...string) (*ExecPlugin, error) {
	if err := ValidateExecutable(path); err != nil {
		return nil, err
	}
	p := &ExecPlugin{
		meta: meta,
		caps: caps,
		path: path,
		args: args,
	}
	if err := ValidatePlugin(p); err != nil {
		return nil, err
	}
	return p, nil
}

func (e *ExecPlugin) Metadata() PluginMetadata {
	return e.meta
}

func (e *ExecPlugin) Capabilities() PluginCapabilities {
	return e.caps
}

// ExecutablePath returns the plugin's executable path. It is used for
// allowlist verification of untrusted (repository-local) plugins.
func (e *ExecPlugin) ExecutablePath() string {
	return e.path
}

func (e *ExecPlugin) Analyze(ctx context.Context, in PluginInput) (PluginOutput, error) {
	args := append([]string{}, e.args...)
	cmd := exec.CommandContext(ctx, e.path, args...)
	cmd.Dir = in.RepositoryRoot
	preparePluginCmd(cmd)
	cmd.Env = sanitizePluginEnv(os.Environ())

	inData, err := json.Marshal(in)
	if err != nil {
		return PluginOutput{}, fmt.Errorf("marshal plugin input: %w", err)
	}
	cmd.Stdin = bytes.NewReader(inData)

	var stdout, stderr cappedBuffer
	stdout.limit = maxPluginOutput
	stderr.limit = maxPluginOutput
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	rawOut := stdout.Bytes()

	// Parse structured output from plugin stdout
	var out PluginOutput
	if len(bytes.TrimSpace(rawOut)) > 0 {
		// Attempt to unmarshal full PluginOutput
		if decErr := json.Unmarshal(rawOut, &out); decErr != nil {
			// Fallback: check if plugin returned a bare array of review.Finding
			var bareFindings []review.Finding
			if arrErr := json.Unmarshal(rawOut, &bareFindings); arrErr == nil {
				out.Findings = bareFindings
				out.Success = runErr == nil
			} else {
				return PluginOutput{
					Success:   false,
					RawOutput: rawOut,
					Error:     fmt.Sprintf("invalid plugin json output: %v (stderr: %s)", decErr, strings.TrimSpace(stderr.String())),
				}, runErr
			}
		}
	} else if runErr != nil {
		return PluginOutput{
			Success:   false,
			ExitCode:  cmd.ProcessState.ExitCode(),
			Error:     fmt.Sprintf("plugin exited with error: %v (stderr: %s)", runErr, strings.TrimSpace(stderr.String())),
			RawOutput: rawOut,
		}, runErr
	}

	out.RawOutput = rawOut
	if cmd.ProcessState != nil {
		out.ExitCode = cmd.ProcessState.ExitCode()
	}
	if runErr != nil && out.Error == "" {
		out.Error = runErr.Error()
	}

	return out, nil
}

// DiscoverPlugins scans a directory for executable plugins or manifest files.
func DiscoverPlugins(pluginDir string) ([]AnalyzerPlugin, error) {
	return discoverPlugins(pluginDir, nil)
}

// DiscoverPluginsAllowlisted scans a directory like DiscoverPlugins but only
// considers executables whose SHA-256 (hex, lowercase) is in allowlist. The
// check runs before any --manifest probe, so unlisted binaries are never
// executed. An empty allowlist discovers nothing.
func DiscoverPluginsAllowlisted(pluginDir string, allowlist map[string]bool) ([]AnalyzerPlugin, error) {
	if len(allowlist) == 0 {
		return nil, nil
	}
	return discoverPlugins(pluginDir, func(execPath string) bool {
		data, err := os.ReadFile(execPath)
		if err != nil {
			return false
		}
		sum := sha256.Sum256(data)
		return allowlist[hex.EncodeToString(sum[:])]
	})
}

// discoverPlugins implements plugin discovery. When execAllowed is non-nil it
// is consulted for every candidate executable path before probing or loading,
// which keeps untrusted binaries from being executed during discovery.
func discoverPlugins(pluginDir string, execAllowed func(string) bool) ([]AnalyzerPlugin, error) {
	info, err := os.Stat(pluginDir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("plugin path %s is not a directory", pluginDir)
	}

	entries, err := os.ReadDir(pluginDir)
	if err != nil {
		return nil, fmt.Errorf("read plugin directory: %w", err)
	}

	var discovered []AnalyzerPlugin

	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(pluginDir, name)

		// 1. JSON manifest discovery
		if strings.HasSuffix(name, ".json") && !entry.IsDir() {
			p, err := loadPluginFromManifest(fullPath, pluginDir, execAllowed)
			if err == nil && p != nil {
				discovered = append(discovered, p)
			}
			continue
		}

		// 2. Directory with plugin.json
		if entry.IsDir() {
			manifestPath := filepath.Join(fullPath, "plugin.json")
			if _, statErr := os.Stat(manifestPath); statErr == nil {
				p, err := loadPluginFromManifest(manifestPath, fullPath, execAllowed)
				if err == nil && p != nil {
					discovered = append(discovered, p)
				}
			}
			continue
		}

		// 3. Direct executable plugin binary named m3tal-review-plugin-*
		if strings.HasPrefix(name, "m3tal-review-plugin-") && !entry.IsDir() {
			pluginShortName := strings.TrimPrefix(name, "m3tal-review-plugin-")
			// Verify trust before probing: --manifest executes the binary.
			if execAllowed != nil && !execAllowed(fullPath) {
				continue
			}
			if ValidateExecutable(fullPath) == nil {
				meta, caps, err := probePluginExecutable(fullPath)
				if err != nil {
					meta = PluginMetadata{
						Name:    pluginShortName,
						Version: "1.0.0",
					}
					caps = PluginCapabilities{}
				}
				p, err := NewExecPlugin(meta, caps, fullPath)
				if err == nil {
					discovered = append(discovered, p)
				}
			}
		}
	}

	return discovered, nil
}

func loadPluginFromManifest(manifestPath, baseDir string, execAllowed func(string) bool) (AnalyzerPlugin, error) {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("unmarshal manifest %s: %w", manifestPath, err)
	}

	execPath := manifest.Executable
	if !filepath.IsAbs(execPath) {
		execPath = filepath.Join(baseDir, execPath)
	}
	// Verify trust before the executable is ever run.
	if execAllowed != nil && !execAllowed(execPath) {
		return nil, fmt.Errorf("plugin executable %s is not allowlisted", execPath)
	}

	meta := PluginMetadata{
		Name:             manifest.Name,
		Version:          manifest.Version,
		Description:      manifest.Description,
		Author:           manifest.Author,
		License:          manifest.License,
		MinRunnerVersion: manifest.MinRunnerVersion,
	}

	return NewExecPlugin(meta, manifest.Capabilities, execPath, manifest.Args...)
}

func probePluginExecutable(execPath string) (PluginMetadata, PluginCapabilities, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, execPath, "--manifest")
	out, err := cmd.Output()
	if err != nil {
		return PluginMetadata{}, PluginCapabilities{}, err
	}

	var m Manifest
	if err := json.Unmarshal(out, &m); err != nil {
		return PluginMetadata{}, PluginCapabilities{}, err
	}

	return PluginMetadata{
		Name:             m.Name,
		Version:          m.Version,
		Description:      m.Description,
		Author:           m.Author,
		License:          m.License,
		MinRunnerVersion: m.MinRunnerVersion,
	}, m.Capabilities, nil
}

// sanitizePluginEnv filters the environment variables passed to plugin subprocesses
// to prevent credential or secret leakage into third-party plugins.
func sanitizePluginEnv(environ []string) []string {
	safe := make([]string, 0, len(environ))
	for _, env := range environ {
		idx := strings.IndexByte(env, '=')
		if idx <= 0 {
			continue
		}
		key := strings.ToUpper(env[:idx])
		if strings.Contains(key, "TOKEN") ||
			strings.Contains(key, "SECRET") ||
			strings.Contains(key, "PASSWORD") ||
			strings.Contains(key, "AUTH") ||
			strings.Contains(key, "KEY") ||
			strings.HasPrefix(key, "M3TAL_") {
			continue
		}
		safe = append(safe, env)
	}
	return safe
}

// killProcess terminates a command's process safely if non-nil.
func killProcess(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
