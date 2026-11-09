package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// userConfig holds repository-independent defaults from
// $XDG_CONFIG_HOME/m3tal-review/config.json (or ~/.config/...). CLI flags
// always override these values.
type userConfig struct {
	Profile   string            `json:"profile,omitempty"`
	FailOn    string            `json:"fail_on,omitempty"`
	Format    string            `json:"format,omitempty"`
	Only      []string          `json:"only,omitempty"`
	Skip      []string          `json:"skip,omitempty"`
	Degraded  bool              `json:"degraded,omitempty"`
	ToolPaths map[string]string `json:"tool_paths,omitempty"`
	Tools     map[string]string `json:"tools,omitempty"`
}

func userConfigPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "m3tal-review", "config.json"), nil
}

func loadUserConfig() (userConfig, error) {
	path, err := userConfigPath()
	if err != nil {
		return userConfig{}, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return userConfig{}, nil
	}
	if err != nil {
		return userConfig{}, fmt.Errorf("read config: %w", err)
	}
	if len(data) > 1<<20 {
		return userConfig{}, fmt.Errorf("config exceeds 1 MiB")
	}
	var cfg userConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return userConfig{}, fmt.Errorf("decode %s: %w", path, err)
	}
	switch cfg.Profile {
	case "", "fast", "full", "security", "slop", "ci":
	default:
		return userConfig{}, fmt.Errorf("invalid config profile %q", cfg.Profile)
	}
	switch cfg.Format {
	case "", "text", "sarif", "github", "json", "junit", "codeclimate", "jsonl", "html":
	default:
		return userConfig{}, fmt.Errorf("invalid config format %q", cfg.Format)
	}
	if cfg.FailOn != "" && !validSeverityName(cfg.FailOn) {
		return userConfig{}, fmt.Errorf("invalid config fail_on %q", cfg.FailOn)
	}
	return cfg, nil
}

// applyUserConfig fills review options the user did not explicitly set.
func applyUserConfig(options *reviewOptions, cfg userConfig) {
	if !options.seen["--profile"] && cfg.Profile != "" {
		options.Profile = cfg.Profile
	}
	if !options.seen["--fail-on"] && cfg.FailOn != "" {
		options.FailOn = cfg.FailOn
	}
	if !options.seen["--format"] && cfg.Format != "" {
		options.Format = cfg.Format
	}
	if !options.seen["--only"] && len(cfg.Only) > 0 {
		options.Only = cfg.Only
	}
	if len(cfg.Skip) > 0 {
		options.Skip = append(cfg.Skip, options.Skip...)
	}
	if !options.seen["--degraded"] && cfg.Degraded {
		options.Degraded = true
	}
	if options.ToolPaths == nil {
		options.ToolPaths = make(map[string]string)
	}
	for k, v := range cfg.ToolPaths {
		if options.ToolPaths[k] == "" {
			options.ToolPaths[k] = v
		}
	}
	for k, v := range cfg.Tools {
		if options.ToolPaths[k] == "" {
			options.ToolPaths[k] = v
		}
	}
}

// applyUserConfigAudit fills audit options the user did not explicitly set.
func applyUserConfigAudit(options *auditOptions, cfg userConfig) {
	// audit only supports fast|full profiles; review-only profiles are ignored.
	if !options.seen["--profile"] && (cfg.Profile == "fast" || cfg.Profile == "full") {
		options.Profile = cfg.Profile
	}
	if !options.seen["--fail-on"] && cfg.FailOn != "" {
		options.FailOn = cfg.FailOn
	}
	if !options.seen["--format"] && cfg.Format != "" {
		options.Format = cfg.Format
	}
	if !options.seen["--only"] && len(cfg.Only) > 0 {
		options.Only = cfg.Only
	}
	if len(cfg.Skip) > 0 {
		options.Skip = append(cfg.Skip, options.Skip...)
	}
	if !options.seen["--degraded"] && cfg.Degraded {
		options.Degraded = true
	}
	if options.ToolPaths == nil {
		options.ToolPaths = make(map[string]string)
	}
	for k, v := range cfg.ToolPaths {
		if options.ToolPaths[k] == "" {
			options.ToolPaths[k] = v
		}
	}
	for k, v := range cfg.Tools {
		if options.ToolPaths[k] == "" {
			options.ToolPaths[k] = v
		}
	}
}
