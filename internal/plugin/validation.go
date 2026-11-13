package plugin

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

var (
	pluginNameRegex   = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]{2,64}$`)
	pluginSemverRegex = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-[0-9A-Za-z.-]+)?$`)
)

// ValidatePlugin verifies that a plugin's metadata and capabilities meet engine requirements.
func ValidatePlugin(p AnalyzerPlugin) error {
	if p == nil {
		return errors.New("plugin cannot be nil")
	}
	meta := p.Metadata()
	if strings.TrimSpace(meta.Name) == "" {
		return errors.New("plugin metadata missing name")
	}
	if !pluginNameRegex.MatchString(meta.Name) {
		return fmt.Errorf("invalid plugin name %q: must be 2-64 alphanumeric characters, hyphens, underscores, or dots", meta.Name)
	}
	if strings.TrimSpace(meta.Version) == "" {
		return fmt.Errorf("plugin %s missing version", meta.Name)
	}
	if !pluginSemverRegex.MatchString(meta.Version) {
		return fmt.Errorf("plugin %s has invalid semver version %q", meta.Name, meta.Version)
	}

	caps := p.Capabilities()
	for _, scope := range caps.Scopes {
		switch scope {
		case "staged", "working-tree", "*", "":
			// Valid
		default:
			return fmt.Errorf("plugin %s declares unsupported scope %q (supported: staged, working-tree)", meta.Name, scope)
		}
	}

	for _, cat := range caps.Categories {
		switch cat {
		case "security", "slop", "confidence", "risk", "drift", "quality", "lint":
			// Valid
		default:
			return fmt.Errorf("plugin %s declares unrecognized category %q", meta.Name, cat)
		}
	}

	return nil
}

// ValidateExecutable verifies that a candidate plugin binary exists and is executable.
func ValidateExecutable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("plugin binary not found: %w", err)
	}
	if fi.IsDir() {
		return fmt.Errorf("plugin path %s is a directory", path)
	}
	// Windows file modes do not record executable bits; executability is
	// determined when the process is launched.
	if runtime.GOOS != "windows" && fi.Mode()&0111 == 0 {
		return fmt.Errorf("plugin file %s is not executable", path)
	}
	return nil
}

// CompareSemver reports whether v1 is greater than or equal to v2.
func CompareSemver(v1, v2 string) (bool, error) {
	m1 := pluginSemverRegex.FindStringSubmatch(v1)
	m2 := pluginSemverRegex.FindStringSubmatch(v2)
	if len(m1) < 3 || len(m2) < 3 {
		return false, fmt.Errorf("invalid semver comparison: %q vs %q", v1, v2)
	}
	maj1, _ := strconv.Atoi(m1[1])
	min1, _ := strconv.Atoi(m1[2])
	patch1 := 0
	if len(m1) > 3 && m1[3] != "" {
		patch1, _ = strconv.Atoi(m1[3])
	}

	maj2, _ := strconv.Atoi(m2[1])
	min2, _ := strconv.Atoi(m2[2])
	patch2 := 0
	if len(m2) > 3 && m2[3] != "" {
		patch2, _ = strconv.Atoi(m2[3])
	}

	if maj1 != maj2 {
		return maj1 > maj2, nil
	}
	if min1 != min2 {
		return min1 > min2, nil
	}
	return patch1 >= patch2, nil
}
