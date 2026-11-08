package review

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

const ignoreFileName = ".m3tal-review-ignore"

// ApplyFindingFilters assigns stable fingerprints, drops findings suppressed
// by inline "m3tal-review: ignore" comments or the .m3tal-review-ignore file,
// and applies policy-file per-rule enable/severity overrides. It is safe to
// call per-file (audit) or once with a combined diff (review).
func ApplyFindingFilters(diff string, findings []Finding, repositoryRoot string, workingTree bool) []Finding {
	findings = AssignFindingIDs(findings)

	var policy *reviewPolicy
	if repositoryRoot != "" {
		if p, err := readReviewPolicy(repositoryRoot, workingTree); err == nil {
			policy = &p
		}
	}

	suppressed := inlineSuppressions(diff)
	var ignorePatterns []ignorePattern
	if repositoryRoot != "" {
		ignorePatterns = readIgnoreFile(repositoryRoot, workingTree)
	}

	out := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if policy != nil {
			override, ok := policy.Rules[f.Rule]
			if !ok && len(policy.Paths) > 0 {
				// Per-path overrides: globs evaluated in sorted order so the
				// first match wins deterministically.
				globs := make([]string, 0, len(policy.Paths))
				for glob := range policy.Paths {
					globs = append(globs, glob)
				}
				sort.Strings(globs)
				for _, glob := range globs {
					if matchesRepoPath(glob, f.File) {
						override, ok = policy.Paths[glob][f.Rule]
						break
					}
				}
			}
			if ok {
				if override.Enabled != nil && !*override.Enabled {
					continue
				}
				if validSeverity(override.Severity) {
					f.Severity = override.Severity
				}
			}
		}
		if isFindingSuppressed(f, suppressed, ignorePatterns) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func findingFingerprint(f Finding) string {
	sum := sha256.Sum256([]byte(f.Rule + "\x1f" + f.File + "\x1f" + strconv.Itoa(f.Line) + "\x1f" + f.Message))
	return hex.EncodeToString(sum[:])[:16]
}

func validSeverity(s string) bool {
	switch s {
	case "info", "low", "medium", "high", "critical":
		return true
	}
	return false
}

// --- inline suppressions -------------------------------------------------

type suppressionRules map[string]bool

type fileSuppressions struct {
	all   bool
	lines map[int]suppressionRules
}

// inlineSuppressions scans added lines for "m3tal-review: ignore" comments.
// A trailing comment suppresses findings on its own line; a comment-only line
// suppresses findings on the following line. "ignore-file" suppresses the
// whole file.
func inlineSuppressions(diff string) map[string]*fileSuppressions {
	result := make(map[string]*fileSuppressions)
	for _, fd := range ParseDiff(diff) {
		fs := result[fd.Path]
		if fs == nil {
			fs = &fileSuppressions{lines: make(map[int]suppressionRules)}
			result[fd.Path] = fs
		}
		lines := make([]int, 0, len(fd.AddedLines))
		lines = append(lines, fd.AddedLines...)
		sort.Ints(lines)
		for _, line := range lines {
			text := fd.AddedText[line]
			markerAt := strings.Index(text, "m3tal-review:")
			if markerAt < 0 {
				continue
			}
			rest := text[markerAt+len("m3tal-review:"):]
			rest = strings.TrimLeft(rest, " \t")
			if !strings.HasPrefix(rest, "ignore") {
				continue
			}
			tail := strings.TrimPrefix(rest, "ignore")
			tail = strings.TrimLeft(tail, " \t")
			if strings.HasPrefix(tail, "-file") {
				fs.all = true
				continue
			}
			rules := parseSuppressionRules(tail)
			// Determine whether code precedes the comment on this line.
			target := line
			if commentOnlyLine(text, markerAt) {
				target = line + 1
			}
			entry := fs.lines[target]
			if entry == nil {
				entry = make(suppressionRules)
				fs.lines[target] = entry
			}
			for name := range rules {
				entry[name] = true
			}
			if len(rules) == 0 {
				entry[""] = true // empty key = suppress all rules on this line
			}
		}
	}
	return result
}

// commentOnlyLine reports whether the text before the marker position is
// entirely comment syntax (i.e., the marker sits on its own comment line).
func commentOnlyLine(text string, markerAt int) bool {
	prefix := text[:markerAt]
	for _, opener := range []string{"//", "#", "/*", "*", "<!--", "-- "} {
		if idx := strings.Index(prefix, opener); idx >= 0 {
			return strings.TrimSpace(prefix[:idx]) == ""
		}
	}
	return strings.TrimSpace(prefix) == ""
}

func parseSuppressionRules(tail string) suppressionRules {
	rules := make(suppressionRules)
	// Stop at a "--" justification or end of comment markers.
	if idx := strings.Index(tail, "--"); idx >= 0 {
		tail = tail[:idx]
	}
	for _, field := range strings.FieldsFunc(tail, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	}) {
		field = strings.Trim(field, "*/")
		if field == "" {
			continue
		}
		rules[field] = true
	}
	return rules
}

func isFindingSuppressed(f Finding, suppressed map[string]*fileSuppressions, patterns []ignorePattern) bool {
	if fs, ok := suppressed[f.File]; ok {
		if fs.all {
			return true
		}
		if rules, ok := fs.lines[f.Line]; ok {
			if rules[""] || rules[f.Rule] {
				return true
			}
		}
	}
	for _, pattern := range patterns {
		if !matchesRepoPath(pattern.glob, f.File) {
			continue
		}
		if len(pattern.rules) == 0 || pattern.rules[f.Rule] {
			return true
		}
	}
	return false
}

// --- .m3tal-review-ignore -----------------------------------------------

type ignorePattern struct {
	glob  string
	rules map[string]bool
}

func readIgnoreFile(repositoryRoot string, workingTree bool) []ignorePattern {
	file := filepath.Join(repositoryRoot, ignoreFileName)
	if info, err := os.Lstat(file); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	var data []byte
	var err error
	if workingTree {
		data, err = os.ReadFile(file)
	} else {
		data, err = git.StagedFileContent(repositoryRoot, ignoreFileName)
		if err != nil {
			data, err = os.ReadFile(file)
		}
	}
	if err != nil {
		return nil
	}
	var patterns []ignorePattern
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		entry := ignorePattern{glob: fields[0], rules: make(map[string]bool)}
		for _, name := range fields[1:] {
			for _, part := range strings.Split(name, ",") {
				if part != "" {
					entry.rules[part] = true
				}
			}
		}
		patterns = append(patterns, entry)
	}
	return patterns
}
