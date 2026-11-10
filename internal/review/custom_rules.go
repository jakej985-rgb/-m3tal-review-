package review

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/review/language"
	"gopkg.in/yaml.v3"
)

// Schema limits and constraints
const (
	MaxCustomRulesFileSize = 1 << 20 // 1 MiB
	MaxRuleIDLen           = 64
	MaxRuleNameLen         = 128
	MaxRuleMessageLen      = 500
	MaxPatternLen          = 1000
	MaxFilePatternLen      = 500
	DefaultRuleTimeout     = 2 * time.Second
	MinRuleTimeout         = 1 * time.Millisecond
	MaxRuleTimeout         = 30 * time.Second
)

var ruleIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

var validCustomRuleSeverities = map[string]bool{
	"info":     true,
	"low":      true,
	"medium":   true,
	"high":     true,
	"critical": true,
}

var validCustomRuleCategories = map[string]bool{
	"security":   true,
	"review":     true,
	"confidence": true,
	"risk":       true,
	"drift":      true,
}

var validLanguages = map[string]language.CodeLanguage{
	"go":         language.LanguageGo,
	"golang":     language.LanguageGo,
	"javascript": language.LanguageJavaScript,
	"js":         language.LanguageJavaScript,
	"typescript": language.LanguageTypeScript,
	"ts":         language.LanguageTypeScript,
	"python":     language.LanguagePython,
	"py":         language.LanguagePython,
	"java":       language.LanguageJava,
	"kotlin":     language.LanguageKotlin,
	"kt":         language.LanguageKotlin,
	"c":          language.LanguageC,
	"cpp":        language.LanguageCpp,
	"c++":        language.LanguageCpp,
	"csharp":     language.LanguageCSharp,
	"c#":         language.LanguageCSharp,
	"rust":       language.LanguageRust,
	"rs":         language.LanguageRust,
	"swift":      language.LanguageSwift,
	"php":        language.LanguagePHP,
	"shell":      language.LanguageShell,
	"sh":         language.LanguageShell,
	"bash":       language.LanguageShell,
}

// CustomRulesConfig is the top-level schema for custom rules files.
type CustomRulesConfig struct {
	Version string          `json:"version" yaml:"version"`
	Rules   []CustomRuleDef `json:"rules" yaml:"rules"`
}

// CustomRuleDef defines the declarative schema for a single custom rule.
type CustomRuleDef struct {
	ID                 string   `json:"id" yaml:"id"`
	Name               string   `json:"name" yaml:"name"`
	Severity           string   `json:"severity" yaml:"severity"`
	Category           string   `json:"category" yaml:"category"`
	Message            string   `json:"message" yaml:"message"`
	Languages          []string `json:"languages,omitempty" yaml:"languages,omitempty"`
	Pattern            string   `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Patterns           []string `json:"patterns,omitempty" yaml:"patterns,omitempty"`
	Remediation        string   `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	FilePattern        string   `json:"file_pattern,omitempty" yaml:"file_pattern,omitempty"`
	FileExcludePattern string   `json:"file_exclude_pattern,omitempty" yaml:"file_exclude_pattern,omitempty"`
	Raw                bool     `json:"raw,omitempty" yaml:"raw,omitempty"`
	Timeout            string   `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// CustomRuleValidationError details a specific schema violation.
type CustomRuleValidationError struct {
	RuleIndex int    `json:"rule_index"`
	RuleID    string `json:"rule_id,omitempty"`
	Field     string `json:"field"`
	Reason    string `json:"reason"`
}

func (e CustomRuleValidationError) Error() string {
	if e.RuleID != "" {
		return fmt.Sprintf("rule %q (index %d) %s: %s", e.RuleID, e.RuleIndex, e.Field, e.Reason)
	}
	return fmt.Sprintf("rule at index %d %s: %s", e.RuleIndex, e.Field, e.Reason)
}

// CustomRuleValidationErrors collects all schema errors found in a custom rules config.
type CustomRuleValidationErrors []CustomRuleValidationError

func (errs CustomRuleValidationErrors) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d custom rule schema validation error(s):\n", len(errs)))
	for _, err := range errs {
		sb.WriteString("  - ")
		sb.WriteString(err.Error())
		sb.WriteString("\n")
	}
	return strings.TrimRight(sb.String(), "\n")
}

// ValidateCustomRulesConfig validates a CustomRulesConfig against the strict schema.
func ValidateCustomRulesConfig(cfg *CustomRulesConfig) (CustomRuleValidationErrors, error) {
	var errs CustomRuleValidationErrors

	if cfg == nil {
		return append(errs, CustomRuleValidationError{Field: "config", Reason: "config is nil"}), nil
	}

	if len(cfg.Rules) == 0 {
		return append(errs, CustomRuleValidationError{Field: "rules", Reason: "at least one rule must be defined"}), nil
	}

	seenIDs := make(map[string]int)

	for i, r := range cfg.Rules {
		// 1. ID validation
		id := strings.TrimSpace(r.ID)
		if id == "" {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, Field: "id", Reason: "rule ID cannot be empty"})
		} else {
			if len(id) > MaxRuleIDLen {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "id", Reason: fmt.Sprintf("rule ID exceeds maximum length of %d characters", MaxRuleIDLen)})
			}
			if !ruleIDRegex.MatchString(id) {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "id", Reason: "rule ID must consist only of letters, numbers, underscores, and hyphens"})
			}
			if prevIdx, exists := seenIDs[id]; exists {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "id", Reason: fmt.Sprintf("duplicate rule ID %q (already defined at index %d)", id, prevIdx)})
			} else {
				seenIDs[id] = i
			}
		}

		// 2. Name validation
		name := strings.TrimSpace(r.Name)
		if name == "" {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "name", Reason: "rule name cannot be empty"})
		} else if len(name) > MaxRuleNameLen {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "name", Reason: fmt.Sprintf("rule name exceeds maximum length of %d characters", MaxRuleNameLen)})
		}

		// 3. Severity validation
		sev := strings.ToLower(strings.TrimSpace(r.Severity))
		if sev == "" {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "severity", Reason: "severity cannot be empty"})
		} else if !validCustomRuleSeverities[sev] {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "severity", Reason: fmt.Sprintf("invalid severity %q; must be one of: info, low, medium, high, critical", r.Severity)})
		}

		// 4. Category validation
		cat := strings.ToLower(strings.TrimSpace(r.Category))
		if cat == "" {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "category", Reason: "category cannot be empty"})
		} else if !validCustomRuleCategories[cat] {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "category", Reason: fmt.Sprintf("invalid category %q; must be one of: security, review, confidence, risk, drift", r.Category)})
		}

		// 5. Message validation
		msg := strings.TrimSpace(r.Message)
		if msg == "" {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "message", Reason: "message cannot be empty"})
		} else if len(msg) > MaxRuleMessageLen {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "message", Reason: fmt.Sprintf("message exceeds maximum length of %d characters", MaxRuleMessageLen)})
		}

		// 6. Language targeting
		for _, lang := range r.Languages {
			l := strings.ToLower(strings.TrimSpace(lang))
			if l == "all" || l == "*" || l == "any" {
				continue
			}
			if _, ok := validLanguages[l]; !ok {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "languages", Reason: fmt.Sprintf("unrecognized language %q", lang)})
			}
		}

		// 7. Regex patterns
		patterns := r.allPatterns()
		if len(patterns) == 0 {
			errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "pattern", Reason: "at least one regex pattern must be specified"})
		}
		for pIdx, pat := range patterns {
			if pat == "" {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: fmt.Sprintf("pattern[%d]", pIdx), Reason: "pattern cannot be empty"})
				continue
			}
			if len(pat) > MaxPatternLen {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: fmt.Sprintf("pattern[%d]", pIdx), Reason: fmt.Sprintf("pattern exceeds maximum length of %d characters (got %d)", MaxPatternLen, len(pat))})
				continue
			}
			if _, compileErr := regexp.Compile(pat); compileErr != nil {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: fmt.Sprintf("pattern[%d]", pIdx), Reason: fmt.Sprintf("invalid regex syntax: %v", compileErr)})
			}
		}

		// 8. File patterns
		if r.FilePattern != "" {
			if len(r.FilePattern) > MaxFilePatternLen {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "file_pattern", Reason: fmt.Sprintf("file_pattern exceeds maximum length of %d characters", MaxFilePatternLen)})
			} else if _, compileErr := regexp.Compile(r.FilePattern); compileErr != nil {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "file_pattern", Reason: fmt.Sprintf("invalid regex syntax: %v", compileErr)})
			}
		}

		if r.FileExcludePattern != "" {
			if len(r.FileExcludePattern) > MaxFilePatternLen {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "file_exclude_pattern", Reason: fmt.Sprintf("file_exclude_pattern exceeds maximum length of %d characters", MaxFilePatternLen)})
			} else if _, compileErr := regexp.Compile(r.FileExcludePattern); compileErr != nil {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "file_exclude_pattern", Reason: fmt.Sprintf("invalid regex syntax: %v", compileErr)})
			}
		}

		// 9. Timeout limits
		if r.Timeout != "" {
			d, parseErr := time.ParseDuration(r.Timeout)
			if parseErr != nil {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "timeout", Reason: fmt.Sprintf("invalid timeout duration %q: %v", r.Timeout, parseErr)})
			} else if d < MinRuleTimeout || d > MaxRuleTimeout {
				errs = append(errs, CustomRuleValidationError{RuleIndex: i, RuleID: id, Field: "timeout", Reason: fmt.Sprintf("timeout duration %s is outside allowed bounds [%s, %s]", d, MinRuleTimeout, MaxRuleTimeout)})
			}
		}
	}

	return errs, nil
}

func (r *CustomRuleDef) allPatterns() []string {
	var res []string
	if strings.TrimSpace(r.Pattern) != "" {
		res = append(res, strings.TrimSpace(r.Pattern))
	}
	for _, p := range r.Patterns {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			res = append(res, trimmed)
		}
	}
	return res
}

// ParseCustomRules parses YAML or JSON data into CustomRulesConfig.
func ParseCustomRules(data []byte) (*CustomRulesConfig, error) {
	if len(data) > MaxCustomRulesFileSize {
		return nil, fmt.Errorf("custom rules file exceeds maximum size of 1 MiB (%d bytes)", len(data))
	}

	var cfg CustomRulesConfig

	// Try YAML unmarshaler first, which handles both valid YAML and JSON
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		// Fallback to JSON unmarshal for exact error reporting
		if jsonErr := json.Unmarshal(data, &cfg); jsonErr != nil {
			return nil, fmt.Errorf("failed to parse custom rules (YAML error: %v; JSON error: %v)", err, jsonErr)
		}
	}

	// Handle top-level array format fallback: [{"id": "..."}, ...]
	if len(cfg.Rules) == 0 {
		var listRules []CustomRuleDef
		if err := yaml.Unmarshal(data, &listRules); err == nil && len(listRules) > 0 {
			cfg.Rules = listRules
		}
	}

	return &cfg, nil
}

// LoadCustomRulesFile reads, parses, and strictly validates a custom rules file.
func LoadCustomRulesFile(path string, repoRoot string) ([]Rule, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("custom rules file %q must not be a symbolic link", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read custom rules file %q: %w", path, err)
	}

	cfg, err := ParseCustomRules(data)
	if err != nil {
		return nil, err
	}

	if valErrs, err := ValidateCustomRulesConfig(cfg); err != nil {
		return nil, err
	} else if len(valErrs) > 0 {
		return nil, valErrs
	}

	rules := make([]Rule, 0, len(cfg.Rules))
	for _, rDef := range cfg.Rules {
		r, buildErr := buildCustomRule(rDef, repoRoot)
		if buildErr != nil {
			return nil, buildErr
		}
		rules = append(rules, r)
	}

	return rules, nil
}

// FindCustomRulesFile checks for an explicit path or standard locations in repoRoot.
func FindCustomRulesFile(repoRoot string, explicitPath string) string {
	if explicitPath != "" {
		if filepath.IsAbs(explicitPath) {
			if _, err := os.Stat(explicitPath); err == nil {
				return explicitPath
			}
		} else {
			if _, err := os.Stat(explicitPath); err == nil {
				return explicitPath
			}
			if repoRoot != "" {
				cand := filepath.Join(repoRoot, explicitPath)
				if _, err := os.Stat(cand); err == nil {
					return cand
				}
			}
		}
		return explicitPath // Return as requested so caller can report file not found
	}

	if repoRoot == "" {
		return ""
	}

	candidates := []string{
		".m3tal-review-rules.yaml",
		".m3tal-review-rules.yml",
		".m3tal-review-rules.json",
	}

	for _, cand := range candidates {
		fullPath := filepath.Join(repoRoot, cand)
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			return fullPath
		}
	}

	return ""
}

// customRule implements Rule and WorkingTreeAware with bounded execution timeout.
type customRule struct {
	ruleRuntime
	def                CustomRuleDef
	patterns           []*regexp.Regexp
	filePattern        *regexp.Regexp
	fileExcludePattern *regexp.Regexp
	languages          map[language.CodeLanguage]bool
	allLanguages       bool
	timeout            time.Duration
}

func buildCustomRule(def CustomRuleDef, repoRoot string) (*customRule, error) {
	cr := &customRule{
		ruleRuntime: ruleRuntime{repositoryRoot: repoRoot},
		def:         def,
		languages:   make(map[language.CodeLanguage]bool),
		timeout:     DefaultRuleTimeout,
	}

	if def.Timeout != "" {
		if d, err := time.ParseDuration(def.Timeout); err == nil && d > 0 {
			cr.timeout = d
		}
	}

	for _, p := range def.allPatterns() {
		compiled, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("compile pattern %q for rule %s: %w", p, def.ID, err)
		}
		cr.patterns = append(cr.patterns, compiled)
	}

	if def.FilePattern != "" {
		re, err := regexp.Compile(def.FilePattern)
		if err != nil {
			return nil, fmt.Errorf("compile file_pattern for rule %s: %w", def.ID, err)
		}
		cr.filePattern = re
	}

	if def.FileExcludePattern != "" {
		re, err := regexp.Compile(def.FileExcludePattern)
		if err != nil {
			return nil, fmt.Errorf("compile file_exclude_pattern for rule %s: %w", def.ID, err)
		}
		cr.fileExcludePattern = re
	}

	if len(def.Languages) == 0 {
		cr.allLanguages = true
	} else {
		for _, lang := range def.Languages {
			l := strings.ToLower(strings.TrimSpace(lang))
			if l == "all" || l == "*" || l == "any" {
				cr.allLanguages = true
				break
			}
			if mapped, ok := validLanguages[l]; ok {
				cr.languages[mapped] = true
			}
		}
	}

	return cr, nil
}

func (r *customRule) Name() string {
	return r.def.ID
}

func (r *customRule) Check(diff string) []Finding {
	resultCh := make(chan []Finding, 1)

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				resultCh <- []Finding{{
					Rule:        r.def.ID + "-error",
					Severity:    "medium",
					Category:    "confidence",
					Message:     fmt.Sprintf("Custom rule %s failed during analysis: %v", r.def.ID, rec),
					Remediation: "Verify the custom rule regex pattern and settings.",
				}}
			}
		}()
		resultCh <- r.checkSync(diff)
	}()

	select {
	case findings := <-resultCh:
		return findings
	case <-time.After(r.timeout):
		return []Finding{{
			Rule:        r.def.ID + "-timeout",
			Severity:    "medium",
			Category:    "confidence",
			Message:     fmt.Sprintf("Custom rule %s exceeded execution timeout of %s", r.def.ID, r.timeout),
			Remediation: "Optimize regex pattern to prevent catastrophic backtracking or increase rule timeout.",
		}}
	}
}

func (r *customRule) checkSync(diff string) []Finding {
	var findings []Finding
	seen := make(map[string]bool)

	for _, block := range sourceBlocks(diff, r.repositoryRoot, r.workingTree) {
		if r.filePattern != nil && !r.filePattern.MatchString(block.file) {
			continue
		}
		if r.fileExcludePattern != nil && r.fileExcludePattern.MatchString(block.file) {
			continue
		}

		fileLanguage := (language.CodeChecker{}).Language(block.file)
		if !r.allLanguages && !r.languages[fileLanguage] {
			continue
		}

		code := block.text
		if !r.def.Raw {
			code = string(maskNonCode(block.file, block.text))
		}

		for _, pat := range r.patterns {
			for _, match := range pat.FindAllStringIndex(code, -1) {
				if !matchTouchesAdded(block, code, match[0], match[1]) {
					continue
				}
				line := lineAtOffset(block.firstLine, code, match[0])
				key := block.file + ":" + strconv.Itoa(line)
				if seen[key] {
					continue
				}
				seen[key] = true
				findings = append(findings, Finding{
					Rule:        r.def.ID,
					Severity:    r.def.Severity,
					Category:    r.def.Category,
					File:        block.file,
					Line:        line,
					Message:     r.def.Message,
					Remediation: r.def.Remediation,
				})
			}
		}
	}

	return findings
}
