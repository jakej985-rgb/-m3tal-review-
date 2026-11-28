package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
)

var (
	ruleIDPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*/(bug|security|slop)/[a-z0-9][a-z0-9._-]{0,63}$`)
	appNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	extensionPattern = regexp.MustCompile(`^\.[a-z0-9]+(\.[a-z0-9]+)*$`)
)

// ValidationError records a protocol violation along with the offending JSON path.
type ValidationError struct {
	Path    string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Path == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

func fail(jsonPath, msg string) error {
	return &ValidationError{Path: jsonPath, Message: msg}
}

// DecodeDescribe strictly decodes and validates a DescribeResult.
func DecodeDescribe(data []byte) (DescribeResult, error) {
	var res DescribeResult
	if err := decodeStrict(data, &res); err != nil {
		return DescribeResult{}, fail("$", err.Error())
	}
	if err := ValidateDescribe(res); err != nil {
		return DescribeResult{}, err
	}
	return res, nil
}

// DecodeInput strictly decodes and validates an Input request.
func DecodeInput(data []byte) (Input, error) {
	if len(data) > MaxInputBytes {
		return Input{}, fail("$", fmt.Sprintf("input exceeds max size (%d > %d bytes)", len(data), MaxInputBytes))
	}
	var in Input
	if err := decodeStrict(data, &in); err != nil {
		return Input{}, fail("$", err.Error())
	}
	if err := ValidateInput(in); err != nil {
		return Input{}, err
	}
	return in, nil
}

// DecodeOutput strictly decodes and validates an Output response.
func DecodeOutput(data []byte, expectedApp string, sentFiles map[string]struct{}) (Output, error) {
	if len(data) > MaxStdoutBytes {
		return Output{}, fail("$", fmt.Sprintf("stdout exceeds max size (%d > %d bytes)", len(data), MaxStdoutBytes))
	}
	var out Output
	if err := decodeStrict(data, &out); err != nil {
		return Output{}, fail("$", err.Error())
	}
	if err := ValidateOutput(out, expectedApp, sentFiles); err != nil {
		return Output{}, err
	}
	return out, nil
}

func decodeStrict(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON object")
	}
	return nil
}

// ValidateDescribe checks all invariants of a DescribeResult.
func ValidateDescribe(res DescribeResult) error {
	if res.Protocol != Version {
		return fail("$.protocol", fmt.Sprintf("expected %q, got %q", Version, res.Protocol))
	}
	if res.Kind != Kind {
		return fail("$.kind", fmt.Sprintf("expected %q, got %q", Kind, res.Kind))
	}
	if !appNamePattern.MatchString(res.App.Name) {
		return fail("$.app.name", fmt.Sprintf("invalid app name %q", res.App.Name))
	}
	if strings.TrimSpace(res.App.Version) == "" {
		return fail("$.app.version", "version must be non-empty")
	}
	if len(res.Extensions) == 0 {
		return fail("$.extensions", "must claim at least one extension")
	}
	for i, ext := range res.Extensions {
		if !extensionPattern.MatchString(ext) {
			return fail(fmt.Sprintf("$.extensions[%d]", i), fmt.Sprintf("invalid extension %q", ext))
		}
	}
	if len(res.Inputs) == 0 {
		return fail("$.inputs", "must declare at least one input mode")
	}
	for i, in := range res.Inputs {
		if in != InputContent && in != InputWorktree {
			return fail(fmt.Sprintf("$.inputs[%d]", i), fmt.Sprintf("invalid input mode %q", in))
		}
	}
	for i, r := range res.Rules {
		if !IsValidRuleID(r.ID) {
			return fail(fmt.Sprintf("$.rules[%d].id", i), fmt.Sprintf("invalid rule id %q (expected <lang>/<category>/<slug>)", r.ID))
		}
		if !IsValidCategory(r.Category) {
			return fail(fmt.Sprintf("$.rules[%d].category", i), fmt.Sprintf("invalid category %q", r.Category))
		}
		if cat, ok := RuleIDCategory(r.ID); ok && cat != r.Category {
			return fail(fmt.Sprintf("$.rules[%d].category", i), fmt.Sprintf("category %q does not match rule id %q", r.Category, r.ID))
		}
		if !IsValidSeverity(r.Severity) {
			return fail(fmt.Sprintf("$.rules[%d].severity", i), fmt.Sprintf("invalid severity %q", r.Severity))
		}
	}
	return nil
}

// ValidateInput checks all invariants of an Input request.
func ValidateInput(in Input) error {
	if in.Protocol != Version {
		return fail("$.protocol", fmt.Sprintf("expected %q, got %q", Version, in.Protocol))
	}
	for i, f := range in.Files {
		if err := ValidateRelativePath(f.Path); err != nil {
			return fail(fmt.Sprintf("$.files[%d].path", i), err.Error())
		}
		if len(f.Content) > MaxFileBytes {
			return fail(fmt.Sprintf("$.files[%d].content", i), fmt.Sprintf("file exceeds max size (%d > %d bytes)", len(f.Content), MaxFileBytes))
		}
	}
	return nil
}

// ValidateOutput checks all invariants of an Output response.
func ValidateOutput(out Output, expectedApp string, sentFiles map[string]struct{}) error {
	if out.Protocol != Version {
		return fail("$.protocol", fmt.Sprintf("expected %q, got %q", Version, out.Protocol))
	}
	if expectedApp != "" && out.App.Name != expectedApp {
		return fail("$.app.name", fmt.Sprintf("expected %q, got %q", expectedApp, out.App.Name))
	}
	for i, f := range out.Findings {
		prefix := fmt.Sprintf("$.findings[%d]", i)
		if !IsValidRuleID(f.Rule) {
			return fail(prefix+".rule", fmt.Sprintf("invalid rule id %q", f.Rule))
		}
		if !IsValidCategory(f.Category) {
			return fail(prefix+".category", fmt.Sprintf("invalid category %q", f.Category))
		}
		if cat, ok := RuleIDCategory(f.Rule); ok && cat != f.Category {
			return fail(prefix+".category", fmt.Sprintf("category %q does not match rule id %q", f.Category, f.Rule))
		}
		if !IsValidSeverity(f.Severity) {
			return fail(prefix+".severity", fmt.Sprintf("invalid severity %q", f.Severity))
		}
		if f.Confidence != "" && !IsValidConfidence(f.Confidence) {
			return fail(prefix+".confidence", fmt.Sprintf("invalid confidence %q", f.Confidence))
		}
		if f.Category == CategorySlop {
			if f.Confidence == "" {
				return fail(prefix+".confidence", "slop findings must include confidence")
			}
			if strings.TrimSpace(f.Evidence) == "" {
				return fail(prefix+".evidence", "slop findings must include evidence")
			}
		}
		if err := ValidateRelativePath(f.File); err != nil {
			return fail(prefix+".file", err.Error())
		}
		if sentFiles != nil {
			if _, ok := sentFiles[f.File]; !ok {
				return fail(prefix+".file", fmt.Sprintf("file %q was not in request", f.File))
			}
		}
		if f.Line < 1 {
			return fail(prefix+".line", "line must be >= 1")
		}
		if strings.TrimSpace(f.Message) == "" {
			return fail(prefix+".message", "message must be non-empty")
		}
	}
	for i, u := range out.Unanalyzed {
		prefix := fmt.Sprintf("$.unanalyzed[%d]", i)
		if err := ValidateRelativePath(u.File); err != nil {
			return fail(prefix+".file", err.Error())
		}
	}
	return nil
}

// ValidateOutputAgainstDescribe checks ValidateOutput and ensures every emitted finding rule
// was declared in the app's DescribeResult.Rules catalog with matching category.
func ValidateOutputAgainstDescribe(out Output, desc DescribeResult, sentFiles map[string]struct{}) error {
	if err := ValidateOutput(out, desc.App.Name, sentFiles); err != nil {
		return err
	}
	if len(desc.Rules) == 0 {
		return nil
	}
	declared := make(map[string]RuleInfo, len(desc.Rules))
	for _, r := range desc.Rules {
		declared[r.ID] = r
	}
	for i, f := range out.Findings {
		prefix := fmt.Sprintf("$.findings[%d]", i)
		r, ok := declared[f.Rule]
		if !ok {
			return fail(prefix+".rule", fmt.Sprintf("rule %q was not declared in describe catalog", f.Rule))
		}
		if r.Category != f.Category {
			return fail(prefix+".category", fmt.Sprintf("category %q does not match declared rule category %q", f.Category, r.Category))
		}
	}
	return nil
}

// ValidateRelativePath ensures a file path is clean, relative, slash-separated, and free of traversal or control chars.
func ValidateRelativePath(p string) error {
	if p == "" {
		return errors.New("path must be non-empty")
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "\\") || hasWindowsDrivePrefix(p) {
		return fmt.Errorf("path %q must be relative and slash-separated", p)
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] == 0x7f {
			return fmt.Errorf("path %q contains control character", p)
		}
	}
	cleaned := path.Clean(p)
	if cleaned != p || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("path %q is not clean or escapes root", p)
	}
	return nil
}

func hasWindowsDrivePrefix(p string) bool {
	if len(p) < 2 || p[1] != ':' {
		return false
	}
	c := p[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// IsValidRuleID reports whether id matches <lang>/<category>/<slug>.
func IsValidRuleID(id string) bool {
	return ruleIDPattern.MatchString(id)
}

// RuleIDCategory extracts the <category> segment from a valid rule ID.
func RuleIDCategory(id string) (string, bool) {
	parts := strings.SplitN(id, "/", 3)
	if len(parts) != 3 || !IsValidCategory(parts[1]) {
		return "", false
	}
	return parts[1], true
}

// IsValidCategory reports whether c is one of bug, security, or slop.
func IsValidCategory(c string) bool {
	return c == CategoryBug || c == CategorySecurity || c == CategorySlop
}

// IsValidSeverity reports whether s is a supported severity level.
func IsValidSeverity(s string) bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// IsValidConfidence reports whether c is a supported confidence level.
func IsValidConfidence(c string) bool {
	switch c {
	case ConfidenceLow, ConfidenceMedium, ConfidenceHigh:
		return true
	default:
		return false
	}
}
