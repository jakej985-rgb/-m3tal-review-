package review

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Fixture-driven analyzer tests (issue #132).
//
// Layout: testdata/fixtures/<rule>/<case>/
//
//	input.diff    unified diff fed to the rule's Check method (required)
//	expect.yaml   expected findings (required; `findings: []` for negatives)
//	golden.json   optional deterministic JSON snapshot of all findings
//
// expect.yaml asserts findings by rule/file/line/severity — never by full
// message text — so tests survive wording changes while still pinning down
// where and how severely a rule fires:
//
//	findings:
//	  - rule: exposed-secret        # optional; defaults to the fixture dir name
//	    file: config.go             # optional; empty means "any file"
//	    line: 3                     # optional; 0/omitted means "any line"
//	    severity: high              # optional
//	    message_contains: aws token # optional substring of the message
//
// The number of expected entries must equal the number of findings exactly,
// so unexpected extra findings fail the test just like missing ones.
//
// Registering a new analyzer requires no bespoke test runner: add its
// constructor to fixtureRules and drop fixture directories under
// testdata/fixtures/<rule-name>/.
//
// Promoting fuzz/regression failures: save the crashing or false-positive
// input as input.diff, run
//
//	go test ./internal/review/ -run TestFixtureSuite -fixture-update
//
// to generate expect.yaml from actual output, review it, and keep it as a
// permanent regression fixture. See testdata/fixtures/README.md.
var (
	fixtureFilter = flag.String("fixture", "", "run only fixture cases whose path contains this substring")
	fixtureUpdate = flag.Bool("fixture-update", false, "regenerate expect.yaml (and existing golden.json) from actual findings")
)

// fixtureExpectation is one expected finding. Zero-valued fields are wildcards.
type fixtureExpectation struct {
	Rule           string `yaml:"rule,omitempty"`
	File           string `yaml:"file,omitempty"`
	Line           int    `yaml:"line,omitempty"`
	Severity       string `yaml:"severity,omitempty"`
	MessageContain string `yaml:"message_contains,omitempty"`
}

type fixtureExpectFile struct {
	Findings []fixtureExpectation `yaml:"findings"`
}

// fixtureRules maps fixture directory names (rule IDs) to rule constructors.
// A new analyzer registers here once; every fixture under its directory then
// runs through the shared TestFixtureSuite runner.
func fixtureRules() map[string]func() Rule {
	return map[string]func() Rule{
		"exposed-secret": func() Rule { return SecretRule{} },
		"debug-leftover": func() Rule { return DebugRule{} },
	}
}

type fixtureCase struct {
	rule    string
	name    string
	dir     string
	diff    string
	expect  fixtureExpectFile
	hasGold bool
}

func loadFixtureCases(t *testing.T) []fixtureCase {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "fixtures")
	rules := fixtureRules()

	var cases []fixtureCase
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) != 2 {
			// Deeper nesting is not part of the convention.
			if len(parts) > 2 {
				t.Errorf("fixture path %q nests deeper than <rule>/<case>", rel)
			}
			return nil
		}
		ruleName, caseName := parts[0], parts[1]
		if _, ok := rules[ruleName]; !ok {
			t.Errorf("fixture %s/%s: no rule registered for %q (known: %s)",
				ruleName, caseName, ruleName, strings.Join(sortedKeys(rules), ", "))
			return nil
		}
		diffPath := filepath.Join(path, "input.diff")
		expectPath := filepath.Join(path, "expect.yaml")
		diffBytes, err := os.ReadFile(diffPath)
		if err != nil {
			t.Errorf("fixture %s/%s: read input.diff: %v", ruleName, caseName, err)
			return nil
		}
		expectBytes, err := os.ReadFile(expectPath)
		if err != nil {
			t.Errorf("fixture %s/%s: read expect.yaml: %v", ruleName, caseName, err)
			return nil
		}
		var expect fixtureExpectFile
		if err := yaml.Unmarshal(expectBytes, &expect); err != nil {
			t.Errorf("fixture %s/%s: parse expect.yaml: %v", ruleName, caseName, err)
			return nil
		}
		_, goldErr := os.Stat(filepath.Join(path, "golden.json"))
		cases = append(cases, fixtureCase{
			rule:    ruleName,
			name:    caseName,
			dir:     path,
			diff:    string(diffBytes),
			expect:  expect,
			hasGold: goldErr == nil,
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk testdata/fixtures: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("no fixtures found under testdata/fixtures")
	}
	return cases
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// sortFindings gives findings a deterministic order for matching output and
// golden serialization regardless of rule-internal iteration order.
func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Rule != b.Rule {
			return a.Rule < b.Rule
		}
		return a.Message < b.Message
	})
}

func findingMatches(f Finding, want fixtureExpectation, defaultRule string) bool {
	rule := want.Rule
	if rule == "" {
		rule = defaultRule
	}
	if f.Rule != rule {
		return false
	}
	if want.File != "" && f.File != want.File {
		return false
	}
	if want.Line != 0 && f.Line != want.Line {
		return false
	}
	if want.Severity != "" && f.Severity != want.Severity {
		return false
	}
	if want.MessageContain != "" && !strings.Contains(f.Message, want.MessageContain) {
		return false
	}
	return true
}

func describeFinding(f Finding) string {
	loc := f.File
	if f.Line > 0 {
		loc += fmt.Sprintf(":%d", f.Line)
	}
	return fmt.Sprintf("%s %s [%s] %s", f.Rule, loc, f.Severity, f.Message)
}

func describeExpectation(w fixtureExpectation, defaultRule string) string {
	rule := w.Rule
	if rule == "" {
		rule = defaultRule
	}
	parts := []string{rule}
	if w.File != "" {
		parts = append(parts, w.File)
	}
	if w.Line != 0 {
		parts = append(parts, fmt.Sprintf("line %d", w.Line))
	}
	if w.Severity != "" {
		parts = append(parts, "severity "+w.Severity)
	}
	if w.MessageContain != "" {
		parts = append(parts, fmt.Sprintf("message~%q", w.MessageContain))
	}
	return strings.Join(parts, " ")
}

// writeExpectFile serializes actual findings back into expect.yaml during
// -fixture-update. Only stable identity fields are written; message text is
// left to message_contains assertions authored by hand.
func writeExpectFile(path string, findings []Finding) error {
	expect := fixtureExpectFile{Findings: make([]fixtureExpectation, 0, len(findings))}
	for _, f := range findings {
		expect.Findings = append(expect.Findings, fixtureExpectation{
			Rule:     f.Rule,
			File:     f.File,
			Line:     f.Line,
			Severity: f.Severity,
		})
	}
	data, err := yaml.Marshal(expect)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func TestFixtureSuite(t *testing.T) {
	cases := loadFixtureCases(t)
	rules := fixtureRules()

	for _, tc := range cases {
		if *fixtureFilter != "" && !strings.Contains(tc.dir, *fixtureFilter) {
			continue
		}
		t.Run(tc.rule+"/"+tc.name, func(t *testing.T) {
			rule := rules[tc.rule]()
			// checkRuleSafely converts panics/timeouts into findings, so a
			// crashing analyzer fails the fixture with a clear "-error" rule
			// finding instead of taking down the test binary.
			findings := checkRuleSafely(rule, tc.diff)
			sortFindings(findings)

			if *fixtureUpdate {
				if err := writeExpectFile(filepath.Join(tc.dir, "expect.yaml"), findings); err != nil {
					t.Fatalf("update expect.yaml: %v", err)
				}
				if tc.hasGold {
					if err := writeGoldenFile(filepath.Join(tc.dir, "golden.json"), findings); err != nil {
						t.Fatalf("update golden.json: %v", err)
					}
				}
				t.Logf("updated %s/%s: %d findings", tc.rule, tc.name, len(findings))
				return
			}

			// Exact-count matching: every expected entry must claim a distinct
			// actual finding and no actual finding may go unclaimed.
			used := make([]bool, len(findings))
			var unmatched []fixtureExpectation
			for _, want := range tc.expect.Findings {
				matched := false
				for i, f := range findings {
					if !used[i] && findingMatches(f, want, tc.rule) {
						used[i] = true
						matched = true
						break
					}
				}
				if !matched {
					unmatched = append(unmatched, want)
				}
			}

			var problems []string
			for _, want := range unmatched {
				problems = append(problems, "  expected but not found: "+describeExpectation(want, tc.rule))
			}
			for i, f := range findings {
				if !used[i] {
					problems = append(problems, "  unexpected finding:   "+describeFinding(f))
				}
			}
			if len(problems) > 0 {
				t.Fatalf("fixture %s/%s mismatch (%d findings, want %d):\n%s",
					tc.rule, tc.name, len(findings), len(tc.expect.Findings), strings.Join(problems, "\n"))
			}

			if tc.hasGold {
				assertGolden(t, filepath.Join(tc.dir, "golden.json"), findings)
			}
		})
	}
}

func writeGoldenFile(path string, findings []Finding) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// assertGolden compares serialized findings against golden.json byte-for-byte.
// Use it only where the serialized shape itself is the contract; prefer
// expect.yaml field assertions everywhere else.
func assertGolden(t *testing.T, path string, findings []Finding) {
	t.Helper()
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden.json: %v", err)
	}
	got, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Fatalf("marshal findings: %v", err)
	}
	got = append(got, '\n')
	if string(got) != string(want) {
		t.Fatalf("golden mismatch for %s\n--- golden.json ---\n%s\n--- actual ---\n%s",
			filepath.Base(filepath.Dir(path)), want, got)
	}
}
