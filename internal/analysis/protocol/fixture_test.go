package protocol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/analysis"
	"gopkg.in/yaml.v3"
)

// fixtureExpect is the expect.yaml format for protocol fixtures:
// field-level assertions (never full snapshots) like the other
// analysis fixture harnesses.
type fixtureExpect struct {
	// ParseErrorContains, when set, asserts that parsing the case's
	// contract documents fails with a message containing it.
	ParseErrorContains string `yaml:"parse_error_contains"`
	// Findings lists expected unsuppressed findings; each entry must
	// match at least one finding. The number of findings is checked
	// exactly only when TotalFindings is set.
	Findings []struct {
		MessageContains string `yaml:"message_contains"`
		Element         string `yaml:"element"`
		ChangeKind      string `yaml:"change_kind"`
		Directions      string `yaml:"directions"`
		Severity        string `yaml:"severity"`
		Status          string `yaml:"status"`
	} `yaml:"findings"`
	// TotalFindings optionally asserts the exact number of
	// unsuppressed findings.
	TotalFindings *int `yaml:"total_findings"`
	// Suppressed optionally asserts the exact number of changes
	// suppressed by compat annotations.
	Suppressed *int `yaml:"suppressed"`
	// Diagnostics lists substrings that must each appear in at least
	// one diagnostic (contract check or comparison).
	Diagnostics []struct {
		MessageContains string `yaml:"message_contains"`
	} `yaml:"diagnostics"`
	// MatrixVersions lists deployed versions for matrix cases.
	MatrixVersions []string `yaml:"matrix_versions"`
	// Matrix asserts compatibility cells as "client->server" pairs.
	Matrix *struct {
		Compatible   []string `yaml:"compatible"`
		Incompatible []string `yaml:"incompatible"`
	} `yaml:"matrix"`
}

// TestFixtureSuite runs every case under testdata/: comparison cases
// contain old.yaml + new.yaml + expect.yaml; matrix cases contain a
// snapshots/ directory of contract files plus expect.yaml.
func TestFixtureSuite(t *testing.T) {
	root := filepath.Join("testdata")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		caseDir := filepath.Join(root, ent.Name())
		t.Run(ent.Name(), func(t *testing.T) { runFixture(t, caseDir) })
	}
}

func runFixture(t *testing.T, caseDir string) {
	t.Helper()
	expectPath := filepath.Join(caseDir, "expect.yaml")
	expectData, err := os.ReadFile(expectPath)
	if err != nil {
		t.Fatalf("read expect.yaml: %v", err)
	}
	var expect fixtureExpect
	if err := yaml.Unmarshal(expectData, &expect); err != nil {
		t.Fatalf("parse expect.yaml: %v", err)
	}

	if expect.Matrix != nil || len(expect.MatrixVersions) > 0 {
		runMatrixFixture(t, caseDir, &expect)
		return
	}

	oldPath := filepath.Join(caseDir, "old.yaml")
	newPath := filepath.Join(caseDir, "new.yaml")
	oldDoc, err := os.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("read old.yaml: %v", err)
	}
	newDoc, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatalf("read new.yaml: %v", err)
	}

	oldC, oldErr := ParseContract(oldDoc)
	newC, newErr := ParseContract(newDoc)
	if expect.ParseErrorContains != "" {
		var perr error
		if oldErr != nil {
			perr = oldErr
		} else {
			perr = newErr
		}
		if perr == nil {
			t.Fatalf("expected parse error containing %q, got none", expect.ParseErrorContains)
		}
		if !strings.Contains(perr.Error(), expect.ParseErrorContains) {
			t.Fatalf("parse error %q does not contain %q", perr, expect.ParseErrorContains)
		}
		return
	}
	if oldErr != nil {
		t.Fatalf("old.yaml: %v", oldErr)
	}
	if newErr != nil {
		t.Fatalf("new.yaml: %v", newErr)
	}
	oldC.Source = oldPath
	newC.Source = newPath

	cmp := Compare(oldC, newC)
	checkDiagnostics(t, cmp.Diagnostics, expect.diagnostics())

	if expect.Suppressed != nil && len(cmp.Suppressed) != *expect.Suppressed {
		t.Fatalf("suppressed count: got %d want %d (%+v)",
			len(cmp.Suppressed), *expect.Suppressed, cmp.Suppressed)
	}

	findings := cmp.Findings()
	if expect.TotalFindings != nil && len(findings) != *expect.TotalFindings {
		t.Fatalf("finding count: got %d want %d; findings=%+v",
			len(findings), *expect.TotalFindings, findings)
	}
	for i, want := range expect.Findings {
		if !findingMatches(findings, want) {
			t.Errorf("findings[%d]: no finding matches %+v; have %d findings", i, want, len(findings))
			for _, f := range findings {
				t.Logf("  finding: %s | %s | %s", f.Severity, f.Metadata["element"], f.Message)
			}
		}
	}
}

func (e *fixtureExpect) diagnostics() []struct {
	MessageContains string `yaml:"message_contains"`
} {
	return e.Diagnostics
}

func findingMatches(findings []analysis.Finding, want struct {
	MessageContains string `yaml:"message_contains"`
	Element         string `yaml:"element"`
	ChangeKind      string `yaml:"change_kind"`
	Directions      string `yaml:"directions"`
	Severity        string `yaml:"severity"`
	Status          string `yaml:"status"`
}) bool {
	for _, f := range findings {
		if want.MessageContains != "" && !strings.Contains(f.Message, want.MessageContains) {
			continue
		}
		if want.Element != "" && f.Metadata["element"] != want.Element {
			continue
		}
		if want.ChangeKind != "" && f.Metadata["change_kind"] != want.ChangeKind {
			continue
		}
		if want.Directions != "" && f.Metadata["directions"] != want.Directions {
			continue
		}
		if want.Severity != "" && f.Severity != want.Severity {
			continue
		}
		if want.Status != "" && string(f.Status) != want.Status {
			continue
		}
		return true
	}
	return false
}

func checkDiagnostics(t *testing.T, diags []analysis.Diagnostic, wants []struct {
	MessageContains string `yaml:"message_contains"`
}) {
	t.Helper()
	for _, w := range wants {
		found := false
		for _, d := range diags {
			if strings.Contains(d.Message, w.MessageContains) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no diagnostic contains %q; have %v", w.MessageContains, diags)
		}
	}
}

func runMatrixFixture(t *testing.T, caseDir string, expect *fixtureExpect) {
	t.Helper()
	set, err := LoadSnapshotSet(filepath.Join(caseDir, "snapshots"))
	if err != nil {
		t.Fatalf("LoadSnapshotSet: %v", err)
	}
	res := EvaluateMatrix(set, expect.MatrixVersions)
	checkDiagnostics(t, res.Diagnostics, expect.Diagnostics)

	cell := func(pair string) (MatrixCell, bool) {
		parts := strings.Split(pair, "->")
		if len(parts) != 2 {
			t.Fatalf("bad matrix pair %q", pair)
		}
		row, ok := res.Cells[parts[0]]
		if !ok {
			return MatrixCell{}, false
		}
		c, ok := row[parts[1]]
		return c, ok
	}
	if expect.Matrix != nil {
		for _, pair := range expect.Matrix.Compatible {
			c, ok := cell(pair)
			if !ok {
				t.Errorf("matrix pair %s: cell missing", pair)
				continue
			}
			if !c.Compatible {
				t.Errorf("matrix pair %s: expected compatible, got %d breaking findings", pair, len(c.Breaking))
			}
		}
		for _, pair := range expect.Matrix.Incompatible {
			c, ok := cell(pair)
			if !ok {
				t.Errorf("matrix pair %s: cell missing", pair)
				continue
			}
			if c.Compatible {
				t.Errorf("matrix pair %s: expected incompatible", pair)
			}
		}
	}
}
