package cli

import (
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestParseReviewOptionsExtended(t *testing.T) {
	opts, err := parseReviewOptions([]string{"--only", "slop,secret", "--skip=debug", "--fail-on", "high", "--base", "origin/main", "--format", "sarif"})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts.Only) != 2 || opts.Only[0] != "slop" || opts.Skip[0] != "debug" || opts.FailOn != "high" || opts.Base != "origin/main" || opts.Format != "sarif" {
		t.Fatalf("options = %+v", opts)
	}
	if _, err := parseReviewOptions([]string{"--fail-on", "bogus"}); err == nil {
		t.Fatal("expected error for bad severity")
	}
	if _, err := parseReviewOptions([]string{"--format", "xml"}); err == nil {
		t.Fatal("expected error for bad format")
	}
}

func TestParsePluginOptions(t *testing.T) {
	opts, err := parseReviewOptions([]string{"--plugin-dir", "/tmp/plugins", "--allow-repo-plugins"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.PluginDir != "/tmp/plugins" || !opts.AllowRepoPlugins {
		t.Fatalf("review options = %+v", opts)
	}

	opts2, err := parseReviewOptions([]string{"--plugin-dir=/other"})
	if err != nil {
		t.Fatal(err)
	}
	if opts2.PluginDir != "/other" || opts2.AllowRepoPlugins {
		t.Fatalf("review options = %+v", opts2)
	}

	aopts, err := parseAuditOptions([]string{"--plugin-dir=/audited", "--allow-repo-plugins"})
	if err != nil {
		t.Fatal(err)
	}
	if aopts.PluginDir != "/audited" || !aopts.AllowRepoPlugins {
		t.Fatalf("audit options = %+v", aopts)
	}

	aopts2, err := parseAuditOptions([]string{"--plugin-dir", "/sep"})
	if err != nil {
		t.Fatal(err)
	}
	if aopts2.PluginDir != "/sep" {
		t.Fatalf("audit options = %+v", aopts2)
	}

	if _, err := parseReviewOptions([]string{"--plugin-dir"}); err == nil {
		t.Fatal("expected error for missing --plugin-dir value")
	}
	if _, err := parseAuditOptions([]string{"--plugin-dir"}); err == nil {
		t.Fatal("expected error for missing --plugin-dir value")
	}
}

func TestFilterRules(t *testing.T) {
	rules := []review.Rule{
		review.TodoRule{},
		review.DebugRule{},
		review.SlopRule{},
	}
	filtered := filterRules(rules, []string{"code-slop", "todo-marker"}, []string{"debug-leftover"})
	if len(filtered) != 2 {
		t.Fatalf("filtered = %v", filtered)
	}
	for _, r := range filtered {
		if r.Name() == "debug-leftover" {
			t.Fatalf("skipped rule present: %v", filtered)
		}
	}
}

// TestWorkingTreeRulesCoverAllRuleTypes guards against new Rule
// implementations silently defaulting to staged-content reads during audit,
// which produced stale findings on uncommitted working-tree changes.
func TestWorkingTreeRulesCoverAllRuleTypes(t *testing.T) {
	probes := []review.Rule{
		review.TaintRule{}, review.ScopeDefaultRule{}, review.PluginTrustRule{},
		review.PrivilegedExecRule{}, review.ProcessKillRule{}, review.CredentialQueryRule{},
	}
	for _, p := range probes {
		out := workingTreeRules([]review.Rule{p})
		switch typed := out[0].(type) {
		case review.TaintRule:
			if !typed.WorkingTree {
				t.Errorf("%s: WorkingTree not enabled", typed.Name())
			}
		case review.ScopeDefaultRule:
			if !typed.WorkingTree {
				t.Errorf("%s: WorkingTree not enabled", typed.Name())
			}
		case review.PluginTrustRule:
			if !typed.WorkingTree {
				t.Errorf("%s: WorkingTree not enabled", typed.Name())
			}
		case review.PrivilegedExecRule:
			if !typed.WorkingTree {
				t.Errorf("%s: WorkingTree not enabled", typed.Name())
			}
		case review.ProcessKillRule:
			if !typed.WorkingTree {
				t.Errorf("%s: WorkingTree not enabled", typed.Name())
			}
		case review.CredentialQueryRule:
			if !typed.WorkingTree {
				t.Errorf("%s: WorkingTree not enabled", typed.Name())
			}
		default:
			t.Errorf("unexpected rule type %T", out[0])
		}
	}
}
