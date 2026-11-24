package review

import (
	"testing"
)

func TestQualityGatePreflightRule(t *testing.T) {
	rule := QualityGatePreflightRule{}

	t.Run("flags gate script missing preflight check", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,6 @@
+#!/usr/bin/env bash
+set -e
+echo "Running tests..."
+python3 -m unittest discover -s test/scripts -p 'test_*.py'
+echo "Done"
+`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for missing preflight check, got 0")
		}
		if findings[0].Rule != "quality-gate-preflight-dependency" {
			t.Errorf("expected rule quality-gate-preflight-dependency, got %s", findings[0].Rule)
		}
	})

	t.Run("passes when preflight check exists", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,8 @@
+#!/usr/bin/env bash
+set -e
+python3 -c "import yaml, jsonschema, PIL, markdown"
+echo "Running tests..."
+python3 -m unittest discover -s test/scripts -p 'test_*.py'
+echo "Done"
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("ignores runner inside a function declaration", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,3 @@
+#!/usr/bin/env bash
+set -e
+run_tests() { cd tests && pytest; }
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for an uncalled runner declaration, got %d", len(findings))
		}
	})

	t.Run("flags top-level call to runner function without preflight", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,4 @@
+#!/usr/bin/env bash
+set -e
+run_tests() { cd tests && pytest; }
+run_tests
+`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for a runner function call without preflight, got 0")
		}
	})

	t.Run("passes one-line runner declaration invoked after same-line preflight", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,2 @@
+#!/usr/bin/env bash
+run_tests() { cd tests && pytest; }; python3 -c 'import pytest' && run_tests
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for same-line preflight before runner call, got %d", len(findings))
		}
	})

	t.Run("passes runner function call after preflight", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,5 @@
+#!/usr/bin/env bash
+set -e
+python3 -c "import pytest"
+run_tests() { cd tests && pytest; }
+run_tests
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for runner call after preflight, got %d", len(findings))
		}
	})

	t.Run("flags runner function call before later preflight", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,5 @@
+#!/usr/bin/env bash
+set -e
+run_tests() { cd tests && pytest; }
+run_tests
+python3 -c "import pytest"
+`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for runner call before preflight, got 0")
		}
	})

	t.Run("flags linter-only gate script missing preflight check", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,6 @@
+#!/usr/bin/env bash
+set -e
+echo "Running linter..."
+python3 -m flake8 .
+echo "Done"
+`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for linter-only gate script without preflight check, got 0")
		}
	})

	t.Run("passes for deletion-only diff in gate script", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
--- a/scripts/quality_gate.sh
+++ b/scripts/quality_gate.sh
@@ -1,4 +1,3 @@
 #!/usr/bin/env bash
 set -e
-# old comment removed
 python3 -m flake8 .
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for deletion-only diff, got %d", len(findings))
		}
	})

	t.Run("flags added test command after unchanged linter without preflight", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
--- a/scripts/quality_gate.sh
+++ b/scripts/quality_gate.sh
@@ -1,3 +1,4 @@
 #!/usr/bin/env bash
 set -e
 ruff check .
+python3 -m unittest discover
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding for added test command after unchanged linter, got 0")
		}
	})

	t.Run("ignores pytest or linter mentions in comments and echo", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,5 @@
+#!/usr/bin/env bash
+set -e
+# run pytest later
+echo "skipping pytest and flake8"
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings for comments and echo mentions, got %d", len(findings))
		}
	})

	t.Run("flags unchanged runner when preflight check is deleted", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
--- a/scripts/quality_gate.sh
+++ b/scripts/quality_gate.sh
@@ -1,4 +1,3 @@
 #!/usr/bin/env bash
 set -e
-python3 -c 'import package'
 python3 -m unittest discover
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected finding when preflight check is deleted, got 0")
		}
	})

	gateDiff := func(body string) string {
		return "diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh\n" +
			"new file mode 100755\n--- /dev/null\n+++ b/scripts/quality_gate.sh\n" +
			"@@ -0,0 +1,4 @@\n+#!/usr/bin/env bash\n+set -e\n+" + body + "\n"
	}

	for name, body := range map[string]string{
		"if-wrapped runner":  "if pytest; then echo ok; else exit 1; fi",
		"uv run launcher":    "uv run pytest",
		"quoted executable":  `"$VIRTUAL_ENV/bin/pytest"`,
		"quoted module name": "python3 -m 'pytest'",
	} {
		t.Run("flags "+name, func(t *testing.T) {
			if findings := rule.Check(gateDiff(body)); len(findings) == 0 {
				t.Fatalf("expected finding for %q, got 0", body)
			}
		})
	}

	t.Run("ignores runner names inside echo with separators", func(t *testing.T) {
		if findings := rule.Check(gateDiff(`echo "next; pytest"`)); len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})

	t.Run("flags runner when import check only appears after it", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
new file mode 100755
--- /dev/null
+++ b/scripts/quality_gate.sh
@@ -0,0 +1,3 @@
+#!/usr/bin/env bash
+pytest
+python3 -c "import yaml"
`
		if findings := rule.Check(diff); len(findings) == 0 {
			t.Fatalf("expected finding for late preflight, got 0")
		}
	})

	t.Run("flags runner before same-line preflight", func(t *testing.T) {
		if findings := rule.Check(gateDiff("pytest && python3.12 -c 'import yaml'")); len(findings) == 0 {
			t.Fatalf("expected finding for runner preceding same-line preflight, got 0")
		}
	})

	t.Run("commented preflight does not count", func(t *testing.T) {
		if findings := rule.Check(gateDiff("# python3 -c 'import pytest'\n+pytest")); len(findings) == 0 {
			t.Fatalf("expected finding when preflight is only a comment, got 0")
		}
	})

	t.Run("deleting commented preflight does not flag unchanged runner", func(t *testing.T) {
		diff := `diff --git a/scripts/quality_gate.sh b/scripts/quality_gate.sh
--- a/scripts/quality_gate.sh
+++ b/scripts/quality_gate.sh
@@ -1,3 +1,2 @@
 #!/usr/bin/env bash
-# python3 -c 'import pytest'
 pytest
`
		if findings := rule.Check(diff); len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
