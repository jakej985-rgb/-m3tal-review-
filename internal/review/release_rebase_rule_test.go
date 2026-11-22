package review

import (
	"testing"
)

func TestReleaseRebaseRule(t *testing.T) {
	rule := ReleaseRebaseRule{}

	t.Run("flags git rebase in release workflow", func(t *testing.T) {
		diff := `diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml
--- a/.github/workflows/release.yml
+++ b/.github/workflows/release.yml
@@ -134,6 +134,8 @@ jobs:
           git commit -m "chore(release): bump version to $TAG"
           git fetch origin main
+          if ! git merge-base --is-ancestor origin/main HEAD; then
+            git rebase origin/main
+          fi
           git tag "$TAG"
           git push --atomic origin HEAD:main "$TAG"
`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "release-rebase-race" {
			t.Errorf("unexpected rule: %s", findings[0].Rule)
		}
		if findings[0].Severity != "high" {
			t.Errorf("unexpected severity: %s", findings[0].Severity)
		}
	})

	t.Run("ignores git rebase in non-release workflow", func(t *testing.T) {
		diff := `diff --git a/.github/workflows/sync-fork.yml b/.github/workflows/sync-fork.yml
--- a/.github/workflows/sync-fork.yml
+++ b/.github/workflows/sync-fork.yml
@@ -20,3 +20,4 @@ jobs:
       - run: |
           git fetch upstream
+          git rebase upstream/main
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
