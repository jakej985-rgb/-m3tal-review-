package review

import (
	"testing"
)

func TestGhCliAssetRule(t *testing.T) {
	rule := GhCliAssetRule{}

	t.Run("flags browser_download_url in gh release view pipeline", func(t *testing.T) {
		diff := `diff --git a/.github/workflows/dispatch-apt.yml b/.github/workflows/dispatch-apt.yml
--- a/.github/workflows/dispatch-apt.yml
+++ b/.github/workflows/dispatch-apt.yml
@@ -50,3 +50,3 @@ jobs:
-            DEB_URL=$(gh release view "${TAG}" --repo "${REPO}" --json assets --jq '.assets[] | select(.name | endswith(".deb")) | .url' 2>/dev/null | head -n 1 || true)
+            DEB_URL=$(gh release view "${TAG}" --repo "${REPO}" --json assets --jq '.assets[] | select(.name | endswith(".deb")) | .browser_download_url' 2>/dev/null | head -n 1 || true)
`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %+v", len(findings), findings)
		}
		if findings[0].Rule != "gh-cli-asset-url" {
			t.Errorf("unexpected rule: %s", findings[0].Rule)
		}
	})

	t.Run("passes correct .url query", func(t *testing.T) {
		diff := `diff --git a/.github/workflows/dispatch-apt.yml b/.github/workflows/dispatch-apt.yml
--- a/.github/workflows/dispatch-apt.yml
+++ b/.github/workflows/dispatch-apt.yml
@@ -50,3 +50,3 @@ jobs:
+            DEB_URL=$(gh release view "${TAG}" --repo "${REPO}" --json assets --jq '.assets[] | select(.name | endswith(".deb")) | .url' 2>/dev/null | head -n 1 || true)
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
