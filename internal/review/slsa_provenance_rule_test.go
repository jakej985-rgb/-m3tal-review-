package review

import (
	"testing"
)

func TestSLSAProvenanceRule(t *testing.T) {
	rule := SLSAProvenanceRule{}

	t.Run("flags SLSA statement missing predicate wrapper", func(t *testing.T) {
		diff := `diff --git a/scripts/generate_release_provenance.py b/scripts/generate_release_provenance.py
--- a/scripts/generate_release_provenance.py
+++ b/scripts/generate_release_provenance.py
@@ -58,15 +58,15 @@ def generate_checksums():
+    provenance_data = {
+        "_type": "https://in-toto.io/Statement/v0.1",
+        "predicateType": "https://slsa.dev/provenance/v0.2",
+        "subject": [
+            {"name": a["name"], "digest": {"sha256": a["sha256"]}}
+            for a in artifacts_metadata
+        ],
+        "builder": {
+            "id": "https://github.com/example/repo"
+        },
+        "metadata": {
+            "buildStartedOn": "2026-01-01T00:00:00Z"
+        }
+    }
`
		findings := rule.Check(diff)
		if len(findings) == 0 {
			t.Fatalf("expected findings for missing predicate wrapper, got 0")
		}
		if findings[0].Rule != "slsa-provenance-schema" {
			t.Errorf("unexpected rule: %s", findings[0].Rule)
		}
	})

	t.Run("passes properly nested SLSA statement", func(t *testing.T) {
		diff := `diff --git a/scripts/generate_release_provenance.py b/scripts/generate_release_provenance.py
--- a/scripts/generate_release_provenance.py
+++ b/scripts/generate_release_provenance.py
@@ -58,15 +58,17 @@ def generate_checksums():
+    provenance_data = {
+        "_type": "https://in-toto.io/Statement/v0.1",
+        "predicateType": "https://slsa.dev/provenance/v0.2",
+        "subject": [
+            {"name": a["name"], "digest": {"sha256": a["sha256"]}}
+            for a in artifacts_metadata
+        ],
+        "predicate": {
+            "builder": {
+                "id": "https://github.com/example/repo"
+            },
+            "metadata": {
+                "buildStartedOn": "2026-01-01T00:00:00Z"
+            }
+        }
+    }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
