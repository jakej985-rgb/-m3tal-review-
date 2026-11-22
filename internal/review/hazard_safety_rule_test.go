package review

import (
	"testing"
)

func TestHazardSafetyRule(t *testing.T) {
	rule := HazardSafetyRule{}

	t.Run("flags laser diode misclassified as caution with requiresParentUnlock=false", func(t *testing.T) {
		diff := `diff --git a/assets/curriculum/components/comp_37.json b/assets/curriculum/components/comp_37.json
--- a/assets/curriculum/components/comp_37.json
+++ b/assets/curriculum/components/comp_37.json
@@ -10,12 +10,12 @@
   "name": "650nm Red Laser Diode Module",
   "safety": {
-    "level": "restrictedAdultSupervision",
+    "level": "caution",
     "hazards": [
       "Direct eye exposure to laser beam can cause retinal injury"
     ],
-    "requiresParentUnlock": true
+    "requiresParentUnlock": false
   }
 }
`
		findings := rule.Check(diff)
		if len(findings) < 2 {
			t.Fatalf("expected at least 2 findings, got %d: %+v", len(findings), findings)
		}
		for _, f := range findings {
			if f.Rule != "hazard-safety-classification" {
				t.Errorf("unexpected rule name: %s", f.Rule)
			}
			if f.Severity != "high" {
				t.Errorf("unexpected severity: %s", f.Severity)
			}
		}
	})

	t.Run("passes properly classified restricted component", func(t *testing.T) {
		diff := `diff --git a/assets/curriculum/components/comp_37.json b/assets/curriculum/components/comp_37.json
--- a/assets/curriculum/components/comp_37.json
+++ b/assets/curriculum/components/comp_37.json
@@ -10,12 +10,12 @@
   "name": "650nm Red Laser Diode Module",
   "safety": {
+    "level": "restrictedAdultSupervision",
+    "hazards": [
+      "Direct eye exposure to laser beam can cause retinal injury"
+    ],
+    "requiresParentUnlock": true
   }
 }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
