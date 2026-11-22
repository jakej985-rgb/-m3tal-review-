package review

import (
	"testing"
)

func TestAndroidSigningRule(t *testing.T) {
	rule := AndroidSigningRule{}

	t.Run("flags taskNames gating and debug fallback in release block", func(t *testing.T) {
		diff := `diff --git a/android/app/build.gradle.kts b/android/app/build.gradle.kts
--- a/android/app/build.gradle.kts
+++ b/android/app/build.gradle.kts
@@ -58,6 +58,18 @@ android {
     buildTypes {
         release {
             val releaseConfig = signingConfigs.getByName("release")
+            val releaseTaskRequested = gradle.startParameter.taskNames.any {
+                it.contains("Release", ignoreCase = true)
+            }
+            if (releaseTaskRequested && releaseConfig.storeFile?.exists() != true) {
+                throw GradleException("Keystore required")
+            }
+            signingConfig = if (releaseTaskRequested) {
+                releaseConfig
+            } else {
+                signingConfigs.getByName("debug")
+            }
+        }
     }
 }
`
		findings := rule.Check(diff)
		if len(findings) < 2 {
			t.Fatalf("expected at least 2 findings, got %d: %+v", len(findings), findings)
		}
		foundTaskNames := false
		foundDebugFallback := false
		for _, f := range findings {
			if f.Rule != "android-signing-bypass" {
				t.Errorf("unexpected rule name: %s", f.Rule)
			}
			if f.Severity != "high" {
				t.Errorf("unexpected severity: %s", f.Severity)
			}
			if f.Line == 61 {
				foundTaskNames = true
			}
			if f.Line == 70 {
				foundDebugFallback = true
			}
		}
		if !foundTaskNames {
			t.Errorf("missing finding for startParameter.taskNames check")
		}
		if !foundDebugFallback {
			t.Errorf("missing finding for debug fallback")
		}
	})

	t.Run("passes clean release signing configuration", func(t *testing.T) {
		diff := `diff --git a/android/app/build.gradle.kts b/android/app/build.gradle.kts
--- a/android/app/build.gradle.kts
+++ b/android/app/build.gradle.kts
@@ -58,6 +58,4 @@ android {
     buildTypes {
         release {
             signingConfig = signingConfigs.getByName("release")
         }
     }
 }
`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d: %+v", len(findings), findings)
		}
	})
}
