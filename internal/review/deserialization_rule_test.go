package review

import "testing"

func TestDeserializationRuleFindsUnsafeLoads(t *testing.T) {
	diff := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,5 @@
+import pickle
+import yaml
+
+data = pickle.loads(raw)
+conf = yaml.load(raw)
`
	findings := (DeserializationRule{}).Check(diff)
	if len(findings) != 2 {
		t.Fatalf("findings = %+v; want 2", findings)
	}
}

func TestDeserializationRuleAcceptsSafeYAMLLoader(t *testing.T) {
	diff := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1 @@
+conf = yaml.load(raw, Loader=yaml.SafeLoader)
`
	if got := (DeserializationRule{}).Check(diff); len(got) != 0 {
		t.Fatalf("findings = %+v; want none for SafeLoader", got)
	}
}

func TestDeserializationRuleFindsPHPUnserialize(t *testing.T) {
	diff := `diff --git a/index.php b/index.php
--- a/index.php
+++ b/index.php
@@ -0,0 +1 @@
+$obj = unserialize($_COOKIE["data"]);
`
	if got := (DeserializationRule{}).Check(diff); len(got) != 1 {
		t.Fatalf("findings = %+v; want 1", got)
	}
}
