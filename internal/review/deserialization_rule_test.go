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

func TestDeserializationRuleFindsCSharpJavaAndTorch(t *testing.T) {
	// Python torch.load
	torchDiff := "diff --git a/model.py b/model.py\n--- a/model.py\n+++ b/model.py\n@@ -0,0 +1 @@\n+weights = torch.load('checkpoint.pt')\n"
	if got := (DeserializationRule{}).Check(torchDiff); len(got) != 1 {
		t.Fatalf("torch findings = %+v; want 1", got)
	}

	// C# BinaryFormatter
	csDiff := "diff --git a/Data.cs b/Data.cs\n--- a/Data.cs\n+++ b/Data.cs\n@@ -0,0 +1 @@\n+var formatter = new BinaryFormatter();\n"
	if got := (DeserializationRule{}).Check(csDiff); len(got) != 1 {
		t.Fatalf("csharp findings = %+v; want 1", got)
	}

	// Java XMLDecoder
	javaDiff := "diff --git a/Parser.java b/Parser.java\n--- a/Parser.java\n+++ b/Parser.java\n@@ -0,0 +1 @@\n+XMLDecoder d = new XMLDecoder(in);\n"
	if got := (DeserializationRule{}).Check(javaDiff); len(got) != 1 {
		t.Fatalf("java findings = %+v; want 1", got)
	}
}
