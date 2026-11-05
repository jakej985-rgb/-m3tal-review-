package review

import "testing"

func TestTraversalRuleFindsRequestControlledPaths(t *testing.T) {
	diff := `diff --git a/handler.go b/handler.go
--- a/handler.go
+++ b/handler.go
@@ -0,0 +1,6 @@
+package main
+
+func serve(w http.ResponseWriter, r *http.Request) {
+	http.ServeFile(w, r, r.URL.Path)
+}
+func safe() { os.ReadFile("/etc/hostname") }
`
	findings := (TraversalRule{}).Check(diff)
	if len(findings) != 1 || findings[0].Line != 4 {
		t.Fatalf("findings = %+v; want one finding at line 4", findings)
	}
}

func TestTraversalRuleFindsPythonAndJS(t *testing.T) {
	pyDiff := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1 @@
+data = open(request.args.get("file"))
`
	jsDiff := `diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -0,0 +1 @@
+fs.readFileSync(req.query.path)
`
	if got := (TraversalRule{}).Check(pyDiff); len(got) != 1 {
		t.Fatalf("python findings = %+v; want 1", got)
	}
	if got := (TraversalRule{}).Check(jsDiff); len(got) != 1 {
		t.Fatalf("js findings = %+v; want 1", got)
	}
}
