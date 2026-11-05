package review

import "testing"

func TestEvalRuleFindsDynamicEvaluation(t *testing.T) {
	diff := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,3 @@
+def run(code):
+	return eval(code)
+exec(user_input)
`
	findings := (EvalRule{}).Check(diff)
	if len(findings) != 2 {
		t.Fatalf("findings = %+v; want 2", findings)
	}
}

func TestEvalRuleFindsJSAndStringSetTimeout(t *testing.T) {
	diff := `diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -0,0 +1,3 @@
+eval(userCode)
+setTimeout("doThing()", 100)
+setTimeout(doThing, 100)
`
	findings := (EvalRule{}).Check(diff)
	if len(findings) != 2 {
		t.Fatalf("findings = %+v; want 2 (eval + string setTimeout only)", findings)
	}
}

func TestEvalRuleIgnoresCommentsAndStrings(t *testing.T) {
	diff := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,3 @@
+# eval(code) is dangerous
+help_text = "use eval() carefully"
+result = safe_call()
`
	if got := (EvalRule{}).Check(diff); len(got) != 0 {
		t.Fatalf("findings = %+v; want none", got)
	}
}
