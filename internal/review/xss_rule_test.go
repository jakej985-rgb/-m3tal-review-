package review

import "testing"

func TestXSSRuleFindsDOMSinkInjection(t *testing.T) {
	diff := `diff --git a/app.jsx b/app.jsx
--- a/app.jsx
+++ b/app.jsx
@@ -0,0 +1,4 @@
+function render(user) {
+	el.innerHTML = user.bio
+	document.write(user.name)
+	return <div>{user.name}</div>
+}
`
	findings := (XSSRule{}).Check(diff)
	if len(findings) != 2 {
		t.Fatalf("findings = %+v; want 2", findings)
	}
}

func TestXSSRuleFindsVueTemplateBinding(t *testing.T) {
	diff := `diff --git a/App.vue b/App.vue
--- a/App.vue
+++ b/App.vue
@@ -0,0 +1 @@
+<div v-html="user.content"></div>
`
	if got := (XSSRule{}).Check(diff); len(got) != 1 {
		t.Fatalf("findings = %+v; want 1", got)
	}
}
