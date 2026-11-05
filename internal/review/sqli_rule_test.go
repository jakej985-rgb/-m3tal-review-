package review

import "testing"

func TestSQLiRuleFindsFormattedQueries(t *testing.T) {
	diff := `diff --git a/db.go b/db.go
--- a/db.go
+++ b/db.go
@@ -0,0 +1,5 @@
+package main
+
+func lookup(db *sql.DB, name string) {
+	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
+	_ = fmt.Sprintf("SELECT %s", name)
+}
`
	findings := (SQLiRule{}).Check(diff)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v; want 1 (concat query only; Sprintf outside query call)", findings)
	}
}

func TestSQLiRuleFindsGoSprintfInQuery(t *testing.T) {
	diff := `diff --git a/db.go b/db.go
--- a/db.go
+++ b/db.go
@@ -0,0 +1,3 @@
+package main
+
+	_, err := db.Query(fmt.Sprintf("SELECT * FROM t WHERE id = %d", id))
`
	if got := (SQLiRule{}).Check(diff); len(got) != 1 {
		t.Fatalf("findings = %+v; want 1", got)
	}
}

func TestSQLiRuleFindsPythonAndJSTemplate(t *testing.T) {
	pyDiff := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
+cursor.execute("SELECT * FROM users WHERE name = %s" % name)
`
	if got := (SQLiRule{}).Check(pyDiff); len(got) != 2 {
		t.Fatalf("python findings = %+v; want 2", got)
	}
	jsDiff := "diff --git a/app.js b/app.js\n--- a/app.js\n+++ b/app.js\n@@ -0,0 +1 @@\n+db.query(`SELECT * FROM users WHERE id = ${uid}`)\n"
	if got := (SQLiRule{}).Check(jsDiff); len(got) != 1 {
		t.Fatalf("js findings = %+v; want 1", got)
	}
}
