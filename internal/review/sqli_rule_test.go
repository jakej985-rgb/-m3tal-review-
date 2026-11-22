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

func TestSQLiRuleFindsCSharpJavaPHP(t *testing.T) {
	// C# EF Core raw SQL interpolation
	csDiff := "diff --git a/Repo.cs b/Repo.cs\n--- a/Repo.cs\n+++ b/Repo.cs\n@@ -0,0 +1 @@\n+ctx.Users.FromSqlRaw($\"SELECT * FROM Users WHERE Name = '{name}'\");\n"
	if got := (SQLiRule{}).Check(csDiff); len(got) != 1 {
		t.Fatalf("csharp findings = %+v; want 1", got)
	}

	// Java JPA query concatenation
	javaDiff := "diff --git a/OrderRepo.java b/OrderRepo.java\n--- a/OrderRepo.java\n+++ b/OrderRepo.java\n@@ -0,0 +1 @@\n+em.createNativeQuery(\"SELECT * FROM orders WHERE id = \" + orderId);\n"
	if got := (SQLiRule{}).Check(javaDiff); len(got) != 1 {
		t.Fatalf("java findings = %+v; want 1", got)
	}

	// PHP Laravel raw query concatenation
	phpDiff := "diff --git a/User.php b/User.php\n--- a/User.php\n+++ b/User.php\n@@ -0,0 +1 @@\n+DB::raw(\"SELECT * FROM users WHERE email = '\" . $email . \"'\");\n"
	if got := (SQLiRule{}).Check(phpDiff); len(got) != 1 {
		t.Fatalf("php findings = %+v; want 1", got)
	}
}

