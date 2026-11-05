package review

import "testing"

func TestCryptoRuleFindsWeakPrimitives(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -0,0 +1,6 @@
+package main
+
+import "crypto/md5"
+
+var sessionToken = fmt.Sprintf("%x", rand.Int63())
+func sum(b []byte) [16]byte { return md5.Sum(b) }
+func ok() []byte { return make([]byte, 32) }
`
	findings := (CryptoRule{}).Check(diff)
	var weakHash, weakRandom int
	for _, f := range findings {
		switch f.Severity {
		case "low":
			weakHash++
		case "high":
			weakRandom++
		default:
			t.Fatalf("unexpected finding: %+v", f)
		}
	}
	if weakHash != 1 || weakRandom != 1 {
		t.Fatalf("weakHash=%d weakRandom=%d; want 1 each (findings: %+v)", weakHash, weakRandom, findings)
	}
}

func TestCryptoRuleIgnoresCryptoRandAndNonSecretRandom(t *testing.T) {
	diff := `diff --git a/main.go b/main.go
--- a/main.go
+++ b/main.go
@@ -0,0 +1,3 @@
+package main
+
+func jitter() int { return rand.Intn(100) }
`
	// math/rand for non-security values is not flagged: the variable name is
	// not security-sensitive.
	if got := (CryptoRule{}).Check(diff); len(got) != 0 {
		t.Fatalf("findings = %+v; want none", got)
	}
}

func TestCryptoRuleFindsPythonAndJSSecrets(t *testing.T) {
	pyDiff := `diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -0,0 +1,2 @@
+import random
+api_key = "".join(random.choices("abcdef", k=32))
`
	if got := (CryptoRule{}).Check(pyDiff); len(got) != 1 {
		t.Fatalf("python findings = %+v; want 1", got)
	}
	jsDiff := `diff --git a/app.js b/app.js
--- a/app.js
+++ b/app.js
@@ -0,0 +1 @@
+const sessionToken = Math.random().toString(36)
`
	if got := (CryptoRule{}).Check(jsDiff); len(got) != 1 {
		t.Fatalf("js findings = %+v; want 1", got)
	}
}
