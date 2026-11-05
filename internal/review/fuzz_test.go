package review

import "testing"

func FuzzParseDiff(f *testing.F) {
	f.Add("diff --git a/x.go b/x.go\n--- a/x.go\n+++ b/x.go\n@@ -1,1 +1,2 @@\n a\n+b\n")
	f.Add("")
	f.Add("@@ -1,1 +1,1 @@\n-x\n+y\n")
	f.Add("diff --git \"a/weird name.go\" \"b/weird name.go\"\n")
	f.Fuzz(func(t *testing.T, diff string) {
		if len(diff) > 1<<20 {
			diff = diff[:1<<20]
		}
		_ = ParseDiff(diff)
	})
}

func FuzzMatchesRepoPath(f *testing.F) {
	f.Add("**/*.go", "internal/foo/bar.go")
	f.Add("*.pem", "dir/key.pem")
	f.Add("docs/**", "docs/a/b.md")
	f.Fuzz(func(t *testing.T, pattern, path string) {
		if len(pattern) > 512 || len(path) > 512 {
			return
		}
		_ = matchesRepoPath(pattern, path)
	})
}
