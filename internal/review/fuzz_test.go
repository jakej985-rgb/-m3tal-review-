package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

// FuzzFixtureRules feeds arbitrary diffs through every rule registered in the
// fixture harness. It asserts only that analysis stays panic/timeout-safe
// (checkRuleSafely converts failures into findings) and terminates quickly;
// correctness is covered by TestFixtureSuite. When fuzzing discovers a crash
// or false positive, promote the reproducer into testdata/fixtures — see
// testdata/fixtures/README.md.
func FuzzFixtureRules(f *testing.F) {
	root := filepath.Join("..", "..", "testdata", "fixtures")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(path) != "input.diff" {
			return err
		}
		if data, err := os.ReadFile(path); err == nil {
			f.Add(strings.TrimSuffix(string(data), "\n"))
		}
		return nil
	})
	f.Add("diff --git a/x.go b/x.go\n")
	f.Add("")

	constructors := fixtureRules()
	names := sortedKeys(constructors)
	f.Fuzz(func(t *testing.T, diff string) {
		if len(diff) > 1<<20 {
			diff = diff[:1<<20]
		}
		for _, name := range names {
			_ = checkRuleSafely(constructors[name](), diff)
		}
	})
}
