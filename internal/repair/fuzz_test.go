package repair

import (
	"strings"
	"testing"
)

func FuzzValidatePatch(f *testing.F) {
	f.Add("--- a/main.go\n+++ b/main.go\n@@ -1,1 +1,1 @@\n-old\n+new\n", "main.go")
	f.Add("", "main.go")
	f.Add("@@ invalid header @@", "main.go")
	f.Add("--- a/secret.txt\n+++ b/secret.txt\n", "main.go")
	f.Add("--- /etc/passwd\n+++ /etc/passwd\n", "/etc/passwd")

	f.Fuzz(func(t *testing.T, patch, targetFile string) {
		if len(patch) > 1<<18 || len(targetFile) > 512 {
			return
		}
		err := ValidatePatch(patch, targetFile)
		if err != nil && len(patch) == 0 {
			t.Log("empty patch rejected")
		}
	})
}

func FuzzValidateTargetFilePath(f *testing.F) {
	f.Add("/tmp/repo", "main.go")
	f.Add("/tmp/repo", "../escape.go")
	f.Add("/tmp/repo", "/etc/shadow")
	f.Add("/tmp/repo", "internal/../../evil")
	f.Add("", "")

	f.Fuzz(func(t *testing.T, repoRoot, targetFile string) {
		if len(repoRoot) > 256 || len(targetFile) > 256 {
			return
		}
		err := ValidateTargetFilePath(repoRoot, targetFile)
		if err != nil && repoRoot == "" && targetFile == "" {
			t.Log("empty validation failure expected")
		}
	})
}

func FuzzApplyProposalToContent(f *testing.F) {
	samplePatch := "--- a/main.go\n+++ b/main.go\n@@ -1,3 +1,3 @@\n" +
		" package main\n-\n+ // comment\n func main() {}\n"
	f.Add("package main\n\nfunc main() {}\n", samplePatch)
	f.Add("", "")
	f.Add("line1\nline2\nline3\n", "@@ -1,2 +1,2 @@\n-line1\n+mod1\n line2\n")

	f.Fuzz(func(t *testing.T, original, patch string) {
		if len(original) > 1<<18 || len(patch) > 1<<18 {
			return
		}
		p := &Proposal{
			TargetFile:      "main.go",
			Patch:           patch,
			ProposedContent: strings.ReplaceAll(original, "line1", "mod1"),
		}
		newContent, err := ApplyProposalToContent(original, p)
		if err == nil && len(newContent) < 0 {
			t.Fatal("negative content length")
		}
	})
}
