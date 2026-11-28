package cli

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRunAppsListAndDoctor(t *testing.T) {
	binDir := t.TempDir()
	goBin := filepath.Join(binDir, "m3tal-review-go")
	if out, err := exec.Command("go", "build", "-o", goBin, "../../cmd/m3tal-review-go").CombinedOutput(); err != nil {
		t.Fatalf("build m3tal-review-go: %v\n%s", err, string(out))
	}

	if err := runAppsCommand([]string{"list", "--app-path", binDir, "--format", "json"}); err != nil {
		t.Fatalf("apps list failed: %v", err)
	}
	if err := runAppsCommand([]string{"doctor", "--app-path", binDir, "--format", "json"}); err != nil {
		t.Fatalf("apps doctor failed: %v", err)
	}

	emptyDir := t.TempDir()
	if err := runAppsCommand([]string{"doctor", "--app-path", emptyDir, "--format", "text"}); err == nil {
		t.Fatalf("expected apps doctor to fail when required review-go is missing")
	}
}
