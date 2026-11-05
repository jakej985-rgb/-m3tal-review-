package git

import (
	"bytes"
	"fmt"
	"os/exec"
)

// StagedFileContent retrieves the staged content of a file from the git index.
func StagedFileContent(repo string, file string) ([]byte, error) {
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "show", ":"+file)
	cmd.Dir = repo

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git show :%s failed: %w (stderr: %s)", file, err, stderr.String())
	}

	return out.Bytes(), nil
}
