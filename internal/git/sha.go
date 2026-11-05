package git

import (
	"os/exec"
	"strings"
)

func CurrentCommitSHA(repo string) (string, error) {
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "rev-parse", "HEAD")
	cmd.Dir = repo

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}
