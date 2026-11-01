package git

import (
	"fmt"
	"os/exec"
	"strings"
)

func RepositoryRoot(path string) (string, error) {
	command := exec.Command("git", "-C", path, "rev-parse", "--show-toplevel")

	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("find repository root: %w", err)
	}

	root := strings.TrimSpace(string(output))

	return root, nil
}