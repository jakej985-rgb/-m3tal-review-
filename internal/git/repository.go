package git

import (
	"fmt"
	"os/exec"
	"strings"
)

func RepositoryRoot(path string) (string, error) {
	command := exec.Command("git", "-C", path, "rev-parse", "--show-toplevel")

	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"find repository root: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	root := strings.TrimSpace(string(output))

	return root, nil
}

func Available() error {
	_, err := exec.LookPath("git")
	if err != nil {
		return fmt.Errorf("git executable not found: %w", err)
	}

	return nil
}

func IsClean(path string) (bool, error) {
	command := exec.Command("git", "-C", path, "status", "--porcelain")

	output, err := command.CombinedOutput()
	if err != nil {
		return false, fmt.Errorf(
			"check working tree status: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	return strings.TrimSpace(string(output)) == "", nil
}

func CurrentBranch(path string) (string, error) {
	command := exec.Command("git", "-C", path, "branch", "--show-current")

	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf(
			"get current branch: %s: %w",
			strings.TrimSpace(string(output)),
			err,
		)
	}

	branch := strings.TrimSpace(string(output))
	if branch == "" {
		return "", fmt.Errorf("get current branch: repository is in detached HEAD state")
	}

	return branch, nil
}
