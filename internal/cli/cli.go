package cli

import (
	"fmt"
	"os"
	"runtime"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
)

var (
	appName = "M3TAL Review"
	version = "1.0.0"
)

func Run(args []string) error {
	command := "help"

	if len(args) > 0 {
		command = args[0]
	}

	return execute(command)
}

func execute(command string) error {
	switch command {
	case "version":
		fmt.Println(appName)
		fmt.Println("Version:", version)
		fmt.Println("Go:", runtime.Version())

		return nil

	case "check":
		workingDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}

		if err := git.Available(); err != nil {
			return err
		}

		repositoryRoot, err := git.RepositoryRoot(workingDir)
		if err != nil {
			return err
		}

		fmt.Println("M3TAL Review")
		fmt.Println("Working directory:", workingDir)
		fmt.Println("Repository root:", repositoryRoot)

		return nil

	case "help":
		printHelp()
		return nil

	default:
		printHelp()
		return fmt.Errorf("unknown command %q", command)
	}
}

func printHelp() {
	fmt.Println(appName)
	fmt.Println("Available commands:")
	fmt.Println("  version")
	fmt.Println("  check")
	fmt.Println("  help")
}
