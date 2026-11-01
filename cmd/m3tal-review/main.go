package main

import (
	"fmt"
	"os"

	"github.com/jakej985-rgb/m3tal-review/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
