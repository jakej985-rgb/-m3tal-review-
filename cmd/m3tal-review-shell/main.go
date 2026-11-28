package main

import (
	"os"

	"github.com/jakej985-rgb/m3tal-review/internal/apps/appcli"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/shell"
)

func main() {
	os.Exit(appcli.Main("m3tal-review-shell", shell.App{}, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
