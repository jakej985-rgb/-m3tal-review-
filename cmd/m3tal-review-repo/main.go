package main

import (
	"os"

	"github.com/jakej985-rgb/m3tal-review/internal/apps/appcli"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/repo"
)

func main() {
	os.Exit(appcli.Main("m3tal-review-repo", repo.App{}, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
