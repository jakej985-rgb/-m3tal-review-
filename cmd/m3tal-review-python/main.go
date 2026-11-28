package main

import (
	"os"

	"github.com/jakej985-rgb/m3tal-review/internal/apps/appcli"
	"github.com/jakej985-rgb/m3tal-review/internal/apps/python"
)

func main() {
	os.Exit(appcli.Main("m3tal-review-python", python.App{}, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
