package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/apps/golang"
	"github.com/jakej985-rgb/m3tal-review/protocol"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("m3tal-review-go", flag.ContinueOnError)
	fs.SetOutput(stderr)
	describe := fs.Bool("describe", false, "Print app capabilities and exit")
	fixMode := fs.Bool("fix", false, "Synthesize deterministic patches for findings on stdin")
	format := fs.String("format", "json", "Output format for standalone mode: json|text|sarif|github")
	if err := fs.Parse(args); err != nil {
		return protocol.ExitError
	}

	if *describe {
		res := golang.Describe()
		enc := json.NewEncoder(stdout)
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(stderr, "encode describe: %v\n", err)
			return protocol.ExitError
		}
		return protocol.ExitClean
	}

	if *fixMode {
		raw, err := io.ReadAll(io.LimitReader(stdin, protocol.MaxInputBytes+1))
		if err != nil {
			fmt.Fprintf(stderr, "read stdin: %v\n", err)
			return protocol.ExitError
		}
		var fixIn protocol.FixInput
		if err := json.Unmarshal(raw, &fixIn); err != nil || fixIn.Protocol != protocol.Version {
			fmt.Fprintf(stderr, "invalid fix input: %v\n", err)
			return protocol.ExitProtocol
		}
		fixOut := golang.Fix(fixIn)
		if err := json.NewEncoder(stdout).Encode(fixOut); err != nil {
			fmt.Fprintf(stderr, "encode fix output: %v\n", err)
			return protocol.ExitError
		}
		return protocol.ExitClean
	}

	rest := fs.Args()
	if len(rest) > 0 {
		switch *format {
		case "json", "text", "sarif", "github":
		default:
			fmt.Fprintf(stderr, "invalid --format %q (expected json, text, sarif, or github)\n", *format)
			return protocol.ExitError
		}
		return runStandalone(rest, *format, stdout, stderr)
	}

	raw, err := io.ReadAll(io.LimitReader(stdin, protocol.MaxInputBytes+1))
	if err != nil {
		fmt.Fprintf(stderr, "read stdin: %v\n", err)
		return protocol.ExitError
	}
	in, err := protocol.DecodeInput(raw)
	if err != nil {
		fmt.Fprintf(stderr, "invalid input: %v\n", err)
		return protocol.ExitProtocol
	}

	out := golang.Run(in)
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintf(stderr, "encode output: %v\n", err)
		return protocol.ExitError
	}
	if len(out.Findings) > 0 {
		return protocol.ExitFindings
	}
	return protocol.ExitClean
}

func runStandalone(targets []string, format string, stdout, stderr io.Writer) int {
	var files []protocol.File
	for _, t := range targets {
		clean := strings.TrimSuffix(t, "/...")
		if clean == "" || clean == "." {
			clean = "."
		}
		err := filepath.WalkDir(clean, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == "vendor" {
					return filepath.SkipDir
				}
				return nil
			}
			if filepath.Ext(p) != ".go" {
				return nil
			}
			data, readErr := os.ReadFile(p)
			if readErr != nil {
				return readErr
			}
			files = append(files, protocol.File{
				Path:    filepath.ToSlash(p),
				Status:  "modified",
				Content: string(data),
			})
			return nil
		})
		if err != nil {
			fmt.Fprintf(stderr, "walk %s: %v\n", t, err)
			return protocol.ExitError
		}
	}

	out := golang.Run(protocol.Input{
		Protocol: protocol.Version,
		Run:      protocol.RunInfo{Root: ".", Scope: "standalone", Mode: "review"},
		Files:    files,
	})

	if err := protocol.RenderOutput(stdout, out, format); err != nil {
		fmt.Fprintf(stderr, "render output: %v\n", err)
		return protocol.ExitError
	}

	if len(out.Findings) > 0 {
		return protocol.ExitFindings
	}
	return protocol.ExitClean
}
