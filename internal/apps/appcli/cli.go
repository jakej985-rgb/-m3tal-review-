package appcli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/protocol"
)

// App defines the minimal interface implemented by every Go-based language review app.
type App interface {
	Describe() protocol.DescribeResult
	Run(protocol.Input) protocol.Output
}

// Main runs the standard CLI loop (--describe, standalone targets, or stdin JSON) for an App.
func Main(name string, app App, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	describe := fs.Bool("describe", false, "Print app capabilities and exit")
	format := fs.String("format", "json", "Output format for standalone mode: json|text|sarif|github")
	if err := fs.Parse(args); err != nil {
		return protocol.ExitError
	}

	desc := app.Describe()
	if *describe {
		if err := json.NewEncoder(stdout).Encode(desc); err != nil {
			fmt.Fprintf(stderr, "encode describe: %v\n", err)
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
		return runStandalone(app, desc, rest, *format, stdout, stderr)
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

	out := app.Run(in)
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintf(stderr, "encode output: %v\n", err)
		return protocol.ExitError
	}
	if len(out.Findings) > 0 {
		return protocol.ExitFindings
	}
	return protocol.ExitClean
}

func runStandalone(app App, desc protocol.DescribeResult, targets []string, format string, stdout, stderr io.Writer) int {
	extSet := make(map[string]bool, len(desc.Extensions))
	for _, e := range desc.Extensions {
		extSet[strings.ToLower(e)] = true
	}

	var files []protocol.File
	for _, t := range targets {
		clean := strings.TrimSuffix(t, "/...")
		if clean == "" {
			clean = "."
		}
		err := filepath.WalkDir(clean, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", "vendor", "node_modules", "__pycache__", "target", "dist":
					return filepath.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(p))
			if !extSet[ext] && !matchesAny(filepath.ToSlash(p), desc.FilePatterns) {
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

	out := app.Run(protocol.Input{
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

func matchesAny(p string, patterns []string) bool {
	base := filepath.Base(p)
	for _, pat := range patterns {
		if ok, _ := filepath.Match(pat, p); ok {
			return true
		}
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
	}
	return false
}
