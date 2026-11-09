package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jakej985-rgb/m3tal-review/internal/git"
	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func runSuppressionsCommand(args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get working directory: %w", err)
	}

	repositoryRoot, err := git.RepositoryRoot(workingDir)
	if err != nil {
		return err
	}

	subcommand := "audit"
	var subArgs []string

	if len(args) > 0 {
		if args[0] == "audit" || args[0] == "record" || args[0] == "prune" {
			subcommand = args[0]
			subArgs = args[1:]
		} else if strings.HasPrefix(args[0], "-") {
			subcommand = "audit"
			subArgs = args
		} else {
			return fmt.Errorf("unknown suppression subcommand %q; expected audit or record", args[0])
		}
	}

	auditPath := filepath.Join(repositoryRoot, ".m3tal-review", "suppressions", "audit.jsonl")

	switch subcommand {
	case "audit":
		return runSuppressionAudit(auditPath, subArgs)
	case "record":
		return runSuppressionRecord(auditPath, subArgs)
	case "prune":
		return runSuppressionPrune(auditPath, subArgs)
	default:
		return fmt.Errorf("unknown subcommand %q", subcommand)
	}
}

func runSuppressionAudit(auditPath string, args []string) error {
	format := "text"
	actorFilter := ""
	ruleFilter := ""
	fileFilter := ""
	actionFilter := ""
	verifyTrail := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--format":
			if i+1 >= len(args) {
				return fmt.Errorf("option --format requires a value (json|text)")
			}
			i++
			format = args[i]
		case "--format=json":
			format = "json"
		case "--format=text":
			format = "text"
		case "--actor":
			if i+1 >= len(args) {
				return fmt.Errorf("option --actor requires a value")
			}
			i++
			actorFilter = args[i]
		case "--rule":
			if i+1 >= len(args) {
				return fmt.Errorf("option --rule requires a value")
			}
			i++
			ruleFilter = args[i]
		case "--file":
			if i+1 >= len(args) {
				return fmt.Errorf("option --file requires a value")
			}
			i++
			fileFilter = args[i]
		case "--action":
			if i+1 >= len(args) {
				return fmt.Errorf("option --action requires a value (add|edit|expire|remove)")
			}
			i++
			actionFilter = args[i]
		case "--verify":
			verifyTrail = true
		case "-h", "--help":
			fmt.Println("Usage: m3tal-review suppressions audit [--actor <name>] [--rule <rule>] [--file <path>] [--action <action>] [--verify] [--format json|text]")
			fmt.Println("Inspect and audit past suppression events with tamper-evident verification.")
			return nil
		default:
			return fmt.Errorf("unknown suppression audit option %q", arg)
		}
	}

	events, err := review.ReadSuppressionAudit(auditPath)
	if err != nil {
		return err
	}

	var tamperErrors []review.TamperError
	if verifyTrail {
		tamperErrors = review.VerifySuppressionAuditTrail(events)
	}

	// Filter events
	var filtered []review.SuppressionEvent
	for _, ev := range events {
		if actorFilter != "" && ev.Actor != actorFilter {
			continue
		}
		if ruleFilter != "" && ev.Rule != ruleFilter {
			continue
		}
		if fileFilter != "" && !strings.Contains(ev.File, fileFilter) {
			continue
		}
		if actionFilter != "" && string(ev.Action) != actionFilter {
			continue
		}
		filtered = append(filtered, ev)
	}

	type auditResponse struct {
		TotalEvents    int                       `json:"total_events"`
		FilteredEvents int                       `json:"filtered_events"`
		Verified       bool                      `json:"verified"`
		TamperErrors   []review.TamperError      `json:"tamper_errors,omitempty"`
		Events         []review.SuppressionEvent `json:"events"`
	}

	resp := auditResponse{
		TotalEvents:    len(events),
		FilteredEvents: len(filtered),
		Verified:       verifyTrail && len(tamperErrors) == 0,
		TamperErrors:   tamperErrors,
		Events:         filtered,
	}

	if format == "json" {
		data, err := json.MarshalIndent(resp, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal audit json: %w", err)
		}
		fmt.Println(string(data))
		if len(tamperErrors) > 0 {
			return fmt.Errorf("suppression audit tamper check failed: %d errors", len(tamperErrors))
		}
		return nil
	}

	fmt.Printf("Suppression Audit Trail (%d events", len(events))
	if verifyTrail {
		if len(tamperErrors) == 0 {
			fmt.Print(", integrity: VERIFIED")
		} else {
			fmt.Print(", integrity: TAMPER DETECTED")
		}
	}
	fmt.Println("):")

	if len(tamperErrors) > 0 {
		fmt.Println("\nTamper errors detected:")
		for _, te := range tamperErrors {
			fmt.Printf("  ! Line %d (event %s): %s\n", te.Line, te.EventID, te.Message)
		}
	}

	if len(filtered) == 0 {
		fmt.Println("  (No suppression events match filter)")
		if len(tamperErrors) > 0 {
			return fmt.Errorf("suppression audit tamper check failed")
		}
		return nil
	}

	for _, ev := range filtered {
		loc := ev.File
		if ev.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, ev.Line)
		}
		expiresText := ""
		if ev.ExpiresAt != nil && !ev.ExpiresAt.IsZero() {
			expiresText = fmt.Sprintf(" [expires %s]", ev.ExpiresAt.Format("2006-01-02"))
		}
		fmt.Printf("  [%s] %s | %s | %s by %s%s\n",
			displayText(string(ev.Action)),
			ev.Timestamp.Format("2006-01-02 15:04:05"),
			displayText(ev.Rule),
			displayText(loc),
			displayText(ev.Actor),
			expiresText,
		)
		if ev.Reason != "" {
			fmt.Printf("    Reason: %s\n", displayText(ev.Reason))
		}
	}

	if len(tamperErrors) > 0 {
		return fmt.Errorf("suppression audit tamper check failed: %d error(s)", len(tamperErrors))
	}

	return nil
}

func runSuppressionRecord(auditPath string, args []string) error {
	var ev review.SuppressionEvent
	var expiresInStr string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "--action":
			if i+1 >= len(args) {
				return fmt.Errorf("option --action requires a value")
			}
			i++
			ev.Action = review.SuppressionAction(args[i])
		case "--rule":
			if i+1 >= len(args) {
				return fmt.Errorf("option --rule requires a value")
			}
			i++
			ev.Rule = args[i]
		case "--file":
			if i+1 >= len(args) {
				return fmt.Errorf("option --file requires a value")
			}
			i++
			ev.File = args[i]
		case "--line":
			if i+1 >= len(args) {
				return fmt.Errorf("option --line requires a value")
			}
			i++
			l, err := strconv.Atoi(args[i])
			if err != nil || l < 0 {
				return fmt.Errorf("invalid line %q", args[i])
			}
			ev.Line = l
		case "--reason":
			if i+1 >= len(args) {
				return fmt.Errorf("option --reason requires a value")
			}
			i++
			ev.Reason = args[i]
		case "--actor":
			if i+1 >= len(args) {
				return fmt.Errorf("option --actor requires a value")
			}
			i++
			ev.Actor = args[i]
		case "--suppression-id":
			if i+1 >= len(args) {
				return fmt.Errorf("option --suppression-id requires a value")
			}
			i++
			ev.SuppressionID = args[i]
		case "--expires-in":
			if i+1 >= len(args) {
				return fmt.Errorf("option --expires-in requires a value (e.g. 30d, 72h)")
			}
			i++
			expiresInStr = args[i]
		default:
			return fmt.Errorf("unknown record option %q", arg)
		}
	}

	if ev.Action == "" {
		ev.Action = review.ActionAdd
	}
	if ev.Rule == "" {
		return fmt.Errorf("option --rule is required")
	}
	if ev.File == "" {
		return fmt.Errorf("option --file is required")
	}

	if expiresInStr != "" {
		d, err := review.ParseRetentionDuration(expiresInStr)
		if err != nil {
			return err
		}
		t := time.Now().UTC().Add(d)
		ev.ExpiresAt = &t
	}

	saved, err := review.AppendSuppressionEvent(auditPath, ev)
	if err != nil {
		return fmt.Errorf("record suppression: %w", err)
	}

	fmt.Printf("Recorded suppression event %s (%s, %s)\n", saved.EventID, saved.Action, saved.Rule)
	return nil
}

func runSuppressionPrune(auditPath string, args []string) error {
	retainCount := 100
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err != nil || n < 0 {
			return fmt.Errorf("invalid retain count %q", args[0])
		}
		retainCount = n
	}

	pruned, err := review.PruneSuppressionAudit(auditPath, retainCount)
	if err != nil {
		return err
	}
	fmt.Printf("Pruned %d suppression events (retained %d)\n", pruned, retainCount)
	return nil
}
