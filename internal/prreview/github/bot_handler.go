package github

import (
	"context"
	"fmt"
	"strings"

	"github.com/jakej985-rgb/m3tal-review/internal/prreview"
)

// BotCommandKind represents the parsed command from a PR comment.
type BotCommandKind string

const (
	CommandReview  BotCommandKind = "review"
	CommandResolve BotCommandKind = "resolve"
	CommandExplain BotCommandKind = "explain"
	CommandHelp    BotCommandKind = "help"
	CommandUnknown BotCommandKind = "unknown"
)

// BotCommand holds parsed command details.
type BotCommand struct {
	Kind     BotCommandKind
	Argument string
}

// ParseBotComment checks if a comment mentions @m3tal-review and extracts the command.
func ParseBotComment(commentBody string) *BotCommand {
	trimmed := strings.TrimSpace(commentBody)
	lower := strings.ToLower(trimmed)

	prefix := "@m3tal-review"
	idx := strings.Index(lower, prefix)
	if idx == -1 {
		return nil
	}

	after := strings.TrimSpace(trimmed[idx+len(prefix):])
	parts := strings.Fields(after)
	if len(parts) == 0 {
		return &BotCommand{Kind: CommandReview}
	}

	switch strings.ToLower(parts[0]) {
	case "review", "re-review", "scan":
		return &BotCommand{Kind: CommandReview}
	case "resolve", "ack":
		return &BotCommand{Kind: CommandResolve}
	case "explain":
		arg := ""
		if len(parts) > 1 {
			arg = parts[1]
		}
		return &BotCommand{Kind: CommandExplain, Argument: arg}
	case "help":
		return &BotCommand{Kind: CommandHelp}
	default:
		return &BotCommand{Kind: CommandUnknown, Argument: parts[0]}
	}
}

// FormatExplainResponse returns a deterministic explanation for a given rule.
func FormatExplainResponse(ruleID string) string {
	rule := prreview.LookupRule(ruleID)
	if rule == nil {
		return fmt.Sprintf("⚠️ Rule `%s` is not recognized. Run `@m3tal-review help` or `m3tal-review list-rules` for available rules.", ruleID)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "### 📖 Rule Explanation: `%s`\n\n", rule.Name)
	fmt.Fprintf(&b, "- **Category:** `%s`\n", rule.Category)
	fmt.Fprintf(&b, "- **Severity:** `%s`\n", strings.ToUpper(rule.Severity))
	fmt.Fprintf(&b, "- **Description:** %s\n\n", rule.Description)

	if rule.Rationale != "" {
		fmt.Fprintf(&b, "> **Deterministic Rationale:**\n> %s\n\n", rule.Rationale)
	}
	if rule.Remediation != "" {
		fmt.Fprintf(&b, "**Remediation Guidance:**\n```\n%s\n```\n\n", rule.Remediation)
	}
	b.WriteString("<sub>Pure deterministic rule explanation — no AI models invoked.</sub>\n")
	return b.String()
}

// FormatHelpResponse returns guidance on available bot comment commands.
func FormatHelpResponse() string {
	return `### 🛡️ m3tal-review Bot Commands

You can interact with m3tal-review by mentioning **@m3tal-review** in PR comments:

- **` + "`@m3tal-review review`" + `** — Re-runs the full review on the latest commit and updates the summary.
- **` + "`@m3tal-review explain <rule>`" + `** — Explains a specific rule with rationale and remediation examples.
- **` + "`@m3tal-review resolve`" + `** — Acknowledges review status and marks threads resolved.
- **` + "`@m3tal-review help`" + `** — Displays this command help message.

<sub>Powered by m3tal-review deterministic offline engine.</sub>`
}

// HandleBotComment processes the parsed command and executes corresponding GitHub actions.
func HandleBotComment(ctx context.Context, client Client, owner, repo string, prNumber int, cmd *BotCommand) error {
	switch cmd.Kind {
	case CommandHelp:
		return client.CreateComment(ctx, owner, repo, prNumber, FormatHelpResponse())
	case CommandExplain:
		resp := FormatExplainResponse(cmd.Argument)
		return client.CreateComment(ctx, owner, repo, prNumber, resp)
	case CommandResolve:
		msg := "✅ **Findings Acknowledged:** Review threads acknowledged. Ensure any critical or high findings are addressed prior to merge."
		return client.CreateComment(ctx, owner, repo, prNumber, msg)
	case CommandReview:
		// Re-review is triggered by caller running the analysis pipeline
		return nil
	default:
		msg := fmt.Sprintf("Unknown command `%s`. Type `@m3tal-review help` for available commands.", cmd.Argument)
		return client.CreateComment(ctx, owner, repo, prNumber, msg)
	}
}
