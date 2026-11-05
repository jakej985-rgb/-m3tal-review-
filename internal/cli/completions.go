package cli

import "fmt"

// commandCompletions prints a shell completion script.
func commandCompletions(shell string) error {
	const rules = "code-slop todo-marker debug-leftover review-risk review-policy insecure-tls-verification risky-shell-execution world-writable-file-mode hardcoded-credential exposed-secret path-traversal weak-cryptography unsafe-deserialization dangerous-eval cross-site-scripting sql-injection ssrf command-injection open-redirect template-injection prototype-pollution archive-extraction xxe injection-other unsafe-code secret-file jwt-misuse hardcoded-session-secret tls-verification weak-crypto-params timing-unsafe-compare insecure-randomness insecure-permissions cors-misconfig cookie-flags web-storage-secrets postmessage-origin xss-extra-sinks unpinned-action pull-request-target actions-script-injection pipe-to-shell unpinned-image ci-secret-exposure container-privilege dockerfile-remote-add dockerfile-user deserialization-gadgets secret-material weak-encoding-crypto server-timeouts websocket-origin js-common-mistakes dynamic-code-loading log-injection nosql-injection graphql-injection email-header-injection unbounded-read client-timeouts rust-unsafe missing-timeout env-passthrough"
	commands := "check review audit history lint recover-history list-rules explain install-hook stdin diff doctor completions watch version help"
	switch shell {
	case "bash":
		fmt.Printf(`# m3tal-review bash completion
_m3tal_review() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  case "${COMP_WORDS[1]}" in
    review|audit)
      COMPREPLY=($(compgen -W "--profile --with-tools --only --skip --fail-on --base --baseline --write-baseline --include --exclude --sort-by --summary-only --max-findings --max-diff-size --rule --format --include-ignored --max-files --max-bytes" -- "$cur"))
      ;;
    explain)
      COMPREPLY=($(compgen -W "%s" -- "$cur"))
      ;;
    completions)
      COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"))
      ;;
    *)
      COMPREPLY=($(compgen -W "%s" -- "$cur"))
      ;;
  esac
}
complete -F _m3tal_review m3tal-review
`, rules, commands)
	case "zsh":
		fmt.Printf(`#compdef m3tal-review
_m3tal_review() {
  local -a opts
  opts=(%s)
  _arguments '*: :->args' && return
}
_m3tal_review "$@"
`, commands)
	case "fish":
		fmt.Printf(`complete -c m3tal-review -f
for c in %s; complete -c m3tal-review -n "__fish_use_subcommand" -a $c; end
for f in --profile --with-tools --only --skip --fail-on --base --baseline --write-baseline --include --exclude --sort-by --summary-only --max-findings --max-diff-size --rule --format --include-ignored --max-files --max-bytes; complete -c m3tal-review -l (string replace -r '^--' '' $f); end
`, commands)
	default:
		return fmt.Errorf("unsupported shell %q; expected bash, zsh, or fish", shell)
	}
	return nil
}
