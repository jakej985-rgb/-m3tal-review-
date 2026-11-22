package repair

import (
	"context"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestSemanticsActionFixer_InjectsOnTap(t *testing.T) {
	orig := `
class _GtkSidebarRowState extends State<_GtkSidebarRow> {
  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      selected: widget.isSelected,
      focused: _isFocused,
      label: widget.label,
      excludeSemantics: true,
      child: Tooltip(
        message: widget.label,
        child: GestureDetector(
          onTap: widget.onTap,
          child: Text(widget.label),
        ),
      ),
    );
  }
}
`
	finding := review.Finding{
		File: "lib/presentation/shared/widgets/gtk_sidebar.dart",
		Line: 11,
		Rule: "flutter-semantics-action",
	}

	fixer := SemanticsActionFixer{}
	if !fixer.CanFix(finding) {
		t.Fatalf("expected CanFix to be true")
	}

	proposal, err := fixer.GenerateProposal(context.Background(), "", finding, []byte(orig))
	if err != nil {
		t.Fatalf("GenerateProposal failed: %v", err)
	}

	patched := proposal.ProposedContent
	if !strings.Contains(patched, "excludeSemantics: true,\n      onTap: widget.onTap,") {
		t.Fatalf("expected patched code to have excludeSemantics and onTap: widget.onTap, got:\n%s", patched)
	}
}
