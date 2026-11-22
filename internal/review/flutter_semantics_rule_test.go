package review

import (
	"testing"
)

func TestFlutterSemanticsRule_CatchesInoperableScreenReaderButton(t *testing.T) {
	source := `
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
        child: FocusableActionDetector(
          child: GestureDetector(
            onTap: widget.onTap,
            child: Container(
              child: Text(widget.label),
            ),
          ),
        ),
      ),
    );
  }
}
`
	diff := goDiff("lib/presentation/shared/widgets/gtk_sidebar.dart", source)
	rule := FlutterSemanticsRule{}
	findings := rule.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for inoperable semantics button, got %d", len(findings))
	}

	f := findings[0]
	if f.Rule != "flutter-semantics-action" {
		t.Errorf("expected rule flutter-semantics-action, got %s", f.Rule)
	}
	if f.Severity != "high" {
		t.Errorf("expected severity high, got %s", f.Severity)
	}
	if f.Category != "quality" {
		t.Errorf("expected category quality, got %s", f.Category)
	}
}

func TestFlutterSemanticsRule_AllowsCompliantSemanticsWithOnTap(t *testing.T) {
	source := `
class _GtkSidebarRowState extends State<_GtkSidebarRow> {
  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      selected: widget.isSelected,
      focused: _isFocused,
      label: widget.label,
      excludeSemantics: true,
      onTap: widget.onTap,
      child: Tooltip(
        message: widget.label,
        child: FocusableActionDetector(
          child: GestureDetector(
            onTap: widget.onTap,
            child: Container(
              child: Text(widget.label),
            ),
          ),
        ),
      ),
    );
  }
}
`
	diff := goDiff("lib/presentation/shared/widgets/gtk_sidebar.dart", source)
	rule := FlutterSemanticsRule{}
	findings := rule.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for compliant semantics button, got %d: %+v", len(findings), findings)
	}
}

func TestFlutterSemanticsRule_IgnoresNonButtonSemantics(t *testing.T) {
	source := `
Widget build(BuildContext context) {
  return Semantics(
    header: true,
    label: "Section Header",
    child: Text("Header"),
  );
}
`
	diff := goDiff("lib/widgets/header.dart", source)
	rule := FlutterSemanticsRule{}
	findings := rule.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for header semantics, got %d", len(findings))
	}
}
