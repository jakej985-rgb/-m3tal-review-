package review

import (
	"testing"
)

func TestScrollFocusRule_DetectsMissingEnsureVisible(t *testing.T) {
	source := `
class _GtkSidebarRowState extends State<_GtkSidebarRow> {
  @override
  Widget build(BuildContext context) {
    return FocusableActionDetector(
      onFocusChange: (focused) {
        if (_isFocused != focused) {
          setState(() => _isFocused = focused);
        }
      },
      child: Container(),
    );
  }
}
`
	diff := goDiff("lib/presentation/shared/widgets/gtk_sidebar.dart", source)
	rule := ScrollFocusRule{}
	findings := rule.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for missing Scrollable.ensureVisible, got %d", len(findings))
	}

	f := findings[0]
	if f.Rule != "flutter-scroll-focus-visibility" {
		t.Errorf("expected rule flutter-scroll-focus-visibility, got %s", f.Rule)
	}
	if f.Severity != "medium" {
		t.Errorf("expected severity medium, got %s", f.Severity)
	}
}

func TestScrollFocusRule_AllowsEnsureVisible(t *testing.T) {
	source := `
class _GtkSidebarRowState extends State<_GtkSidebarRow> {
  @override
  Widget build(BuildContext context) {
    return FocusableActionDetector(
      onFocusChange: (focused) {
        if (_isFocused != focused) {
          setState(() => _isFocused = focused);
        }
        if (focused) {
          Scrollable.ensureVisible(
            context,
            alignmentPolicy: ScrollPositionAlignmentPolicy.keepVisibleAtStart,
          );
        }
      },
      child: Container(),
    );
  }
}
`
	diff := goDiff("lib/presentation/shared/widgets/gtk_sidebar.dart", source)
	rule := ScrollFocusRule{}
	findings := rule.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when Scrollable.ensureVisible is present, got %d", len(findings))
	}
}
