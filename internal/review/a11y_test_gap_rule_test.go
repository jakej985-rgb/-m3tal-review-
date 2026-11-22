package review

import (
	"testing"
)

func TestA11yTestGapRule_DetectsShallowTooltipCount(t *testing.T) {
	source := `
void main() {
  testWidgets('GtkSidebar rows show tooltips and semantics', (tester) async {
    await tester.pumpWidget(MaterialApp(home: Container()));
    expect(find.byType(FocusableActionDetector), findsAtLeastNWidgets(6));
    expect(find.byType(Tooltip), findsAtLeastNWidgets(6));
  });
}
`
	diff := goDiff("test/widget/adaptive_responsive_desktop_test.dart", source)
	rule := A11yTestGapRule{}
	findings := rule.Check(diff)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for shallow tooltip count, got %d", len(findings))
	}

	f := findings[0]
	if f.Rule != "test-a11y-action-gap" {
		t.Errorf("expected rule test-a11y-action-gap, got %s", f.Rule)
	}
	if f.Severity != "low" {
		t.Errorf("expected severity low, got %s", f.Severity)
	}
}

func TestA11yTestGapRule_AllowsExercisedSemanticsAndTooltip(t *testing.T) {
	source := `
void main() {
  testWidgets('GtkSidebar rows show tooltips and semantics', (tester) async {
    await tester.pumpWidget(MaterialApp(home: Container()));
    expect(find.byType(Tooltip), findsAtLeastNWidgets(6));
    expect(tester.getSemantics(find.text("Learn")), matchesSemantics(isButton: true));
    final gesture = await tester.createGesture(kind: PointerDeviceKind.mouse);
  });
}
`
	diff := goDiff("test/widget/adaptive_responsive_desktop_test.dart", source)
	rule := A11yTestGapRule{}
	findings := rule.Check(diff)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when semantics and tooltip are exercised, got %d", len(findings))
	}
}
