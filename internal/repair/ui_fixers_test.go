package repair

import (
	"context"
	"strings"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review"
)

func TestAsyncGapFixer(t *testing.T) {
	orig := `class _MyState extends State<MyScreen> {
  Future<void> _load() async {
    await fetch();
    setState(() {
      _done = true;
    });
  }
}`
	f := review.Finding{
		Rule:    "unmounted-async-gap",
		File:    "lib/screen.dart",
		Line:    4,
		Message: "setState() called across async gap",
	}

	fixer := AsyncGapFixer{}
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	if prop == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(prop.ProposedContent, "if (!mounted) return;") {
		t.Fatalf("expected 'if (!mounted) return;' in proposed, got:\n%s", prop.ProposedContent)
	}
}

func TestStaleStateFixer(t *testing.T) {
	orig := `class _MyState extends State<MyScreen> {
  @override
  void didUpdateWidget(covariant MyScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.id != widget.id) {
      _future = load(widget.id);
    }
  }
}`
	f := review.Finding{
		Rule:    "stale-state-invalidation",
		File:    "lib/screen.dart",
		Line:    3,
		Message: "didUpdateWidget updates resource on id change but does not reset cursor _currentStepIndex",
	}

	fixer := StaleStateFixer{}
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	if prop == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(prop.ProposedContent, "_currentStepIndex = 0;") {
		t.Fatalf("expected '_currentStepIndex = 0;' in proposed, got:\n%s", prop.ProposedContent)
	}
}

func TestResourceLeakFixer(t *testing.T) {
	orig := `class _MyState extends State<MyScreen> {
  final ScrollController _scrollController = ScrollController();

  @override
  void dispose() {
    super.dispose();
  }
}`
	f := review.Finding{
		Rule:    "resource-leak-disposable",
		File:    "lib/screen.dart",
		Line:    2,
		Message: "Disposable resource '_scrollController' (ScrollController) allocated in State but not cleaned up in dispose()",
	}

	fixer := ResourceLeakFixer{}
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	if prop == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(prop.ProposedContent, "_scrollController.dispose();") {
		t.Fatalf("expected '_scrollController.dispose();' in proposed, got:\n%s", prop.ProposedContent)
	}
}

func TestTouchTargetFixer(t *testing.T) {
	orig := `Widget build(BuildContext context) {
  return TextButton(
    style: TextButton.styleFrom(
      minimumSize: Size.zero,
      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
    ),
    child: Text('Hi'),
  );
}`
	f := review.Finding{
		Rule:    "touch-target-size",
		File:    "lib/button.dart",
		Line:    2,
		Message: "Interactive button explicitly shrinks hit target via shrinkWrap",
	}

	fixer := TouchTargetFixer{}
	prop, err := fixer.GenerateProposal(context.Background(), "", f, []byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	if prop == nil {
		t.Fatal("expected proposal, got nil")
	}

	if !strings.Contains(prop.ProposedContent, "MaterialTapTargetSize.padded") || !strings.Contains(prop.ProposedContent, "const Size(48, 48)") {
		t.Fatalf("expected padded and 48x48 in proposed, got:\n%s", prop.ProposedContent)
	}
}
