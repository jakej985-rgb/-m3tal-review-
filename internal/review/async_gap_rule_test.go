package review

import (
	"strings"
	"testing"
)

func TestAsyncGapRuleDetectsUnguardedSetState(t *testing.T) {
	diff := `diff --git a/lib/presentation/fetch_screen.dart b/lib/presentation/fetch_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/fetch_screen.dart
@@ -0,0 +1,15 @@
+class _FetchScreenState extends State<FetchScreen> {
+  bool _loading = false;
+
+  Future<void> _loadData() async {
+    await api.fetchData();
+    setState(() {
+      _loading = false;
+    });
+  }
+
+  @override
+  Widget build(BuildContext context) => Container();
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unguarded setState, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if f.Rule != "unmounted-async-gap" {
		t.Errorf("expected rule unmounted-async-gap, got %s", f.Rule)
	}
	if !strings.Contains(f.Message, "setState()") {
		t.Errorf("expected setState() in message, got %s", f.Message)
	}
	if !strings.Contains(f.Message, "without checking if (!mounted)") {
		t.Errorf("expected mounted check in message, got %s", f.Message)
	}
}

func TestAsyncGapRuleDetectsUnguardedContextUse(t *testing.T) {
	diff := `diff --git a/lib/presentation/nav_screen.dart b/lib/presentation/nav_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nav_screen.dart
@@ -0,0 +1,12 @@
+class _NavScreenState extends State<NavScreen> {
+  Future<void> _handleSave() async {
+    await api.save();
+    Navigator.of(context).pop();
+  }
+
+  @override
+  Widget build(BuildContext context) => Container();
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unguarded Navigator.of, got %d: %+v", len(findings), findings)
	}

	f := findings[0]
	if !strings.Contains(f.Message, "Navigator.of") {
		t.Errorf("expected Navigator.of in message, got %s", f.Message)
	}
}

func TestAsyncGapRuleAllowsGuardedAsync(t *testing.T) {
	diff := `diff --git a/lib/presentation/safe_screen.dart b/lib/presentation/safe_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/safe_screen.dart
@@ -0,0 +1,24 @@
+class _SafeScreenState extends State<SafeScreen> {
+  bool _loading = false;
+
+  Future<void> _loadData() async {
+    await api.fetchData();
+    if (!mounted) return;
+    setState(() {
+      _loading = false;
+    });
+  }
+
+  Future<void> _saveData() async {
+    await api.save();
+    if (context.mounted) {
+      Navigator.of(context).pop();
+    }
+  }
+
+  @override
+  Widget build(BuildContext context) => Container();
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when mounted guards are present, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleAllowsMultiLineAwaitWithInnerCallbacks(t *testing.T) {
	diff := `diff --git a/lib/presentation/dialog_screen.dart b/lib/presentation/dialog_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/dialog_screen.dart
@@ -0,0 +1,22 @@
+class _DialogScreenState extends State<DialogScreen> {
+  Future<void> _showConfirmation(BuildContext context) async {
+    final confirmed = await showDialog<bool>(
+      context: context,
+      builder: (dialogCtx) => Dialog(
+        child: TextButton(
+          onPressed: () => Navigator.of(dialogCtx).pop(true),
+          child: Text('OK'),
+        ),
+      ),
+    );
+    if (confirmed != true || !context.mounted) return;
+    Navigator.of(context).pop();
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for multi-line await with inner callbacks, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleDetectsSetStateInInitStateAndDispose(t *testing.T) {
	diff := `diff --git a/lib/presentation/screen.dart b/lib/presentation/screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/screen.dart
@@ -0,0 +1,18 @@
+class _ScreenState extends State<Screen> {
+  @override
+  void initState() {
+    super.initState();
+    setState(() {
+      _loaded = true;
+    });
+  }
+
+  @override
+  void dispose() {
+    setState(() {
+      _active = false;
+    });
+    super.dispose();
+  }
+}
+`
	rule := LifecycleSetStateRule{}
	findings := rule.Check(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for setState in initState and dispose, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Rule != "invalid-lifecycle-setstate" {
			t.Errorf("expected rule invalid-lifecycle-setstate, got %s", f.Rule)
		}
	}
}

func TestAsyncGapRuleDoesNotAcceptUnguardedIfUnmounted(t *testing.T) {
	diff := `diff --git a/lib/presentation/broken_guard.dart b/lib/presentation/broken_guard.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/broken_guard.dart
@@ -0,0 +1,17 @@
+class _BrokenGuardState extends State<BrokenGuard> {
+  Future<void> _fetch() async {
+    await api.fetch();
+    if (!mounted) {
+      print('unmounted');
+      // Missing return statement!
+    }
+    setState(() {});
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding because if (!mounted) without return is NOT a guard, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "setState()") {
		t.Errorf("expected setState() in message, got %s", findings[0].Message)
	}
}

func TestAsyncGapRuleAllowsMultiLineIfUnmountedReturn(t *testing.T) {
	diff := `diff --git a/lib/presentation/multiline_guard.dart b/lib/presentation/multiline_guard.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/multiline_guard.dart
@@ -0,0 +1,18 @@
+class _MultiLineGuardState extends State<MultiLineGuard> {
+  Future<void> _fetch() async {
+    await api.fetch();
+    if (!mounted) {
+      return;
+    }
+    setState(() {});
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for multi-line if (!mounted) return, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleDetectsProviderAndBlocAcrossAsyncGap(t *testing.T) {
	diff := `diff --git a/lib/presentation/state_mgmt_screen.dart b/lib/presentation/state_mgmt_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/state_mgmt_screen.dart
@@ -0,0 +1,18 @@
+class _StateMgmtState extends State<StateMgmtScreen> {
+  Future<void> _update() async {
+    await api.syncUser();
+    context.read<UserCubit>().refresh();
+  }
+
+  Future<void> _dispatch() async {
+    await api.syncUser();
+    BlocProvider.of<AuthBloc>(context).add(Logout());
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for context.read and BlocProvider.of, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleDetectsRiverpodRefAcrossAsyncGap(t *testing.T) {
	diff := `diff --git a/lib/presentation/riverpod_screen.dart b/lib/presentation/riverpod_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/riverpod_screen.dart
@@ -0,0 +1,13 @@
+class _RiverpodScreenState extends ConsumerState<RiverpodScreen> {
+  Future<void> _sync() async {
+    await api.sync();
+    ref.read(syncStatusProvider.notifier).complete();
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ref.read across async gap, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleDetectsShowDialogAcrossAsyncGap(t *testing.T) {
	diff := `diff --git a/lib/presentation/dialog_screen.dart b/lib/presentation/dialog_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/dialog_screen.dart
@@ -0,0 +1,18 @@
+class _DialogScreenState extends State<DialogScreen> {
+  Future<void> _prompt() async {
+    await api.checkStatus();
+    showDialog(
+      context: context,
+      builder: (_) => Container(),
+    );
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for showDialog across async gap, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleDetectsControllerMutationAcrossAsyncGap(t *testing.T) {
	diff := `diff --git a/lib/presentation/animation_screen.dart b/lib/presentation/animation_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/animation_screen.dart
@@ -0,0 +1,18 @@
+class _AnimationScreenState extends State<AnimationScreen> {
+  Future<void> _animate() async {
+    await api.loadNext();
+    _animationController.forward();
+  }
+
+  Future<void> _scroll() async {
+    await api.loadNext();
+    _scrollController.animateTo(0);
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for controller mutations across async gap, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRuleDetectsDeactivatedContextInDispose(t *testing.T) {
	diff := `diff --git a/lib/presentation/dispose_screen.dart b/lib/presentation/dispose_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/dispose_screen.dart
@@ -0,0 +1,14 @@
+class _DisposeScreenState extends State<DisposeScreen> {
+  @override
+  void dispose() {
+    Theme.of(context);
+    context.read<UserCubit>().reset();
+    super.dispose();
+  }
+}
+`
	rule := DeactivatedContextRule{}
	findings := rule.Check(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for deactivated context lookups in dispose, got %d: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f.Rule != "deactivated-context-lifecycle" {
			t.Errorf("expected rule deactivated-context-lifecycle, got %s", f.Rule)
		}
	}
}

func TestAsyncGapRuleDetectsWatchOutsideBuild(t *testing.T) {
	diff := `diff --git a/lib/presentation/watch_screen.dart b/lib/presentation/watch_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/watch_screen.dart
@@ -0,0 +1,18 @@
+class _WatchScreenState extends State<WatchScreen> {
+  void _handleTap() {
+    final data = context.watch<UserData>();
+    print(data);
+  }
+
+  @override
+  Widget build(BuildContext context) {
+    final data = context.watch<UserData>();
+    return Container();
+  }
+}
+`
	rule := WatchOutsideBuildRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for context.watch outside build, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "watch-outside-build" {
		t.Errorf("expected rule watch-outside-build, got %s", findings[0].Rule)
	}
}

func TestAsyncGapRule_PositiveBranchDoesNotHideFollowingUnguardedCalls(t *testing.T) {
	diff := `diff --git a/lib/presentation/branch_screen.dart b/lib/presentation/branch_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/branch_screen.dart
@@ -0,0 +1,16 @@
+class _BranchScreenState extends State<BranchScreen> {
+  Future<void> _save() async {
+    await api.save();
+    if (mounted) {
+      setState(() {});
+    }
+    showDialog(context: context, builder: (_) => Container());
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for showDialog after if (mounted) block, got %d: %+v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "showDialog") {
		t.Errorf("expected showDialog in message, got %s", findings[0].Message)
	}
}

func TestAsyncGapRule_CompoundPositiveGuardAllowed(t *testing.T) {
	diff := `diff --git a/lib/presentation/compound_screen.dart b/lib/presentation/compound_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/compound_screen.dart
@@ -0,0 +1,14 @@
+class _CompoundScreenState extends State<CompoundScreen> {
+  Future<void> _update(bool changed) async {
+    await api.sync();
+    if (mounted && changed) {
+      setState(() {});
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for compound mounted check if (mounted && changed), got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_ConditionalExitInIfUnmountedDoesNotHideCalls(t *testing.T) {
	diff := `diff --git a/lib/presentation/nested_exit.dart b/lib/presentation/nested_exit.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nested_exit.dart
@@ -0,0 +1,17 @@
+class _NestedExitState extends State<NestedExit> {
+  Future<void> _fetch(bool foo) async {
+    await api.fetch();
+    if (!mounted) {
+      if (foo) return;
+    }
+    showDialog(context: context, builder: (_) => Container());
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding because nested return does not guarantee unmounted exit, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_GenericProviderOfInDispose(t *testing.T) {
	diff := `diff --git a/lib/presentation/provider_dispose.dart b/lib/presentation/provider_dispose.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/provider_dispose.dart
@@ -0,0 +1,11 @@
+class _ProviderDisposeState extends State<ProviderDispose> {
+  @override
+  void dispose() {
+    Provider.of<User>(context);
+    super.dispose();
+  }
+}
+`
	rule := DeactivatedContextRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for Provider.of<User>(context) in dispose, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "deactivated-context-lifecycle" {
		t.Errorf("expected deactivated-context-lifecycle, got %s", findings[0].Rule)
	}
}

func TestAsyncGapRule_GenericContextWatchInTapHandler(t *testing.T) {
	diff := `diff --git a/lib/presentation/tap_screen.dart b/lib/presentation/tap_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/tap_screen.dart
@@ -0,0 +1,15 @@
+class _TapScreenState extends State<TapScreen> {
+  @override
+  Widget build(BuildContext context) {
+    return ElevatedButton(
+      onPressed: () {
+        context.watch<List<User>>();
+      },
+      child: Text('Tap'),
+    );
+  }
+}
+`
	rule := WatchOutsideBuildRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for context.watch inside onPressed callback, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "watch-outside-build" {
		t.Errorf("expected watch-outside-build, got %s", findings[0].Rule)
	}
}

func TestAsyncGapRule_ControllerForwardWithoutCapitalController(t *testing.T) {
	diff := `diff --git a/lib/presentation/anim_screen.dart b/lib/presentation/anim_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/anim_screen.dart
@@ -0,0 +1,10 @@
+class _AnimScreenState extends State<AnimScreen> {
+  Future<void> _start() async {
+    await api.prepare();
+    _controller.forward();
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for _controller.forward(), got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_IgnoresVueShowMenu(t *testing.T) {
	diff := `diff --git a/src/components/Menu.vue b/src/components/Menu.vue
new file mode 100644
--- /dev/null
+++ b/src/components/Menu.vue
@@ -0,0 +1,8 @@
+<script setup>
+async function open() {
+  await api.fetch();
+  showMenu();
+}
+</script>
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for non-Dart Vue file, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_RiverpodNotifierBuildMethodAllowed(t *testing.T) {
	diff := `diff --git a/lib/notifier.dart b/lib/notifier.dart
new file mode 100644
--- /dev/null
+++ b/lib/notifier.dart
@@ -0,0 +1,9 @@
+class MyNotifier extends Notifier<String> {
+  @override
+  String build() {
+    final user = ref.watch(userProvider);
+    return user.name;
+  }
+}
+`
	rule := WatchOutsideBuildRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for ref.watch inside Riverpod String build(), got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_DoesNotFlagWatchWhenEnclosingMethodUnknown(t *testing.T) {
	diff := `diff --git a/lib/presentation/partial.dart b/lib/presentation/partial.dart
--- a/lib/presentation/partial.dart
+++ b/lib/presentation/partial.dart
@@ -42,1 +42,2 @@
+    final settings = context.watch<Settings>();
+    return Text(settings.title);
`
	rule := WatchOutsideBuildRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for body-only hunk with unknown enclosing method, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_DisjunctionMountedGuardNotAccepted(t *testing.T) {
	diff := `diff --git a/lib/presentation/disjunction_screen.dart b/lib/presentation/disjunction_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/disjunction_screen.dart
@@ -0,0 +1,14 @@
+class _DisjunctionState extends State<DisjunctionScreen> {
+  Future<void> _update(bool force) async {
+    await api.sync();
+    if (mounted || force) {
+      setState(() {});
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding because disjunction 'mounted || force' cannot guarantee mounted, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_FalseMountedGuardNotAccepted(t *testing.T) {
	diff := `diff --git a/lib/presentation/false_screen.dart b/lib/presentation/false_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/false_screen.dart
@@ -0,0 +1,14 @@
+class _FalseState extends State<FalseScreen> {
+  Future<void> _update() async {
+    await api.sync();
+    if (mounted == false) {
+      setState(() {});
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding because 'mounted == false' indicates unmounted, got %d: %+v", len(findings), findings)
	}
}

func TestWatchOutsideBuild_SingleLineCallbackDoesNotContaminateFollowingCode(t *testing.T) {
	diff := `diff --git a/lib/presentation/single_line_screen.dart b/lib/presentation/single_line_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/single_line_screen.dart
@@ -0,0 +1,17 @@
+class _SingleLineState extends State<SingleLineScreen> {
+  @override
+  Widget build(BuildContext context) {
+    return Column(
+      children: [
+        ElevatedButton(onPressed: () {}, child: Text('OK')),
+        Builder(builder: (context) {
+          final data = context.watch<Data>();
+          return Text(data.title);
+        }),
+      ],
+    );
+  }
+}
+`
	rule := WatchOutsideBuildRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings because single-line callback does not contaminate subsequent lines, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_CompoundPositiveGuardWithNegationAndParens(t *testing.T) {
	diff := `diff --git a/lib/presentation/compound_parens.dart b/lib/presentation/compound_parens.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/compound_parens.dart
@@ -0,0 +1,19 @@
+class _CompoundParensState extends State<CompoundParensScreen> {
+  Future<void> _update(bool busy, bool changed, bool force) async {
+    await api.sync();
+    if (mounted && !busy) {
+      setState(() {});
+    }
+    await api.sync2();
+    if (mounted && (changed || force)) {
+      setState(() {});
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe compound mounted guards, got %d: %+v", len(findings), findings)
	}
}

func TestWatchOutsideBuild_InlineCallbackWithWatch(t *testing.T) {
	diff := `diff --git a/lib/presentation/inline_cb.dart b/lib/presentation/inline_cb.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/inline_cb.dart
@@ -0,0 +1,12 @@
+class _InlineCbState extends State<InlineCbScreen> {
+  @override
+  Widget build(BuildContext context) {
+    return ElevatedButton(
+      onPressed: () { context.watch<Data>(); },
+      child: Text('OK'),
+    );
+  }
+}
+`
	rule := WatchOutsideBuildRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for context.watch inside inline callback, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "watch-outside-build" {
		t.Errorf("expected rule watch-outside-build, got %s", findings[0].Rule)
	}
}

func TestWatchOutsideBuild_WatchAfterNestedCallbackInsideHandler(t *testing.T) {
	diff := `diff --git a/lib/presentation/nested_cb.dart b/lib/presentation/nested_cb.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nested_cb.dart
@@ -0,0 +1,15 @@
+class _NestedCbState extends State<NestedCbScreen> {
+  @override
+  Widget build(BuildContext context) {
+    return ElevatedButton(
+      onPressed: () {
+        nested(() {});
+        context.watch<Data>();
+      },
+      child: Text('OK'),
+    );
+  }
+}
+`
	rule := WatchOutsideBuildRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for context.watch after nested callback inside handler, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_TernaryGuardDoesNotHideUnmountedUpdate(t *testing.T) {
	diff := `diff --git a/lib/presentation/ternary_screen.dart b/lib/presentation/ternary_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/ternary_screen.dart
@@ -0,0 +1,15 @@
+class _TernaryState extends State<TernaryScreen> {
+  Future<void> _update(bool busy, bool ready, bool force) async {
+    await api.sync();
+    if (mounted && !busy ? ready : force) {
+      setState(() {});
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding because ternary guard cannot guarantee mounted, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_ThisMountedGuardAllowed(t *testing.T) {
	diff := `diff --git a/lib/presentation/this_mounted_screen.dart b/lib/presentation/this_mounted_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/this_mounted_screen.dart
@@ -0,0 +1,14 @@
+class _ThisMountedState extends State<ThisMountedScreen> {
+  Future<void> _update() async {
+    await api.sync();
+    if (this.mounted) {
+      setState(() {});
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for safe if (this.mounted), got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_CtxMountedGuardProtectsMatchingContext(t *testing.T) {
	diff := `diff --git a/lib/presentation/ctx_screen.dart b/lib/presentation/ctx_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/ctx_screen.dart
@@ -0,0 +1,17 @@
+class _CtxScreenState extends State<CtxScreen> {
+  Future<void> _update(BuildContext ctx, BuildContext otherCtx) async {
+    await api.sync();
+    if (ctx.mounted) {
+      Navigator.of(ctx).pop();
+    }
+    await api.sync2();
+    if (ctx.mounted) {
+      Navigator.of(otherCtx).pop();
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for Navigator.of(otherCtx) inside if (ctx.mounted), got %d: %+v", len(findings), findings)
	}
	if findings[0].Line != 9 {
		t.Errorf("expected finding on line 9 for otherCtx, got line %d", findings[0].Line)
	}
	if !strings.Contains(findings[0].Snippet, "otherCtx") {
		t.Errorf("expected finding snippet to mention otherCtx, got %q", findings[0].Snippet)
	}
}

func TestAsyncGapRule_EarlyExitCtxDoesNotProtectOtherContext(t *testing.T) {
	diff := `diff --git a/lib/presentation/early_exit.dart b/lib/presentation/early_exit.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/early_exit.dart
@@ -0,0 +1,12 @@
+class _EarlyExitState extends State<EarlyExit> {
+  Future<void> _update(BuildContext ctx, BuildContext otherCtx) async {
+    await api.sync();
+    if (!ctx.mounted) return;
+    Navigator.of(ctx).pop();
+    Navigator.of(otherCtx).pop();
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unproven otherCtx after early return on !ctx.mounted, got %d: %+v", len(findings), findings)
	}
	if findings[0].Line != 6 {
		t.Errorf("expected finding on line 6 for otherCtx, got line %d", findings[0].Line)
	}
	if !strings.Contains(findings[0].Snippet, "otherCtx") {
		t.Errorf("expected snippet to reference otherCtx, got %q", findings[0].Snippet)
	}
}

func TestAsyncGapRule_NestedMountedGuard(t *testing.T) {
	diff := `diff --git a/lib/presentation/nested.dart b/lib/presentation/nested.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nested.dart
@@ -0,0 +1,14 @@
+class _NestedState extends State<Nested> {
+  Future<void> _update(BuildContext ctx) async {
+    await api.sync();
+    if (ctx.mounted) {
+      if (mounted) {
+        setState(() {});
+      }
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for nested mounted guard, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_NullAwareDoesNotTriggerTernary(t *testing.T) {
	diff := `diff --git a/lib/presentation/null_aware.dart b/lib/presentation/null_aware.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/null_aware.dart
@@ -0,0 +1,12 @@
+class _NullAwareState extends State<NullAware> {
+  Future<void> _update(Config? config) async {
+    await api.sync();
+    if (mounted && config?.ready == true) {
+      setState(() {});
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for null-aware condition without ternary, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_NullCoalescingGuardDoesNotHideUnmountedUpdate(t *testing.T) {
	diff := `diff --git a/lib/presentation/coalesce.dart b/lib/presentation/coalesce.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/coalesce.dart
@@ -0,0 +1,12 @@
+class _CoalesceState extends State<Coalesce> {
+  Future<void> _update(bool? overrideReady, bool isReady) async {
+    await api.sync();
+    if (overrideReady ?? isReady && mounted) {
+      setState(() {});
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for unmounted update inside null-coalescing guard, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_StaticNavigatorPopGuarded(t *testing.T) {
	diff := `diff --git a/lib/presentation/nav.dart b/lib/presentation/nav.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nav.dart
@@ -0,0 +1,11 @@
+class _NavState extends State<Nav> {
+  Future<void> _update(BuildContext ctx) async {
+    await api.sync();
+    if (!ctx.mounted) return;
+    Navigator.pop(ctx);
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for Navigator.pop(ctx) guarded by if (!ctx.mounted), got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_StaticNavigatorPopOtherContext(t *testing.T) {
	diff := `diff --git a/lib/presentation/nav_other.dart b/lib/presentation/nav_other.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nav_other.dart
@@ -0,0 +1,11 @@
+class _NavOtherState extends State<NavOther> {
+  Future<void> _update(BuildContext ctx, BuildContext otherCtx) async {
+    await api.sync();
+    if (!ctx.mounted) return;
+    Navigator.pop(otherCtx);
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for Navigator.pop(otherCtx), got %d: %+v", len(findings), findings)
	}
	if findings[0].Line != 5 {
		t.Errorf("expected finding on line 5, got %d", findings[0].Line)
	}
}

func TestAsyncGapRule_NestedGuardConditionWithUnprotectedContext(t *testing.T) {
	diff := `diff --git a/lib/presentation/nested_cond.dart b/lib/presentation/nested_cond.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nested_cond.dart
@@ -0,0 +1,16 @@
+class _NestedCondState extends State<NestedCond> {
+  Future<void> _update(BuildContext ctx, BuildContext otherCtx) async {
+    await api.sync();
+    if (ctx.mounted) {
+      if (mounted && Navigator.of(otherCtx).canPop()) {
+        setState(() {});
+      }
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for Navigator.of(otherCtx) in nested if condition, got %d: %+v", len(findings), findings)
	}
	if findings[0].Line != 5 {
		t.Errorf("expected finding on line 5, got %d", findings[0].Line)
	}
}

func TestAsyncGapRule_NestedGuardConditionWithProtectedContext(t *testing.T) {
	diff := `diff --git a/lib/presentation/nested_safe.dart b/lib/presentation/nested_safe.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nested_safe.dart
@@ -0,0 +1,16 @@
+class _NestedSafeState extends State<NestedSafe> {
+  Future<void> _update(BuildContext ctx) async {
+    await api.sync();
+    if (ctx.mounted) {
+      if (mounted && Navigator.of(ctx).canPop()) {
+        setState(() {});
+      }
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings when nested if condition checks protected ctx, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_RiverpodGuardedRef(t *testing.T) {
	// Guarded by State mounted
	guardedDiff := `diff --git a/lib/presentation/riverpod_screen.dart b/lib/presentation/riverpod_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/riverpod_screen.dart
@@ -0,0 +1,15 @@
+class _RiverpodScreenState extends ConsumerState<RiverpodScreen> {
+  Future<void> _fetch() async {
+    await api.fetch();
+    if (!mounted) return;
+    ref.read(counterProvider.notifier).increment();
+  }
+}
+`
	rule := AsyncGapRule{}
	if findings := rule.Check(guardedDiff); len(findings) != 0 {
		t.Fatalf("expected 0 findings for mounted-guarded ref.read in ConsumerState, got %d: %+v", len(findings), findings)
	}

	// Unguarded ref.read after await
	unguardedDiff := `diff --git a/lib/presentation/riverpod_screen.dart b/lib/presentation/riverpod_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/riverpod_screen.dart
@@ -0,0 +1,14 @@
+class _RiverpodScreenState extends ConsumerState<RiverpodScreen> {
+  Future<void> _fetch() async {
+    await api.fetch();
+    ref.read(counterProvider.notifier).increment();
+  }
+}
+`
	if findings := rule.Check(unguardedDiff); len(findings) != 1 {
		t.Fatalf("expected 1 finding for unguarded ref.read after await, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_ParenthesizedMountedGuard(t *testing.T) {
	diff := `diff --git a/lib/presentation/paren_screen.dart b/lib/presentation/paren_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/paren_screen.dart
@@ -0,0 +1,14 @@
+class _ParenScreenState extends State<ParenScreen> {
+  Future<void> _handlePop() async {
+    await api.fetch();
+    if ((mounted && Navigator.of(context).canPop())) {
+      Navigator.of(context).pop();
+    }
+  }
+}
+`
	rule := AsyncGapRule{}
	if findings := rule.Check(diff); len(findings) != 0 {
		t.Fatalf("expected 0 findings for parenthesized ((mounted && Navigator...)) condition, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_ExtendedNavigatorMethods(t *testing.T) {
	unguardedDiff := `diff --git a/lib/presentation/nav_methods.dart b/lib/presentation/nav_methods.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nav_methods.dart
@@ -0,0 +1,24 @@
+class _NavMethodsState extends State<NavMethods> {
+  Future<void> _nav1() async {
+    await api.fetch();
+    Navigator.pushAndRemoveUntil(context, route, (r) => false);
+  }
+  Future<void> _nav2() async {
+    await api.fetch();
+    Navigator.replace(context, oldRoute: r1, newRoute: r2);
+  }
+  Future<void> _nav3() async {
+    await api.fetch();
+    Navigator.removeRoute(context, r1);
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(unguardedDiff)
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings for unguarded pushAndRemoveUntil, replace, removeRoute, got %d: %+v", len(findings), findings)
	}

	guardedDiff := `diff --git a/lib/presentation/nav_methods.dart b/lib/presentation/nav_methods.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/nav_methods.dart
@@ -0,0 +1,17 @@
+class _NavMethodsState extends State<NavMethods> {
+  Future<void> _navigate() async {
+    await api.fetch();
+    if (!mounted) return;
+    Navigator.pushAndRemoveUntil(context, route, (r) => false);
+    Navigator.replace(context, oldRoute: r1, newRoute: r2);
+    Navigator.removeRoute(context, r1);
+  }
+}
+`
	if findings := rule.Check(guardedDiff); len(findings) != 0 {
		t.Fatalf("expected 0 findings when guarded by if (!mounted) return, got %d: %+v", len(findings), findings)
	}
}

func TestFlutterRules_WorkingTreeAware(t *testing.T) {
	asyncGap := &AsyncGapRule{}
	asyncGap.EnableWorkingTree()
	if !asyncGap.WorkingTree {
		t.Errorf("expected AsyncGapRule.WorkingTree = true")
	}

	deactivated := &DeactivatedContextRule{}
	deactivated.EnableWorkingTree()
	if !deactivated.WorkingTree {
		t.Errorf("expected DeactivatedContextRule.WorkingTree = true")
	}

	watchOutside := &WatchOutsideBuildRule{}
	watchOutside.EnableWorkingTree()
	if !watchOutside.WorkingTree {
		t.Errorf("expected WatchOutsideBuildRule.WorkingTree = true")
	}

	lifecycleSetState := &LifecycleSetStateRule{}
	lifecycleSetState.EnableWorkingTree()
	if !lifecycleSetState.WorkingTree {
		t.Errorf("expected LifecycleSetStateRule.WorkingTree = true")
	}
}

func TestAsyncGapRule_AwaitInConditionalBlockFollowedBySink(t *testing.T) {
	diff := `diff --git a/lib/presentation/refresh_screen.dart b/lib/presentation/refresh_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/refresh_screen.dart
@@ -0,0 +1,15 @@
+class _RefreshScreenState extends State<RefreshScreen> {
+  Future<void> refresh(bool needsReload) async {
+    if (needsReload) {
+      await reload();
+    }
+    setState(() {});
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for setState after conditional await block, got %d: %+v", len(findings), findings)
	}
}

func TestAsyncGapRule_UnrelatedContextGuardDoesNotProtectRef(t *testing.T) {
	diff := `diff --git a/lib/presentation/user_screen.dart b/lib/presentation/user_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/user_screen.dart
@@ -0,0 +1,15 @@
+class _UserScreenState extends ConsumerState<UserScreen> {
+  Future<void> save(BuildContext routeCtx) async {
+    await api.save();
+    if (!routeCtx.mounted) return;
+    ref.read(userProvider);
+  }
+}
+`
	rule := AsyncGapRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for ref.read guarded only by route context, got %d: %+v", len(findings), findings)
	}
}
