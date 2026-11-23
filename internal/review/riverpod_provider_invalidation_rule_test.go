package review

import (
	"testing"
)

func TestRiverpodProviderInvalidationRule(t *testing.T) {
	rule := RiverpodProviderInvalidationRule{}

	t.Run("flags notifier mutation omitting ref.invalidate", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/shared/user_notifier.dart b/lib/presentation/shared/user_notifier.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/shared/user_notifier.dart
@@ -0,0 +1,15 @@
+import 'package:flutter_riverpod/flutter_riverpod.dart';
+
+class UserNotifier extends StateNotifier<UserModel?> {
+  final UserRepository _repo;
+  UserNotifier(this._repo) : super(null);
+
+  Future<void> saveProfile(UserModel profile) async {
+    await _repo.saveProfile(profile);
+    state = profile;
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Rule != "riverpod-stale-provider-mutation" {
			t.Errorf("unexpected rule name: %s", findings[0].Rule)
		}
	})

	t.Run("passes when notifier invalidates cached providers", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/shared/user_notifier.dart b/lib/presentation/shared/user_notifier.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/shared/user_notifier.dart
@@ -0,0 +1,17 @@
+import 'package:flutter_riverpod/flutter_riverpod.dart';
+
+class UserNotifier extends StateNotifier<UserModel?> {
+  final UserRepository _repo;
+  final Ref _ref;
+  UserNotifier(this._repo, this._ref) : super(null);
+
+  Future<void> saveProfile(UserModel profile) async {
+    await _repo.saveProfile(profile);
+    _ref.invalidate(allUsersProvider);
+    state = profile;
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
