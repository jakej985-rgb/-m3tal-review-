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

	t.Run("flags plain CRUD method name save calling repo.save", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/shared/user_notifier.dart b/lib/presentation/shared/user_notifier.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/shared/user_notifier.dart
@@ -0,0 +1,14 @@
+import 'package:flutter_riverpod/flutter_riverpod.dart';
+
+class UserNotifier extends StateNotifier<UserModel?> {
+  final UserRepository _repo;
+  UserNotifier(this._repo) : super(null);
+
+  Future<void> save(UserModel profile) async {
+    await _repo.save(profile);
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding for plain save method, got %d", len(findings))
		}
	})

	t.Run("flags mutator even when later independent method calls ref.invalidate", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/shared/user_notifier.dart b/lib/presentation/shared/user_notifier.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/shared/user_notifier.dart
@@ -0,0 +1,19 @@
+import 'package:flutter_riverpod/flutter_riverpod.dart';
+
+class UserNotifier extends StateNotifier<UserModel?> {
+  final UserRepository _repo;
+  final Ref _ref;
+  UserNotifier(this._repo, this._ref) : super(null);
+
+  Future<void> saveProfile(UserModel profile) async {
+    await _repo.saveProfile(profile);
+  }
+
+  void reloadProfiles() {
+    _ref.invalidate(allUsersProvider);
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding for saveProfile, got %d", len(findings))
		}
	})

	t.Run("flags mutator calling unrelated refreshSession", func(t *testing.T) {
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
+    refreshSession();
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
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

	t.Run("passes when notifier uses cascade invalidation", func(t *testing.T) {
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
+    _ref..invalidate(allUsersProvider);
+    state = profile;
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings with cascade invalidate, got %d", len(findings))
		}
	})

	t.Run("flags added mutation body under unchanged method header", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/shared/user_notifier.dart b/lib/presentation/shared/user_notifier.dart
--- a/lib/presentation/shared/user_notifier.dart
+++ b/lib/presentation/shared/user_notifier.dart
@@ -1,7 +1,9 @@
 class UserNotifier extends StateNotifier<UserModel?> {
   final UserRepository _repo;
   UserNotifier(this._repo) : super(null);
   Future<void> saveProfile(UserModel profile) async {
+    await _repo.saveProfile(profile);
+    state = profile;
   }
 }
 `
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding when method header is context and body is added, got %d", len(findings))
		}
	})
}
