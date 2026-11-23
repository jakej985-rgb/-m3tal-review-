package review

import (
	"testing"
)

func TestCourseCompletionGatingRule(t *testing.T) {
	rule := CourseCompletionGatingRule{}

	t.Run("flags course completion checking loaded sibling lessons", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/learn/lesson_screen.dart b/lib/presentation/features/learn/lesson_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/features/learn/lesson_screen.dart
@@ -0,0 +1,15 @@
+class LessonScreen {
+  Future<void> checkCompletion(String courseId) async {
+    final siblings = await repo.getCourseLessons(courseId);
+    if (siblings.every((l) => progress.isCompleted(l.id))) {
+      await repo.markCourseComplete(courseId);
+    }
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		if findings[0].Rule != "course-completion-authoritative-gating" {
			t.Errorf("unexpected rule name: %s", findings[0].Rule)
		}
	})

	t.Run("flags completion checking siblings even if course.lessonIds.isNotEmpty is checked", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/learn/lesson_screen.dart b/lib/presentation/features/learn/lesson_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/features/learn/lesson_screen.dart
@@ -0,0 +1,18 @@
+class LessonScreen {
+  Future<void> checkCompletion(String courseId) async {
+    final course = await repo.getCourseById(courseId);
+    final siblings = await repo.getCourseLessons(courseId);
+    if (course.lessonIds.isNotEmpty && siblings.every((l) => progress.isCompleted(l.id))) {
+      await repo.markCourseComplete(courseId);
+    }
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
	})

	t.Run("ignores siblings.every when only controlling download indicator", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/learn/lesson_screen.dart b/lib/presentation/features/learn/lesson_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/features/learn/lesson_screen.dart
@@ -0,0 +1,15 @@
+class LessonScreen {
+  Future<void> updateDownloadStatus(String courseId) async {
+    final siblings = await repo.getCourseLessons(courseId);
+    final isReady = siblings.every((l) => l.isDownloaded);
+    updateBadge(isReady);
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for download indicator, got %d: %+v", len(findings), findings)
		}
	})

	t.Run("passes when verifying authoritative course.lessonIds", func(t *testing.T) {
		diff := `diff --git a/lib/presentation/features/learn/lesson_screen.dart b/lib/presentation/features/learn/lesson_screen.dart
new file mode 100644
--- /dev/null
+++ b/lib/presentation/features/learn/lesson_screen.dart
@@ -0,0 +1,16 @@
+class LessonScreen {
+  Future<void> checkCompletion(String courseId) async {
+    final course = await repo.getCourseById(courseId);
+    if (course.lessonIds.isNotEmpty &&
+        course.lessonIds.every((id) => progress.isCompleted(id))) {
+      await repo.markCourseComplete(courseId);
+    }
+  }
+}
+`
		findings := rule.Check(diff)
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings, got %d", len(findings))
		}
	})
}
