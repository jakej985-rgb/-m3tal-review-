package review

import (
	"testing"
)

func TestCSharpAsyncRule_DetectsAsyncVoid(t *testing.T) {
	diff := `diff --git a/Services/DataService.cs b/Services/DataService.cs
new file mode 100644
--- /dev/null
+++ b/Services/DataService.cs
@@ -0,0 +1,10 @@
+namespace App.Services;
+
+public class DataService
+{
+    public async void ProcessData(string input)
+    {
+        await Task.Delay(100);
+    }
+}
+`
	rule := CSharpAsyncRule{}
	findings := rule.Check(diff)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for async void, got %d: %+v", len(findings), findings)
	}
	if findings[0].Rule != "csharp-async-anti-pattern" {
		t.Errorf("unexpected rule name: %s", findings[0].Rule)
	}
	if findings[0].Line != 5 {
		t.Errorf("expected line 5, got %d", findings[0].Line)
	}
}

func TestCSharpAsyncRule_AllowsEventHandlerAsyncVoid(t *testing.T) {
	diff := `diff --git a/Forms/MainForm.cs b/Forms/MainForm.cs
new file mode 100644
--- /dev/null
+++ b/Forms/MainForm.cs
@@ -0,0 +1,15 @@
+namespace App.Forms;
+
+public class MainForm
+{
+    public async void Button_Click(object sender, EventArgs e)
+    {
+        await Task.Delay(100);
+    }
+
+    private async void SubmitButton_Clicked(object sender, RoutedEventArgs e)
+    {
+        await Task.Delay(100);
+    }
+}
+`
	rule := CSharpAsyncRule{}
	findings := rule.Check(diff)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for event handlers, got %d: %+v", len(findings), findings)
	}
}

func TestCSharpAsyncRule_DetectsSyncOverAsync(t *testing.T) {
	diff := `diff --git a/Controllers/UserController.cs b/Controllers/UserController.cs
new file mode 100644
--- /dev/null
+++ b/Controllers/UserController.cs
@@ -0,0 +1,15 @@
+namespace App.Controllers;
+
+public class UserController
+{
+    public User GetUser(int id)
+    {
+        return FetchUserAsync(id).Result;
+    }
+
+    public void Refresh()
+    {
+        Task.Run(() => DoSync()).GetAwaiter().GetResult();
+    }
+}
+`
	rule := CSharpAsyncRule{}
	findings := rule.Check(diff)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings for sync-over-async, got %d: %+v", len(findings), findings)
	}
}
