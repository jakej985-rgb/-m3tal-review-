package review

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var testHookMu sync.Mutex

// setFSOpsForTest replaces the filesystem hooks for the duration of a test and
// restores them via t.Cleanup when the test completes. It locks testHookMu to prevent
// concurrent tests from racing over package hooks.
func setFSOpsForTest(t testing.TB, custom fsOps) {
	testHookMu.Lock()
	origSync := syncFileHook
	origClose := closeFileHook
	origRename := renameFileHook
	origSyncDir := syncDirHook

	if custom.syncFile != nil {
		syncFileHook = custom.syncFile
	}
	if custom.closeFile != nil {
		closeFileHook = custom.closeFile
	}
	if custom.renameFile != nil {
		renameFileHook = custom.renameFile
	}
	if custom.syncDir != nil {
		syncDirHook = custom.syncDir
	}

	t.Cleanup(func() {
		syncFileHook = origSync
		closeFileHook = origClose
		renameFileHook = origRename
		syncDirHook = origSyncDir
		testHookMu.Unlock()
	})
}

// TestFSOpsHookRestoration verifies that setFSOpsForTest cleanly restores hooks upon test completion.
func TestFSOpsHookRestoration(t *testing.T) {
	initialOps := currentFSOps()

	t.Run("inner test with override", func(subT *testing.T) {
		setFSOpsForTest(subT, fsOps{
			syncFile: func(f *os.File) error {
				return fmt.Errorf("injected failure")
			},
		})

		current := currentFSOps()
		if err := current.syncFile(nil); err == nil || err.Error() != "injected failure" {
			subT.Fatalf("expected injected failure, got: %v", err)
		}
	})

	// After inner test finishes, original hook must be restored
	restoredOps := currentFSOps()
	tempFile, err := os.CreateTemp(t.TempDir(), "restore-test-*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer tempFile.Close()

	if err := restoredOps.syncFile(tempFile); err != nil {
		t.Fatalf("expected restored sync to succeed, got: %v", err)
	}
	_ = initialOps
}

// TestParallelOperationsWithIsolatedFS verifies that operations using explicit fsOps
// can run concurrently in parallel without racing or contention.
func TestParallelOperationsWithIsolatedFS(t *testing.T) {
	tempDir := t.TempDir()
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			reportDir := filepath.Join(tempDir, fmt.Sprintf("dir-%d", id))
			reportPath := filepath.Join(reportDir, "report.json")

			localOps := defaultFSOps()
			report := NewReport(fmt.Sprintf("run-%d", id), tempDir, "main", "sha", "basesha", "hash", "ver", nil, nil)

			if err := writeReportWithFS(reportPath, report, localOps); err != nil {
				t.Errorf("writeReportWithFS worker %d failed: %v", id, err)
			}
		}(i)
	}

	wg.Wait()
}
