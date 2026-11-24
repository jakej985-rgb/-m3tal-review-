package review

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jakej985-rgb/m3tal-review/internal/review/fsutil"
)

// TestParallelReportWrites verifies concurrent report writes execute safely without races or contention.
func TestParallelReportWrites(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()
	reportsDir := filepath.Join(tempDir, "reports")

	const workerCount = 10
	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func(id int) {
			defer wg.Done()
			reportPath := filepath.Join(reportsDir, fmt.Sprintf("report-%03d.json", id))
			report := NewReport(fmt.Sprintf("run-%03d", id), tempDir, "main", "sha", "basesha", "hash", "1.0.0", nil, nil)

			if err := WriteReport(reportPath, report); err != nil {
				t.Errorf("WriteReport worker %d failed: %v", id, err)
			}

			readRep, err := ReadReport(reportPath)
			if err != nil {
				t.Errorf("ReadReport worker %d failed: %v", id, err)
			} else if readRep.RunID != report.RunID {
				t.Errorf("worker %d RunID = %s, want %s", id, readRep.RunID, report.RunID)
			}
		}(i)
	}

	wg.Wait()
}

// TestParallelIsolatedFSOps verifies that concurrent operations using isolated fsOps instances
// operate completely independently without shared state, global locks, or data races.
func TestParallelIsolatedFSOps(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()

	const workerCount = 8
	var wg sync.WaitGroup
	wg.Add(workerCount)

	for i := 0; i < workerCount; i++ {
		go func(id int) {
			defer wg.Done()
			var syncCount int64
			var closeCount int64

			isolatedOps := fsOps{
				SyncFile: func(f *os.File) error {
					atomic.AddInt64(&syncCount, 1)
					return f.Sync()
				},
				CloseFile: func(f *os.File) error {
					atomic.AddInt64(&closeCount, 1)
					return f.Close()
				},
			}

			reportPath := filepath.Join(tempDir, fmt.Sprintf("worker-%d", id), "report.json")
			report := NewReport(fmt.Sprintf("run-iso-%d", id), tempDir, "main", "sha", "basesha", "hash", "1.0.0", nil, nil)

			if err := writeReportWithFS(reportPath, report, isolatedOps); err != nil {
				t.Errorf("worker %d writeReportWithFS failed: %v", id, err)
			}

			if atomic.LoadInt64(&syncCount) != 1 {
				t.Errorf("worker %d expected 1 sync, got %d", id, atomic.LoadInt64(&syncCount))
			}
			if atomic.LoadInt64(&closeCount) != 1 {
				t.Errorf("worker %d expected 1 close, got %d", id, atomic.LoadInt64(&closeCount))
			}
		}(i)
	}

	wg.Wait()
}

// TestFSOpsInjectedFailures verifies sync, close, rename, and directory sync failures with injected fsOps.
func TestFSOpsInjectedFailures(t *testing.T) {
	t.Parallel()

	errInjectedSync := errors.New("injected sync failure")
	errInjectedClose := errors.New("injected close failure")
	errInjectedRename := errors.New("injected rename failure")
	errInjectedDirSync := errors.New("injected dir sync failure")

	t.Run("SyncFile failure", func(t *testing.T) {
		t.Parallel()
		tempDir := t.TempDir()
		reportPath := filepath.Join(tempDir, "report.json")
		report := NewReport("run-sync-fail", tempDir, "main", "sha", "", "", "1.0.0", nil, nil)

		ops := fsOps{
			SyncFile: func(f *os.File) error {
				return errInjectedSync
			},
		}

		err := writeReportWithFS(reportPath, report, ops)
		if !errors.Is(err, errInjectedSync) {
			t.Fatalf("expected sync error, got: %v", err)
		}
	})

	t.Run("CloseFile failure", func(t *testing.T) {
		t.Parallel()
		tempDir := t.TempDir()
		reportPath := filepath.Join(tempDir, "report.json")
		report := NewReport("run-close-fail", tempDir, "main", "sha", "", "", "1.0.0", nil, nil)

		ops := fsOps{
			CloseFile: func(f *os.File) error {
				_ = f.Close()
				return errInjectedClose
			},
		}

		err := writeReportWithFS(reportPath, report, ops)
		if !errors.Is(err, errInjectedClose) {
			t.Fatalf("expected close error, got: %v", err)
		}
	})

	t.Run("RenameFile failure", func(t *testing.T) {
		t.Parallel()
		tempDir := t.TempDir()
		reportPath := filepath.Join(tempDir, "report.json")
		report := NewReport("run-rename-fail", tempDir, "main", "sha", "", "", "1.0.0", nil, nil)

		ops := fsOps{
			RenameFile: func(oldpath, newpath string) error {
				return errInjectedRename
			},
		}

		err := writeReportWithFS(reportPath, report, ops)
		if !errors.Is(err, errInjectedRename) {
			t.Fatalf("expected rename error, got: %v", err)
		}
	})

	t.Run("SyncDir failure is non-fatal warning", func(t *testing.T) {
		t.Parallel()
		tempDir := t.TempDir()
		reportPath := filepath.Join(tempDir, "report.json")
		report := NewReport("run-dirsync-fail", tempDir, "main", "sha", "", "", "1.0.0", nil, nil)

		ops := fsOps{
			SyncDir: func(dir string) error {
				return errInjectedDirSync
			},
		}

		err := writeReportWithFS(reportPath, report, ops)
		if err != nil {
			t.Fatalf("expected writeReportWithFS to succeed despite dir sync failure, got: %v", err)
		}

		if _, err := os.Stat(reportPath); err != nil {
			t.Fatalf("expected report file to exist, got: %v", err)
		}
	})
}

// TestFSOpsWithDefaults verifies withDefaults populates unset operations.
func TestFSOpsWithDefaults(t *testing.T) {
	t.Parallel()
	emptyOps := fsOps{}
	populated := fsutil.WithDefaults(emptyOps)

	if populated.OpenFile == nil ||
		populated.StatFile == nil ||
		populated.WriteFile == nil ||
		populated.SyncFile == nil ||
		populated.CloseFile == nil ||
		populated.TruncateFile == nil ||
		populated.RemoveFile == nil ||
		populated.RenameFile == nil ||
		populated.SyncDir == nil {
		t.Fatal("expected all operations to be populated by withDefaults")
	}
}
