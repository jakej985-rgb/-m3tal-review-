// Package fsutil provides injectable filesystem operations shared by the
// atomic report and history writers. Tests substitute individual functions to
// exercise failure and rollback paths.
package fsutil

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"
)

// Ops defines filesystem operations used for atomic report and history writes.
type Ops struct {
	OpenFile     func(name string, flag int, perm os.FileMode) (*os.File, error)
	StatFile     func(name string) (os.FileInfo, error)
	WriteFile    func(f *os.File, b []byte) (int, error)
	SyncFile     func(f *os.File) error
	CloseFile    func(f *os.File) error
	TruncateFile func(f *os.File, size int64) error
	RemoveFile   func(name string) error
	RenameFile   func(oldpath, newpath string) error
	SyncDir      func(dir string) error
}

func defaultSyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		// Directory fsync is unsupported on Windows file systems
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()

	if err := d.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			return nil
		}
		return err
	}
	return nil
}

func defaultRename(oldpath, newpath string) error {
	var err error
	// Windows denies renaming over a destination that is momentarily open
	// (readers, indexers, AV), so retry transient failures longer there.
	attempts := 5
	if runtime.GOOS == "windows" {
		attempts = 50
	}
	for i := 0; i < attempts; i++ {
		err = os.Rename(oldpath, newpath)
		if err == nil {
			return nil
		}
		if runtime.GOOS == "windows" {
			time.Sleep(time.Duration(min(i+1, 20)) * time.Millisecond)
			continue
		}
		break
	}
	return err
}

// SyncDir exposes the platform-aware directory sync for callers that keep
// their own write paths.
func SyncDir(dir string) error { return defaultSyncDir(dir) }

// Rename exposes the platform-aware rename for callers that keep their own
// write paths.
func Rename(oldpath, newpath string) error { return defaultRename(oldpath, newpath) }

// Default returns the real filesystem implementation.
func Default() Ops {
	return Ops{
		OpenFile:     os.OpenFile,
		StatFile:     os.Stat,
		WriteFile:    func(f *os.File, b []byte) (int, error) { return f.Write(b) },
		SyncFile:     func(f *os.File) error { return f.Sync() },
		CloseFile:    func(f *os.File) error { return f.Close() },
		TruncateFile: func(f *os.File, size int64) error { return f.Truncate(size) },
		RemoveFile:   func(name string) error { return os.Remove(name) },
		RenameFile:   defaultRename,
		SyncDir:      defaultSyncDir,
	}
}

// WithDefaults fills any nil operation with its real implementation.
func WithDefaults(ops Ops) Ops {
	def := Default()
	if ops.OpenFile == nil {
		ops.OpenFile = def.OpenFile
	}
	if ops.StatFile == nil {
		ops.StatFile = def.StatFile
	}
	if ops.WriteFile == nil {
		ops.WriteFile = def.WriteFile
	}
	if ops.SyncFile == nil {
		ops.SyncFile = def.SyncFile
	}
	if ops.CloseFile == nil {
		ops.CloseFile = def.CloseFile
	}
	if ops.TruncateFile == nil {
		ops.TruncateFile = def.TruncateFile
	}
	if ops.RemoveFile == nil {
		ops.RemoveFile = def.RemoveFile
	}
	if ops.RenameFile == nil {
		ops.RenameFile = def.RenameFile
	}
	if ops.SyncDir == nil {
		ops.SyncDir = def.SyncDir
	}
	return ops
}
