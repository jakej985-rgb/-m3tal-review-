package review

import (
	"errors"
	"os"
	"syscall"
)

// fsOps defines filesystem operations used for atomic report and history writes.
type fsOps struct {
	syncFile   func(f *os.File) error
	closeFile  func(f *os.File) error
	renameFile func(oldpath, newpath string) error
	syncDir    func(dir string) error
}

func defaultSyncDir(dir string) error {
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

func defaultFSOps() fsOps {
	return fsOps{
		syncFile:   func(f *os.File) error { return f.Sync() },
		closeFile:  func(f *os.File) error { return f.Close() },
		renameFile: func(oldpath, newpath string) error { return os.Rename(oldpath, newpath) },
		syncDir:    defaultSyncDir,
	}
}

// Package-level injectable hooks. Tests should use setFSOpsForTest or isolated fsOps.
var (
	syncFileHook   = func(f *os.File) error { return f.Sync() }
	closeFileHook  = func(f *os.File) error { return f.Close() }
	renameFileHook = func(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }
	syncDirHook    = defaultSyncDir
)

// currentFSOps returns the active filesystem operations using package-level hooks.
func currentFSOps() fsOps {
	return fsOps{
		syncFile:   syncFileHook,
		closeFile:  closeFileHook,
		renameFile: renameFileHook,
		syncDir:    syncDirHook,
	}
}
