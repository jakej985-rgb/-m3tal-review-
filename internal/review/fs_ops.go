package review

import (
	"errors"
	"os"
	"syscall"
)

// Injected filesystem hooks for deterministic error injection and testing.
var (
	syncFileHook   = func(f *os.File) error { return f.Sync() }
	closeFileHook  = func(f *os.File) error { return f.Close() }
	renameFileHook = func(oldpath, newpath string) error { return os.Rename(oldpath, newpath) }
	syncDirHook    = func(dir string) error {
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
)
