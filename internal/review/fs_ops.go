package review

import (
	"errors"
	"os"
	"syscall"
)

// fsOps defines filesystem operations used for atomic report and history writes.
type fsOps struct {
	writeFile    func(f *os.File, b []byte) (int, error)
	syncFile     func(f *os.File) error
	closeFile    func(f *os.File) error
	truncateFile func(f *os.File, size int64) error
	removeFile   func(name string) error
	renameFile   func(oldpath, newpath string) error
	syncDir      func(dir string) error
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
		writeFile:    func(f *os.File, b []byte) (int, error) { return f.Write(b) },
		syncFile:     func(f *os.File) error { return f.Sync() },
		closeFile:    func(f *os.File) error { return f.Close() },
		truncateFile: func(f *os.File, size int64) error { return f.Truncate(size) },
		removeFile:   func(name string) error { return os.Remove(name) },
		renameFile:   func(oldpath, newpath string) error { return os.Rename(oldpath, newpath) },
		syncDir:      defaultSyncDir,
	}
}

func (ops fsOps) withDefaults() fsOps {
	def := defaultFSOps()
	if ops.writeFile == nil {
		ops.writeFile = def.writeFile
	}
	if ops.syncFile == nil {
		ops.syncFile = def.syncFile
	}
	if ops.closeFile == nil {
		ops.closeFile = def.closeFile
	}
	if ops.truncateFile == nil {
		ops.truncateFile = def.truncateFile
	}
	if ops.removeFile == nil {
		ops.removeFile = def.removeFile
	}
	if ops.renameFile == nil {
		ops.renameFile = def.renameFile
	}
	if ops.syncDir == nil {
		ops.syncDir = def.syncDir
	}
	return ops
}
