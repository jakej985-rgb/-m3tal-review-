package review

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"time"
)

// fsOps defines filesystem operations used for atomic report and history writes.
type fsOps struct {
	openFile     func(name string, flag int, perm os.FileMode) (*os.File, error)
	statFile     func(name string) (os.FileInfo, error)
	writeFile    func(f *os.File, b []byte) (int, error)
	syncFile     func(f *os.File) error
	closeFile    func(f *os.File) error
	truncateFile func(f *os.File, size int64) error
	removeFile   func(name string) error
	renameFile   func(oldpath, newpath string) error
	syncDir      func(dir string) error
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

func defaultFSOps() fsOps {
	return fsOps{
		openFile:     os.OpenFile,
		statFile:     os.Stat,
		writeFile:    func(f *os.File, b []byte) (int, error) { return f.Write(b) },
		syncFile:     func(f *os.File) error { return f.Sync() },
		closeFile:    func(f *os.File) error { return f.Close() },
		truncateFile: func(f *os.File, size int64) error { return f.Truncate(size) },
		removeFile:   func(name string) error { return os.Remove(name) },
		renameFile:   defaultRename,
		syncDir:      defaultSyncDir,
	}
}

func (ops fsOps) withDefaults() fsOps {
	def := defaultFSOps()
	if ops.openFile == nil {
		ops.openFile = def.openFile
	}
	if ops.statFile == nil {
		ops.statFile = def.statFile
	}
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
