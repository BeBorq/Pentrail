//go:build linux

package background

import (
	"os"
	"path/filepath"
	"syscall"
)

// Lock serializes global state changes with automatic session startup. Once
// off acknowledges, a startup already in flight cannot escape its session scan.
func Lock() (func(), error) {
	if err := os.MkdirAll(Dir(), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(Dir(), "control.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
