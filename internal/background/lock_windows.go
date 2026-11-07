//go:build windows

package background

import (
	"github.com/BeBorq/Pentrail/internal/localipc"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
)

func Lock() (func(), error) {
	if e := localipc.ProtectDir(Dir()); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(Dir(), "control.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	o := &windows.Overlapped{}
	if e = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, o); e != nil {
		f.Close()
		return nil, e
	}
	return func() { _ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, o); _ = f.Close() }, nil
}
