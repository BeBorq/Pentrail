//go:build linux

package capture

import (
	"os"
	"syscall"
	"unsafe"
)

func SharesConsole(pid int, console string) bool {
	if console == "" || pid <= 0 || syscall.Kill(pid, 0) != nil {
		return false
	}
	tty, e := os.OpenFile("/dev/tty", os.O_RDONLY, 0)
	if e != nil {
		return false
	}
	defer tty.Close()
	var dev uint32
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, tty.Fd(), 0x80045432, uintptr(unsafe.Pointer(&dev)))
	if errno != 0 {
		return false
	}
	fi, e := os.Stat(console)
	if e != nil {
		return false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && uint64(dev) == st.Rdev
}
