//go:build windows

package capture

import (
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

func SharesConsole(pid int, console string) bool {
	if pid <= 0 {
		return false
	}
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")
	list := make([]uint32, 64)
	for tries := 0; tries < 2; tries++ {
		n, _, _ := proc.Call(uintptr(unsafe.Pointer(&list[0])), uintptr(len(list)))
		if n == 0 || n > 4096 {
			return false
		}
		if int(n) > len(list) {
			list = make([]uint32, n)
			continue
		}
		for _, p := range list[:n] {
			if int(p) == pid {
				return true
			}
		}
		return false
	}
	return false
}

var _ = os.Getpid
