//go:build windows

package capture

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procQueryThreadCycleTime = kernel32.NewProc("QueryThreadCycleTime")
	procGetThreadTimes       = kernel32.NewProc("GetThreadTimes")
)

func ftDur(f windows.Filetime) time.Duration {
	return time.Duration((uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)) * 100)
}

// osThreadSnap: the calling OS thread's id, CPU time and cycle count, and
// the process CPU time.
func osThreadSnap() (tid uint64, threadCPU time.Duration, cycles uint64, procCPU time.Duration) {
	var c, e, k, u windows.Filetime
	th := windows.CurrentThread()
	if r, _, _ := procGetThreadTimes.Call(uintptr(th), uintptr(unsafe.Pointer(&c)), uintptr(unsafe.Pointer(&e)),
		uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u))); r != 0 {
		threadCPU = ftDur(k) + ftDur(u)
	}
	var cy uint64
	if r, _, _ := procQueryThreadCycleTime.Call(uintptr(th), uintptr(unsafe.Pointer(&cy))); r != 0 {
		cycles = cy
	}
	if windows.GetProcessTimes(windows.CurrentProcess(), &c, &e, &k, &u) == nil {
		procCPU = ftDur(k) + ftDur(u)
	}
	return uint64(windows.GetCurrentThreadId()), threadCPU, cycles, procCPU
}
