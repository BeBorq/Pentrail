//go:build linux

package capture

import (
	"time"

	"golang.org/x/sys/unix"
)

func osThreadSnap() (tid uint64, threadCPU time.Duration, cycles uint64, procCPU time.Duration) {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &ts) == nil {
		threadCPU = time.Duration(ts.Nano())
	}
	if unix.ClockGettime(unix.CLOCK_PROCESS_CPUTIME_ID, &ts) == nil {
		procCPU = time.Duration(ts.Nano())
	}
	return uint64(unix.Gettid()), threadCPU, 0, procCPU
}
