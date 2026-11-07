//go:build linux

package redact

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Codex 04R (diagnostic, opt-in): the first redaction steps of a FRESH
// process, without a session around them. TestFlowCursorLedRowsLinux in
// QEMU had its slowest step at write #2 (the first 8 KiB of output, context
// 383 B) — 168.7 ms live, while the warm re-runs of the same writes stayed
// at most 51.4 ms. This separates a first-execution cost of the redaction
// code in this machine (if these steps are slow here too, alone) from
// contention with the session's other goroutines (if they are not). It
// asserts nothing; run it as the only test of a fresh process:
//
//	PENTRAIL_COLD_STEPS=1 go test -tags sqlcipher -count=1 -run '^TestRedactColdSteps$' -v ./internal/redact
//
// Per step: wall time and the CPU time of the OS thread (when the step ran
// on one thread; the goroutine is locked to it for the measurement).
func TestRedactColdSteps(t *testing.T) {
	if os.Getenv("PENTRAIL_COLD_STEPS") != "1" {
		t.Skip("diagnostic: set PENTRAIL_COLD_STEPS=1 and run as the only test")
	}
	data := stepShapes()["cursor-led rows"] // the content of TestFlowCursorLedRowsLinux
	thread := func() time.Duration {
		var ts unix.Timespec
		if unix.ClockGettime(unix.CLOCK_THREAD_CPUTIME_ID, &ts) != nil {
			return -1
		}
		return time.Duration(ts.Nano())
	}
	runtime.LockOSThread() // thread CPU belongs to this goroutine's steps
	defer runtime.UnlockOSThread()
	var s Stream
	var b strings.Builder
	for i, off := 0, 0; i < 16; i++ {
		n := 8 << 10
		c0, t0 := thread(), time.Now()
		c := s.Clone()
		c.Feed(data[off : off+n])
		wall, cpu := time.Since(t0), thread()-c0
		s = c
		pending, _, ctx := s.Sizes()
		fmt.Fprintf(&b, "\n  step %2d: wall %8.3f ms, thread CPU %8.3f ms, context %4d B, pending %3d B", i, float64(wall)/1e6, float64(cpu)/1e6, ctx, pending)
		off += n
	}
	t.Logf("COLDSTEPS fresh process, 8 KiB cursor-led batches:%s", b.String())
}
