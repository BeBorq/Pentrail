package capture

import (
	"fmt"
	"runtime/metrics"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/BeBorq/Pentrail/internal/store"
)

// Codex 04K: what one redaction step consumed, measured on the goroutine
// that runs it, right before and right after the step (store step snapshot
// hook; diagnostics only). Wall time minus the CPU time of the OS thread
// that ran it says how long that thread was NOT running (taken off the CPU
// by the OS, or the goroutine moved/blocked); the cycle counter (Windows)
// is exact where thread times are tick-granular; allocations and GC cycles
// are process-wide counters (runtime/metrics, no stop-the-world).

type stepSnap struct {
	at        time.Time
	tid       uint64        // OS thread id
	threadCPU time.Duration // CPU time of that thread (user+kernel)
	cycles    uint64        // CPU cycles of that thread (Windows; 0 elsewhere)
	procCPU   time.Duration // CPU time of the whole process
	alloc     uint64        // heap bytes allocated, process total
	allocObjs uint64        // heap objects allocated, process total
	gcCycles  uint64        // GC cycles completed, process total
}

var snapMetrics = struct {
	sync.Mutex
	s []metrics.Sample
}{s: []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}, {Name: "/gc/heap/allocs:objects"}, {Name: "/gc/cycles/total:gc-cycles"}}}

// takeStepSnap is installed as the store's step snapshot hook.
func takeStepSnap() any {
	s := stepSnap{at: time.Now()}
	s.tid, s.threadCPU, s.cycles, s.procCPU = osThreadSnap()
	snapMetrics.Lock()
	metrics.Read(snapMetrics.s)
	get := func(i int) uint64 {
		if snapMetrics.s[i].Value.Kind() == metrics.KindUint64 {
			return snapMetrics.s[i].Value.Uint64()
		}
		return 0
	}
	s.alloc, s.allocObjs, s.gcCycles = get(0), get(1), get(2)
	snapMetrics.Unlock()
	return s
}

// stepUse: the difference across one step.
type stepUse struct {
	ok                   bool
	sameThread           bool
	threadCPU, procCPU   time.Duration
	cycles               uint64
	alloc, allocObjs     uint64
	gcCycles             uint64
	pending, ctx, output int
}

func useOf(p store.CommitProfile) stepUse {
	a, ok1 := p.Snap[0].(stepSnap)
	b, ok2 := p.Snap[1].(stepSnap)
	if !ok1 || !ok2 {
		return stepUse{pending: p.Pending, ctx: p.Context, output: p.Output}
	}
	u := stepUse{ok: true, sameThread: a.tid == b.tid, procCPU: b.procCPU - a.procCPU,
		alloc: b.alloc - a.alloc, allocObjs: b.allocObjs - a.allocObjs, gcCycles: b.gcCycles - a.gcCycles,
		pending: p.Pending, ctx: p.Context, output: p.Output}
	if u.sameThread {
		u.threadCPU, u.cycles = b.threadCPU-a.threadCPU, b.cycles-a.cycles
	}
	return u
}

func (u stepUse) String() string {
	if !u.ok {
		return fmt.Sprintf("no snapshot; redactor state before: pending %d B, context %d B; output %d B", u.pending, u.ctx, u.output)
	}
	th := "thread changed during the step (no thread CPU)"
	if u.sameThread {
		th = fmt.Sprintf("its OS thread ran %v CPU", u.threadCPU.Round(time.Microsecond))
		if u.cycles > 0 {
			th += fmt.Sprintf(" (%d Mcycles)", u.cycles/1e6)
		}
	}
	return fmt.Sprintf("%s; process CPU %v; allocated %d KiB in %d objects (process-wide); GC cycles completed %d; redactor state before: pending %d B, context %d B; output %d B",
		th, u.procCPU.Round(time.Microsecond), u.alloc>>10, u.allocObjs, u.gcCycles, u.pending, u.ctx, u.output)
}

// stepEvidence: the slow steps next to the median step, in plain numbers.
func stepEvidence(live []liveStep, limit time.Duration) string {
	if len(live) == 0 {
		return ""
	}
	var b strings.Builder
	med := func(f func(liveStep) float64) float64 {
		v := make([]float64, 0, len(live))
		for _, l := range live {
			if l.use.ok {
				v = append(v, f(l))
			}
		}
		if len(v) == 0 {
			return 0
		}
		sort.Float64s(v)
		return v[len(v)/2]
	}
	fmt.Fprintf(&b, "STEP median: wall %.2f ms, thread CPU %.2f ms, %.1f Mcycles, alloc %.0f KiB / %.0f objects",
		med(func(l liveStep) float64 { return float64(l.step) / 1e6 }),
		med(func(l liveStep) float64 { return float64(l.use.threadCPU) / 1e6 }),
		med(func(l liveStep) float64 { return float64(l.use.cycles) / 1e6 }),
		med(func(l liveStep) float64 { return float64(l.use.alloc) / 1024 }),
		med(func(l liveStep) float64 { return float64(l.use.allocObjs) }))
	for _, i := range slowest(live, 3) {
		for _, l := range live {
			if l.i == i {
				mark := ""
				if l.step > limit {
					mark = " OVER"
				}
				fmt.Fprintf(&b, "; STEP write #%d%s: wall %v, input %d B; %s", l.i, mark, l.step.Round(time.Microsecond), l.input, l.use)
			}
		}
	}
	return b.String()
}
