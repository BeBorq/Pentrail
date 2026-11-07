package capture

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/redact"
)

// Codex 04J: a single redaction step of 110 ms (limit 100 ms) in one full
// native run, 11.8 ms in a focused run of the same test without a code
// change. The per-step time is WALL-CLOCK: it includes whatever the
// operating system and the Go runtime do to the process meanwhile, which no
// limit on a non-realtime OS can bound. The limit is therefore checked as
// two separate statements, each with its own evidence:
//
//  1. algorithmic: after the session, the exact batches of that run (sizes
//     from flowHook, bytes from what the client received) are replayed
//     through the same redactor step (Clone + Feed); the slowest live
//     batches are re-run (min of several runs). Over the limit = FAIL.
//  2. live: every live step over the limit must be EXPLAINED by a stall the
//     scheduler probe — an independent goroutine sleeping 1 ms in a loop,
//     touching neither the store nor the redactor — saw in the same time
//     window, at least as long as the overrun. Unexplained = FAIL.
//
// An explained overrun is reported (LATENCY line), not hidden.

// latencyLimit: the 04E acceptance — no single redaction step costs
// hundreds of milliseconds; 100 ms, unchanged.
const latencyLimit = 100 * time.Millisecond

// stall: the probe woke late by late; the stall ended at end.
type stall struct {
	end  time.Time
	late time.Duration
}

type schedProbe struct {
	mu      sync.Mutex
	stalls  []stall
	maxLate time.Duration
	wakes   int64
	stop    chan struct{}
	done    chan struct{}
	gc0     runtime.MemStats
	gc1     runtime.MemStats
}

// probeStallMin: shorter lateness is timer granularity, not a stall.
const probeStallMin = 20 * time.Millisecond

func startSchedProbe(t *testing.T) *schedProbe {
	p := &schedProbe{stop: make(chan struct{}), done: make(chan struct{})}
	runtime.ReadMemStats(&p.gc0)
	go func() {
		defer close(p.done)
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			t0 := time.Now()
			time.Sleep(time.Millisecond)
			now := time.Now()
			late := now.Sub(t0) - time.Millisecond
			p.mu.Lock()
			p.wakes++
			p.maxLate = max(p.maxLate, late)
			if late >= probeStallMin {
				p.stalls = append(p.stalls, stall{end: now, late: late})
			}
			p.mu.Unlock()
		}
	}()
	t.Cleanup(p.finish)
	return p
}

func (p *schedProbe) finish() {
	select {
	case <-p.stop:
		return
	default:
	}
	close(p.stop)
	<-p.done
	runtime.ReadMemStats(&p.gc1)
}

func (p *schedProbe) summary() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf("probe wakes=%d max_late=%v stalls>=%v: %d; GC cycles=%d pause_total=%v",
		p.wakes, p.maxLate.Round(time.Microsecond), probeStallMin, len(p.stalls),
		p.gc1.NumGC-p.gc0.NumGC, time.Duration(p.gc1.PauseTotalNs-p.gc0.PauseTotalNs).Round(time.Microsecond))
}

// liveStep: one durable write's redaction step as measured in the session.
type liveStep struct {
	i     int           // index among durable writes
	input int           // bytes fed by it (0: a seal/finish)
	step  time.Duration // redaction step (Clone + Feed/Seal)
	end   time.Time     // when the write's profile was reported
	total time.Duration // the whole write (all stages)
	use   stepUse       // what the step consumed (Codex 04K)
}

// window: the interval in which the write, and so its step, ran.
func (s liveStep) window() (time.Time, time.Time) { return s.end.Add(-s.total), s.end }

// replayResult: the algorithmic cost of the run's own batches.
type replayResult struct {
	ok      bool   // false: sizes did not match the bytes; no replay
	why     string // when !ok
	steps   []time.Duration
	p50     time.Duration
	max     time.Duration
	maxAt   int
	reruns  map[int]time.Duration // batch index -> min of reruns
	nReruns int
}

// replaySteps repeats the run's durable writes on stream: ops[i] is write
// i's input size (0: a seal of the pending line, no new input), timing each
// step as the store does (Clone, then Feed or Seal). The writes in rerun are
// then re-run from their own saved state n times, keeping the minimum: the
// cost without scheduling noise.
func replaySteps(stream []byte, ops []int, rerun []int, n int) replayResult {
	sum := 0
	for _, s := range ops {
		sum += s
	}
	if sum != len(stream) || len(ops) == 0 {
		return replayResult{why: fmt.Sprintf("the writes fed %d B, the client received %d B", sum, len(stream))}
	}
	starts := make([]int, len(ops)+1)
	for i, size := range ops {
		starts[i+1] = starts[i] + size
	}
	apply := func(c *redact.Stream, i int) {
		if ops[i] == 0 {
			c.Seal()
		} else {
			c.Feed(stream[starts[i]:starts[i+1]])
		}
	}
	r := replayResult{ok: true, reruns: map[int]time.Duration{}, nReruns: n}
	saved := make([]redact.Stream, len(ops))
	var s redact.Stream
	for i := range ops {
		saved[i] = s.Clone()
		t0 := time.Now()
		c := s.Clone()
		apply(&c, i)
		d := time.Since(t0)
		s = c
		r.steps = append(r.steps, d)
		if d > r.max {
			r.max, r.maxAt = d, i
		}
	}
	rerun = append(rerun, r.maxAt) // the replay's own slowest write too
	for _, i := range rerun {
		if i < 0 || i >= len(ops) {
			continue
		}
		best := time.Duration(1<<63 - 1)
		for k := 0; k < n; k++ {
			t0 := time.Now()
			c := saved[i].Clone()
			apply(&c, i)
			best = min(best, time.Since(t0))
		}
		r.reruns[i] = best
	}
	sorted := append([]time.Duration(nil), r.steps...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a] < sorted[b] })
	r.p50 = sorted[len(sorted)/2]
	return r
}

// judgeLatency applies the two statements above. live: every durable
// write's step in order; stalls: what the probe saw.
func judgeLatency(live []liveStep, r replayResult, stalls []stall, limit time.Duration) (fail bool, report string) {
	var b strings.Builder
	var worst liveStep
	over := 0
	for _, s := range live {
		if s.step > worst.step {
			worst = s
		}
		if s.step > limit {
			over++
		}
	}
	fmt.Fprintf(&b, "LATENCY live: %d steps, worst %v (write #%d), over %v: %d", len(live), worst.step.Round(time.Microsecond), worst.i, limit, over)
	if !r.ok {
		fmt.Fprintf(&b, "; replay NOT possible (%s)", r.why)
		if over > 0 {
			fmt.Fprintf(&b, "; FAIL: a live step exceeded the limit and its algorithmic cost cannot be established")
			return true, b.String()
		}
		return false, b.String()
	}
	algoWorst, algoAt := time.Duration(0), -1
	for i, d := range r.reruns {
		if d > algoWorst {
			algoWorst, algoAt = d, i
		}
	}
	fmt.Fprintf(&b, "; replay of the same %d durable writes: p50 %v, max %v (write #%d); re-run min of %d: worst %v (write #%d)",
		len(r.steps), r.p50.Round(time.Microsecond), r.max.Round(time.Microsecond), r.maxAt, r.nReruns, algoWorst.Round(time.Microsecond), algoAt)
	if algoWorst > limit {
		fmt.Fprintf(&b, "; FAIL: algorithmic — write #%d costs %v without scheduling noise", algoAt, algoWorst)
		fail = true
	}
	for _, s := range live {
		if s.step <= limit {
			continue
		}
		from, to := s.window()
		need := s.step - limit
		var by *stall
		for k := range stalls {
			st := stalls[k]
			sFrom := st.end.Add(-st.late)
			if sFrom.Before(to) && st.end.After(from) && st.late >= need {
				by = &st
				break
			}
		}
		algo := r.reruns[s.i]
		if by == nil {
			fmt.Fprintf(&b, "; FAIL: write #%d step %v (algorithmic %v) over the limit and NOT explained by a scheduler stall in its window", s.i, s.step.Round(time.Microsecond), algo.Round(time.Microsecond))
			fail = true
		} else {
			fmt.Fprintf(&b, "; write #%d step %v (algorithmic %v) explained: the probe stalled %v in the same window", s.i, s.step.Round(time.Microsecond), algo.Round(time.Microsecond), by.late.Round(time.Microsecond))
		}
	}
	return fail, b.String()
}

// slowest returns the indices of the k slowest live steps.
func slowest(live []liveStep, k int) []int {
	idx := make([]int, len(live))
	for i := range idx {
		idx[i] = i
	}
	sort.Slice(idx, func(a, b int) bool { return live[idx[a]].step > live[idx[b]].step })
	var out []int
	for _, i := range idx[:min(k, len(idx))] {
		out = append(out, live[i].i)
	}
	return out
}

// checkLatency: the whole 04J check for a finished session. stream: what
// the client received (the PTY bytes, in order); fs, cs: the run's flow
// and commit statistics; probe: the run's scheduler probe.
func checkLatency(t *testing.T, stream []byte, fs *flowStats, cs *commitStats, probe *schedProbe, diag *latencyDiag) (bool, string) {
	t.Helper()
	probe.finish()
	fs.mu.Lock()
	sizes := append([]int(nil), fs.sizes...)
	fs.mu.Unlock()
	cs.mu.Lock()
	live := append([]liveStep(nil), cs.steps...)
	cs.mu.Unlock()
	// optional deep diagnostics (PENTRAIL_LATENCY_DIAG): stopped before the
	// replay so the trace holds the session only
	diagRep := diag.finish(live, latencyLimit) // reported with the result below
	// cross-check: the writes that fed input are the PTY batches, in order
	var ops, fed []int
	for _, l := range live {
		ops = append(ops, l.input)
		if l.input > 0 {
			fed = append(fed, l.input)
		}
	}
	if fmt.Sprint(fed) != fmt.Sprint(sizes) {
		r := replayResult{why: fmt.Sprintf("%d feeding writes do not match the %d PTY batches", len(fed), len(sizes))}
		fail, rep := judgeLatency(live, r, probe.stalls, latencyLimit)
		return fail, rep + "; " + probe.summary() + "; " + stepEvidence(live, latencyLimit) + diagSuffix(diagRep)
	}
	r := replaySteps(stream, ops, slowest(live, 5), 5)
	probe.mu.Lock()
	stalls := append([]stall(nil), probe.stalls...)
	probe.mu.Unlock()
	fail, rep := judgeLatency(live, r, stalls, latencyLimit)
	return fail, rep + "; " + probe.summary() + "; " + stepEvidence(live, latencyLimit) + diagSuffix(diagRep)
}

func diagSuffix(s string) string {
	if s == "" {
		return ""
	}
	return "; " + s
}

// --- the check itself, on fabricated measurements (deterministic) ---

func TestJudgeLatency(t *testing.T) {
	t0 := time.Unix(1000, 0)
	step := func(i int, ms int, endMs int) liveStep {
		return liveStep{i: i, step: time.Duration(ms) * time.Millisecond, end: t0.Add(time.Duration(endMs) * time.Millisecond), total: time.Duration(ms+5) * time.Millisecond}
	}
	okReplay := replayResult{ok: true, steps: []time.Duration{time.Millisecond}, reruns: map[int]time.Duration{0: 12 * time.Millisecond, 1: 11 * time.Millisecond}, nReruns: 5}
	cases := []struct {
		name   string
		live   []liveStep
		replay replayResult
		stalls []stall
		fail   bool
		want   string
	}{
		{"all under the limit", []liveStep{step(0, 12, 100), step(1, 11, 200)}, okReplay, nil, false, "over 100ms: 0"},
		{"overrun explained by a stall in its window", []liveStep{step(0, 12, 100), step(1, 110, 400)},
			okReplay, []stall{{end: t0.Add(390 * time.Millisecond), late: 95 * time.Millisecond}}, false, "explained"},
		{"overrun, no stall", []liveStep{step(1, 110, 400)}, okReplay, nil, true, "NOT explained"},
		{"stall too short for the overrun", []liveStep{step(1, 150, 400)}, okReplay,
			[]stall{{end: t0.Add(390 * time.Millisecond), late: 30 * time.Millisecond}}, true, "NOT explained"},
		{"stall outside the window", []liveStep{step(1, 110, 400)}, okReplay,
			[]stall{{end: t0.Add(100 * time.Millisecond), late: 95 * time.Millisecond}}, true, "NOT explained"},
		{"algorithmic overrun fails even with a stall", []liveStep{step(1, 150, 400)},
			replayResult{ok: true, steps: []time.Duration{time.Millisecond}, reruns: map[int]time.Duration{1: 140 * time.Millisecond}, nReruns: 5},
			[]stall{{end: t0.Add(390 * time.Millisecond), late: 200 * time.Millisecond}}, true, "algorithmic"},
		{"no replay and an overrun", []liveStep{step(1, 110, 400)}, replayResult{why: "x"},
			[]stall{{end: t0.Add(390 * time.Millisecond), late: 200 * time.Millisecond}}, true, "cannot be established"},
	}
	for _, c := range cases {
		fail, rep := judgeLatency(c.live, c.replay, c.stalls, latencyLimit)
		if fail != c.fail || !strings.Contains(rep, c.want) {
			t.Errorf("%s: fail=%v want %v; %s", c.name, fail, c.fail, rep)
		}
	}
}

// The replay reproduces the redactor's own batching: same bytes out as one
// Feed of the whole stream, and every re-run batch measured.
func TestReplayStepsMatchesStream(t *testing.T) {
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b []byte
	for i := 0; len(b) < 256<<10; i++ {
		b = append(b, "\x1b[30;1H"...)
		for k := 0; k < 120; k++ {
			j := i*120 + k
			b = append(b, abc[(j*7+j/97)%len(abc)])
		}
		b = append(b, "\r\n"...)
	}
	var sizes []int
	for left, k := len(b), 0; left > 0; k++ {
		n := min(left, 1+(k*2654435761)%(8<<10))
		sizes = append(sizes, n)
		left -= n
	}
	ops := append([]int{}, sizes[:10]...)
	ops = append(ops, 0) // a seal between batches (pause)
	ops = append(ops, sizes[10:]...)
	r := replaySteps(b, ops, []int{0, 3, 10, len(ops) - 1}, 3)
	if !r.ok || len(r.steps) != len(ops) || len(r.reruns) < 4 {
		t.Fatalf("replay: %+v", r)
	}
	if bad := replaySteps(b[:len(b)-1], sizes, nil, 1); bad.ok {
		t.Fatal("size mismatch not detected")
	}
	t.Logf("replay of %d batches: p50 %v max %v; reruns %v", len(sizes), r.p50, r.max, r.reruns)
}
