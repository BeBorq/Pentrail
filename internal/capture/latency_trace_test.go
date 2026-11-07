package capture

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Codex 04K: optional deep diagnostics of the redaction step, for ONE run
// (no repetition): PENTRAIL_LATENCY_DIAG=<existing folder> makes the 8 MiB
// native test (and the Linux flow tests) record, for this test process only,
//
//	trace.out  a Go execution trace (runtime/trace) of the whole output
//	           phase: every goroutine state change, GC phase, stop-the-
//	           world, GC mark assist and sweep, with timestamps; each
//	           redaction step is a region "pentrail-redact-step"
//	cpu.pprof  a CPU profile of the same phase (its samples also appear in
//	           the trace, with stacks)
//	steps.csv  every durable write: wall time of its redaction step, CPU
//	           of the thread that ran it, cycles, process CPU, allocations,
//	           GC cycles, input/pending/context/output sizes
//	analysis.txt  for the slowest steps (and every one over the limit):
//	           how the step's goroutine spent its wall time according to
//	           the trace (running / runnable = waiting for a CPU slot /
//	           waiting / syscall), the GC work done ON it (mark assist,
//	           sweep), stop-the-world overlap, and where its CPU samples
//	           fell — read with `go tool trace -d=parsed` (the Go toolchain
//	           that runs the test)
//
// Nothing changes in production (the store marks the region only while a
// test runs a trace); no OS setting, priority or GC setting is touched. The
// 100 ms assertion and the live overruns are reported as before.

type latencyDiag struct {
	dir       string
	traceFile *os.File
	cpuFile   *os.File
	stopped   bool
}

func startLatencyDiag(t *testing.T) *latencyDiag {
	base := os.Getenv("PENTRAIL_LATENCY_DIAG")
	if base == "" {
		return nil
	}
	if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
		t.Fatalf("PENTRAIL_LATENCY_DIAG=%q must be an existing folder", base)
	}
	name := regexp.MustCompile(`[^A-Za-z0-9_.-]+`).ReplaceAllString(t.Name(), "_")
	d := &latencyDiag{dir: filepath.Join(base, name+"-"+time.Now().Format("20060102-150405"))}
	if err := os.MkdirAll(d.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	var err error
	if d.traceFile, err = os.Create(filepath.Join(d.dir, "trace.out")); err != nil {
		t.Fatal(err)
	}
	if d.cpuFile, err = os.Create(filepath.Join(d.dir, "cpu.pprof")); err != nil {
		d.traceFile.Close()
		t.Fatal(err)
	}
	if err := pprof.StartCPUProfile(d.cpuFile); err != nil {
		t.Logf("LATENCY_DIAG: CPU profile not started: %v", err)
	}
	if err := trace.Start(d.traceFile); err != nil {
		pprof.StopCPUProfile()
		d.traceFile.Close()
		d.cpuFile.Close()
		t.Fatalf("execution trace: %v", err)
	}
	t.Cleanup(d.stop)
	t.Logf("LATENCY_DIAG folder: %s", d.dir)
	return d
}

func (d *latencyDiag) stop() {
	if d == nil || d.stopped {
		return
	}
	d.stopped = true
	trace.Stop()
	pprof.StopCPUProfile()
	d.traceFile.Close()
	d.cpuFile.Close()
}

// finish stops recording, writes steps.csv and analysis.txt; returns the
// analysis summary for the test log.
func (d *latencyDiag) finish(live []liveStep, limit time.Duration) string {
	if d == nil {
		return ""
	}
	d.stop()
	var csv strings.Builder
	csv.WriteString("write,input_B,step_wall_us,same_thread,thread_cpu_us,cycles,process_cpu_us,alloc_B,alloc_objects,gc_cycles,pending_B,context_B,output_B,end_unix_ns\n")
	for _, l := range live {
		u := l.use
		fmt.Fprintf(&csv, "%d,%d,%d,%v,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n", l.i, l.input, l.step.Microseconds(), u.sameThread,
			u.threadCPU.Microseconds(), u.cycles, u.procCPU.Microseconds(), u.alloc, u.allocObjs, u.gcCycles, u.pending, u.ctx, u.output, l.end.UnixNano())
	}
	os.WriteFile(filepath.Join(d.dir, "steps.csv"), []byte(csv.String()), 0o600)
	report, err := analyzeTraceFile(filepath.Join(d.dir, "trace.out"), limit, 3)
	if err != nil {
		report = "trace analysis not possible: " + err.Error()
	}
	os.WriteFile(filepath.Join(d.dir, "analysis.txt"), []byte(report+"\n"), 0o600)
	return "LATENCY_DIAG " + d.dir + ": " + strings.ReplaceAll(report, "\n", " | ")
}

// goTool finds the go command of the toolchain running the test.
func goTool() (string, error) {
	exe := "go"
	if runtime.GOOS == "windows" {
		exe = "go.exe"
	}
	if p := filepath.Join(runtime.GOROOT(), "bin", exe); fileExists(p) {
		return p, nil
	}
	return exec.LookPath("go")
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// analyzeTraceFile runs `go tool trace -d=parsed` twice (streamed): first
// to find the redaction-step regions, then to account the selected ones.
func analyzeTraceFile(path string, limit time.Duration, top int) (string, error) {
	gobin, err := goTool()
	if err != nil {
		return "", fmt.Errorf("go toolchain not found: %v", err)
	}
	run := func(f func(io.Reader) error) error {
		cmd := exec.Command(gobin, "tool", "trace", "-d=parsed", path)
		out, err := cmd.StdoutPipe()
		if err != nil {
			return err
		}
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			return err
		}
		perr := f(out)
		io.Copy(io.Discard, out)
		if werr := cmd.Wait(); werr != nil {
			return fmt.Errorf("go tool trace: %v %s", werr, strings.TrimSpace(stderr.String()))
		}
		return perr
	}
	var regions []traceRegion
	if err := run(func(r io.Reader) error { var e error; regions, e = findRegions(r); return e }); err != nil {
		return "", err
	}
	sel := selectRegions(regions, limit, top)
	if len(sel) == 0 {
		return fmt.Sprintf("no %q region in the trace", stepRegion), nil
	}
	var acc []*regionAccount
	if err := run(func(r io.Reader) error { var e error; acc, e = accountRegions(r, sel); return e }); err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d redaction-step regions in the trace; slowest %d accounted:", len(regions), len(acc))
	for _, a := range acc {
		b.WriteString("\n" + a.String())
	}
	return b.String(), nil
}

const stepRegion = "pentrail-redact-step"

type traceRegion struct {
	g          int64
	begin, end int64 // trace clock, ns
}

func (r traceRegion) dur() time.Duration { return time.Duration(r.end - r.begin) }

var (
	reHead   = regexp.MustCompile(`^M=-?\d+ P=(-?\d+) G=(-?\d+) (\w+) Time=(\d+)`)
	reType   = regexp.MustCompile(`Type="([^"]*)"`)
	reName   = regexp.MustCompile(`Name="([^"]*)"`)
	reScope  = regexp.MustCompile(`Scope=(\w+(?:\((-?\d+)\))?)`)
	reReason = regexp.MustCompile(`Reason="([^"]*)"`)
	reRes    = regexp.MustCompile(`(?:^|\s)Resource=(\w+)(?:\((-?\d+)\))?`)
	reQuoted = regexp.MustCompile(`"[^"]*"`)
	// the resource ID written directly before the transition: "GoID=1 Running->Waiting"
	reTrans = regexp.MustCompile(`(?:^|\s)(\w+)=(-?\d+)\s+(\w+)->(\w+)(?:\s|$)`)
)

// goTransition reads the goroutine state transition from a StateTransition
// line of `go tool trace -d=parsed`. Two layouts are known:
//
//	Go 1.25: ... StateTransition Time=T Resource=Goroutine(1) Reason="sleep" GoID=1 Running->Waiting
//	Go 1.27: ... StateTransition Time=T GoID=1 Running->Waiting Reason="sleep"
//
// In both, the resource ID directly before "From->To" names what changed
// state. Only GoID=N is a goroutine; the affected goroutine is N, never the
// emitter in the line's G= field. ProcID=N (a processor) and any other
// resource are not goroutine transitions: ok is false. A Resource= field, when
// present, must agree (Goroutine(N) with the same N). Quoted values (the
// reason) are blanked before matching, so a reason cannot be read as a
// transition or an ID.
func goTransition(line string) (g int64, from, to, reason string, ok bool) {
	i := strings.Index(line, " StateTransition ")
	if i < 0 {
		return 0, "", "", "", false
	}
	line = line[i+len(" StateTransition "):]
	if rm := reReason.FindStringSubmatch(line); rm != nil {
		reason = rm[1]
	}
	bare := reQuoted.ReplaceAllString(line, `""`)
	tr := reTrans.FindAllStringSubmatch(bare, -1)
	if len(tr) != 1 || tr[0][1] != "GoID" {
		return 0, "", "", "", false
	}
	if m := reRes.FindStringSubmatch(bare); m != nil && (m[1] != "Goroutine" || m[2] != tr[0][2]) {
		return 0, "", "", "", false
	}
	g, err := strconv.ParseInt(tr[0][2], 10, 64)
	if err != nil {
		return 0, "", "", "", false
	}
	return g, tr[0][3], tr[0][4], reason, true
}

type traceEvent struct {
	g    int64
	kind string
	t    int64
	line string
}

func scanEvents(r io.Reader, f func(ev traceEvent, stack []string)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	var cur *traceEvent
	var stack []string
	flush := func() {
		if cur != nil {
			f(*cur, stack)
		}
		cur, stack = nil, nil
	}
	for sc.Scan() {
		line := sc.Text()
		if m := reHead.FindStringSubmatch(line); m != nil {
			flush()
			g, _ := strconv.ParseInt(m[2], 10, 64)
			t, _ := strconv.ParseInt(m[4], 10, 64)
			cur = &traceEvent{g: g, kind: m[3], t: t, line: line}
			continue
		}
		// stack frames: "\tfunc @ 0x..." (file lines have two tabs)
		if cur != nil && cur.kind == "StackSample" && strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, "\t\t") {
			fn := strings.TrimSpace(line)
			if i := strings.Index(fn, " @ "); i >= 0 {
				fn = fn[:i]
			}
			stack = append(stack, fn)
		}
	}
	flush()
	return sc.Err()
}

func findRegions(r io.Reader) ([]traceRegion, error) {
	open := map[int64][]int64{}
	var out []traceRegion
	err := scanEvents(r, func(ev traceEvent, _ []string) {
		if ev.kind != "RegionBegin" && ev.kind != "RegionEnd" {
			return
		}
		if m := reType.FindStringSubmatch(ev.line); m == nil || m[1] != stepRegion {
			return
		}
		if ev.kind == "RegionBegin" {
			open[ev.g] = append(open[ev.g], ev.t)
			return
		}
		if s := open[ev.g]; len(s) > 0 {
			out = append(out, traceRegion{g: ev.g, begin: s[len(s)-1], end: ev.t})
			open[ev.g] = s[:len(s)-1]
		}
	})
	return out, err
}

// selectRegions: every region over limit, else (and at least) the top
// slowest.
func selectRegions(rs []traceRegion, limit time.Duration, top int) []traceRegion {
	s := append([]traceRegion(nil), rs...)
	sort.Slice(s, func(i, j int) bool { return s[i].dur() > s[j].dur() })
	n := 0
	for n < len(s) && (n < top || s[n].dur() > limit) {
		n++
	}
	return s[:n]
}

type regionAccount struct {
	r       traceRegion
	state   string
	last    int64
	inState map[string]time.Duration
	trans   int
	onG     map[string]time.Duration // ranges run on the step's goroutine (GC mark assist, sweep, ...)
	global  map[string]time.Duration // stop-the-world and GC phases overlapping the step
	samples int
	frames  map[string]int
}

func (a *regionAccount) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "step region %v on goroutine %d:", a.r.dur().Round(time.Microsecond), a.r.g)
	b.WriteString(" goroutine state —")
	b.WriteString(fmtDurMap(a.inState))
	fmt.Fprintf(&b, " (%d state changes); GC work on this goroutine —%s; overlapping global —%s; CPU samples on it: %d",
		a.trans, fmtDurMap(a.onG), fmtDurMap(a.global), a.samples)
	if len(a.frames) > 0 {
		type kv struct {
			k string
			v int
		}
		var fs []kv
		for k, v := range a.frames {
			fs = append(fs, kv{k, v})
		}
		sort.Slice(fs, func(i, j int) bool { return fs[i].v > fs[j].v || fs[i].v == fs[j].v && fs[i].k < fs[j].k })
		b.WriteString(" — where:")
		for i, f := range fs {
			if i == 6 {
				break
			}
			fmt.Fprintf(&b, " %s×%d", f.k, f.v)
		}
	}
	return b.String()
}

func fmtDurMap(m map[string]time.Duration) string {
	if len(m) == 0 {
		return " none"
	}
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return m[ks[i]] > m[ks[j]] })
	var b strings.Builder
	for _, k := range ks {
		fmt.Fprintf(&b, " %s %v;", k, m[k].Round(time.Microsecond))
	}
	return strings.TrimSuffix(b.String(), ";")
}

func overlap(a0, a1, b0, b1 int64) time.Duration {
	lo, hi := max(a0, b0), min(a1, b1)
	if hi <= lo {
		return 0
	}
	return time.Duration(hi - lo)
}

// accountRegions: for each selected region, how its goroutine spent the
// region's wall time (from its state transitions; it is Running when the
// region begins), the ranges that ran on it, global stop-the-world and GC
// phases overlapping it, and its CPU samples (first frame outside the Go
// runtime, and the innermost frame).
func accountRegions(r io.Reader, sel []traceRegion) ([]*regionAccount, error) {
	acc := make([]*regionAccount, len(sel))
	for i, s := range sel {
		acc[i] = &regionAccount{r: s, state: "Running", last: s.begin, inState: map[string]time.Duration{},
			onG: map[string]time.Duration{}, global: map[string]time.Duration{}, frames: map[string]int{}}
	}
	type openRange struct {
		name, scope string
		g           int64
		t           int64
	}
	open := map[string]openRange{}
	err := scanEvents(r, func(ev traceEvent, stack []string) {
		switch ev.kind {
		case "StateTransition":
			g, _, to, reason, ok := goTransition(ev.line)
			if !ok {
				return
			}
			if to == "Waiting" && reason != "" {
				to = "Waiting(" + reason + ")"
			}
			for _, a := range acc {
				if a.r.g != g || ev.t <= a.r.begin || ev.t >= a.r.end {
					continue
				}
				a.inState[a.state] += time.Duration(ev.t - a.last)
				a.state, a.last = to, ev.t
				a.trans++
			}
		case "RangeBegin", "RangeEnd":
			nm := reName.FindStringSubmatch(ev.line)
			sc := reScope.FindStringSubmatch(ev.line)
			if nm == nil || sc == nil {
				return
			}
			key := nm[1] + "|" + sc[1] + "|" + strconv.FormatInt(ev.g, 10)
			if ev.kind == "RangeBegin" {
				open[key] = openRange{name: nm[1], scope: sc[1], g: ev.g, t: ev.t}
				return
			}
			o, ok := open[key]
			if !ok {
				// an end may come from another emitter than its begin
				for k, v := range open {
					if v.name == nm[1] && v.scope == sc[1] {
						o, ok, key = v, true, k
						break
					}
				}
				if !ok {
					return
				}
			}
			delete(open, key)
			for _, a := range acc {
				ov := overlap(o.t, ev.t, a.r.begin, a.r.end)
				if ov == 0 {
					continue
				}
				switch {
				case strings.HasPrefix(o.name, "stop-the-world") || strings.HasPrefix(o.name, "GC concurrent mark phase") || o.scope == "Global":
					// affects every goroutine, whoever started it
					a.global[o.name] += ov
				case o.scope == fmt.Sprintf("Goroutine(%d)", a.r.g) || o.g == a.r.g:
					a.onG[o.name] += ov // e.g. GC mark assist, sweep done by the step itself
				}
			}
		case "StackSample":
			for _, a := range acc {
				if a.r.g != ev.g || ev.t < a.r.begin || ev.t > a.r.end {
					continue
				}
				a.samples++
				where := "?"
				for _, f := range stack {
					if !strings.HasPrefix(f, "runtime.") {
						where = f
						break
					}
				}
				if len(stack) > 0 && stack[0] != where {
					where += " ← " + stack[0]
				}
				a.frames[where]++
			}
		}
	})
	for _, a := range acc {
		a.inState[a.state] += time.Duration(a.r.end - a.last)
	}
	return acc, err
}

// The analysis on a REAL execution trace of this process: a region doing
// allocation-heavy work, a region that sleeps, a region that waits for a
// busy CPU. Each region's wall time must be accounted in full and the
// sleeping one must show its waiting time (not "running").
func TestTraceAnalysisAccountsRegions(t *testing.T) {
	if trace.IsEnabled() {
		t.Skip("a trace is already running")
	}
	gobin, err := goTool()
	if err != nil {
		t.Skip("go toolchain not found")
	}
	_ = gobin
	path := filepath.Join(t.TempDir(), "trace.out")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := trace.Start(f); err != nil {
		t.Fatal(err)
	}
	var sink [][]byte
	for i := 0; i < 5; i++ { // allocation-heavy steps
		r := trace.StartRegion(context.Background(), stepRegion)
		for k := 0; k < 3000; k++ {
			sink = append(sink, make([]byte, 4096))
			if len(sink) > 300 {
				sink = sink[:0]
			}
		}
		r.End()
	}
	r := trace.StartRegion(context.Background(), stepRegion) // a step that is not running
	time.Sleep(120 * time.Millisecond)
	r.End()
	trace.Stop()
	f.Close()
	rep, err := analyzeTraceFile(path, 100*time.Millisecond, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rep)
	if !strings.Contains(rep, "6 redaction-step regions") {
		t.Fatalf("regions not found: %s", rep)
	}
	lines := strings.Split(rep, "\n")
	if len(lines) < 2 || !strings.Contains(lines[1], "Waiting") {
		t.Fatalf("the sleeping step's waiting time is not shown: %s", rep)
	}
	// every accounted region: states add up to its wall time
	regs := make([]traceRegion, 0)
	fr, _ := os.Open(path)
	defer fr.Close()
	cmd := exec.Command(gobin, "tool", "trace", "-d=parsed", path)
	out, _ := cmd.StdoutPipe()
	cmd.Start()
	regs, err = findRegions(out)
	cmd.Wait()
	if err != nil || len(regs) != 6 {
		t.Fatalf("regions %v %v", regs, err)
	}
	cmd = exec.Command(gobin, "tool", "trace", "-d=parsed", path)
	out, _ = cmd.StdoutPipe()
	cmd.Start()
	acc, err := accountRegions(out, regs)
	cmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range acc {
		var sum time.Duration
		for _, d := range a.inState {
			sum += d
		}
		if sum != a.r.dur() {
			t.Fatalf("region %v accounted %v: %s", a.r.dur(), sum, a)
		}
	}
	_ = sink
}
