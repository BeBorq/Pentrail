package capture

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/redact"
	"github.com/BeBorq/Pentrail/internal/store"
)

// flowStats aggregates FlowSamples (Codex 04D): reads, bytes and time per
// stage of the session's output path, plus progress over time.
type flowStats struct {
	mu     sync.Mutex
	start  time.Time
	reads  int64
	bytes  int64
	offset int64
	small  int64 // reads under 256 bytes
	total  [5]time.Duration
	max    [5]time.Duration
	lastAt time.Time
	sizes  []int // every batch's size, in order (Codex 04J replay)
}

func installFlow(t *testing.T) *flowStats {
	f := &flowStats{start: time.Now()}
	flowHook = f.add
	t.Cleanup(func() { flowHook = nil })
	return f
}

func (f *flowStats) add(s FlowSample) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reads++
	f.bytes += int64(s.N)
	f.offset = s.Offset
	if s.N > 0 {
		f.sizes = append(f.sizes, s.N)
	}
	if s.N < 256 {
		f.small++
	}
	for i, d := range s.Stage {
		f.total[i] += d
		if d > f.max[i] {
			f.max[i] = d
		}
	}
	f.lastAt = time.Now()
}

// summary: one line, safe to log (counters and times only).
func (f *flowStats) summary() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "t=%v pty_reads=%d (<256B: %d) pty_bytes=%d recorded_offset=%d last_read=%v ago;",
		time.Since(f.start).Round(time.Millisecond), f.reads, f.small, f.bytes, f.offset, since(f.lastAt))
	for i, name := range flowStages {
		fmt.Fprintf(&b, " %s=%v(max %v)", name, f.total[i].Round(time.Millisecond), f.max[i].Round(time.Microsecond))
	}
	return b.String()
}

func since(t time.Time) time.Duration {
	if t.IsZero() {
		return -1
	}
	return time.Since(t).Round(time.Millisecond)
}

// marker697: a complete 697 marker "ESC ] 697 ; token ; ... BEL|ST".
var marker697 = regexp.MustCompile("\x1b\\]697;([^;\x07\x1b]*)[^\x07\x1b]*(\x07|\x1b\\\\)")

// expectedStored derives, from the bytes the client received, EXACTLY what
// the store must hold for synthetic data without secrets (Codex 04E: no
// tolerance windows):
//   - the token of every 697 marker is masked ('*', same length); every other
//     byte of the marker (ESC ] 697 ; the separators, verb, text, BEL/ST) is
//     unchanged;
//   - a line longer than redact.MaxLine (counted from the byte after the
//     previous LF up to and including its LF) is masked fail-closed: every
//     byte except CR and LF becomes '*' (the redactor cannot inspect an
//     unbounded line); this overrides the marker rule.
//
// It returns the expected bytes and how many were masked by the line rule.
func expectedStored(client []byte) ([]byte, int64) {
	exp := append([]byte(nil), client...)
	for _, m := range marker697.FindAllSubmatchIndex(client, -1) {
		for k := m[2]; k < m[3]; k++ {
			exp[k] = '*'
		}
	}
	var masked int64
	start := 0
	for i := 0; i <= len(client); i++ {
		if i < len(client) && client[i] != '\n' {
			continue
		}
		end := i + 1
		if i == len(client) {
			end = i
		}
		if end-start > redact.MaxLine {
			for k := start; k < end; k++ {
				if client[k] != '\r' && client[k] != '\n' {
					exp[k] = '*'
					masked++
				}
			}
		}
		start = end
	}
	return exp, masked
}

// rawMatchesClient: the stored stream, aligned at its end with what the
// client received (output before the client attached is not on its
// screen), must equal expectedStored(client) byte for byte.
func rawMatchesClient(raw, client []byte) (masked int64, err error) {
	if len(client) > len(raw) {
		return 0, fmt.Errorf("client received %d bytes, raw has %d", len(client), len(raw))
	}
	exp, masked := expectedStored(client)
	got := raw[len(raw)-len(client):]
	for i := range exp {
		if got[i] != exp[i] {
			lo := max(0, i-20)
			return masked, fmt.Errorf("stored byte %d is %q, expected %q (client %q); context stored %q expected %q",
				i, got[i], exp[i], client[i], got[lo:min(len(got), i+20)], exp[lo:min(len(exp), i+20)])
		}
	}
	return masked, nil
}

// The oracle itself, on what the real redactor stores (fed in chunks), and
// negative controls: a '*' at the start of a normal line, a changed byte of
// an OSC frame, an unmasked token, an unmasked over-long line, and a changed
// byte after the over-long line must all be rejected.
func TestRawMatchesClientOracle(t *testing.T) {
	long := strings.Repeat("abc", redact.MaxLine/3+10)
	client := []byte("\x1b]697;secret-tok;A\x07\x1b]697;secret-tok;P;C:\\x>\x07C:\\x>type big\r\n" +
		long + "\x1b]697;secret-tok;A\x07" + long + "\r\n\r\nC:\\x>echo ok\r\nok\r\n")
	var s redact.Stream
	var raw []byte
	for i := 0; i < len(client); i += 4096 {
		raw = append(raw, s.Feed(client[i:min(i+4096, len(client))])...)
	}
	raw = append(raw, s.Finish()...)
	if len(raw) != len(client) || strings.Contains(string(raw), "secret-tok") {
		t.Fatalf("redactor output %d bytes", len(raw))
	}
	masked, err := rawMatchesClient(raw, client)
	if err != nil || masked != int64(2*len(long)+len("\x1b]697;secret-tok;A\x07")) {
		t.Fatalf("masked %d err %v", masked, err)
	}
	okLine := strings.Index(string(client), "C:\\x>echo ok")
	osc := strings.Index(string(client), "\x1b]697;secret-tok;P;")
	tok := osc + len("\x1b]697;")
	longAt := strings.Index(string(client), long)
	for name, mutate := range map[string]func(b []byte){
		"star at the start of a normal line": func(b []byte) { b[okLine] = '*' },
		"ESC of an OSC frame changed":        func(b []byte) { b[osc] = '*' },
		"OSC verb changed":                   func(b []byte) { b[tok+len("secret-tok;")] = '*' },
		"OSC terminator changed":             func(b []byte) { b[strings.Index(string(client), "C:\\x>\x07")+4] = '*' },
		"token not masked":                   func(b []byte) { copy(b[tok:], "secret-tok") },
		"over-long line not masked":          func(b []byte) { b[longAt+5] = client[longAt+5] },
		"byte after the over-long line":      func(b []byte) { b[len(b)-3] = 'X' },
	} {
		bad := append([]byte(nil), raw...)
		mutate(bad)
		if string(bad) == string(raw) {
			t.Fatalf("%s: mutation did not change anything", name)
		}
		if _, err := rawMatchesClient(bad, client); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// commitStats aggregates store.CommitProfile (Codex 04E): what one durable
// capture write spends per sub-stage.
type commitStats struct {
	mu      sync.Mutex
	writes  int64
	stored  int64
	retries int64
	total   [6]time.Duration
	max     [6]time.Duration
	steps   []liveStep // every write's redaction step (Codex 04J)
}

func installCommitStats(t *testing.T) *commitStats {
	c := &commitStats{}
	store.SetCommitProfileHook(func(p store.CommitProfile) {
		c.mu.Lock()
		defer c.mu.Unlock()
		var total time.Duration
		for _, d := range p.Stage {
			total += d
		}
		c.steps = append(c.steps, liveStep{i: int(c.writes), input: p.Input, step: p.Stage[0], end: time.Now(), total: total, use: useOf(p)})
		c.writes++
		c.stored += int64(p.Stored)
		c.retries += int64(p.Retries)
		for i, d := range p.Stage {
			c.total[i] += d
			c.max[i] = max(c.max[i], d)
		}
	})
	store.SetStepSnapHook(takeStepSnap) // Codex 04K: what each step consumed
	t.Cleanup(func() { store.SetCommitProfileHook(nil); store.SetStepSnapHook(nil) })
	return c
}

func (c *commitStats) summary() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var b strings.Builder
	fmt.Fprintf(&b, "store writes=%d stored_bytes=%d busy_retries=%d;", c.writes, c.stored, c.retries)
	for i, name := range store.CommitStages {
		avg := time.Duration(0)
		if c.writes > 0 {
			avg = c.total[i] / time.Duration(c.writes)
		}
		fmt.Fprintf(&b, " %s=%v(avg %v max %v)", name, c.total[i].Round(time.Millisecond), avg.Round(time.Microsecond), c.max[i].Round(time.Microsecond))
	}
	return b.String()
}

// rowShapes counts output lines (LF-terminated) and how many start with a
// cursor-positioning sequence — the shape that sends the redactor into its
// continuation join (Codex 04E diagnosis).
var rowCursorStart = regexp.MustCompile(`^\x1b\[[0-9;?]*[ -/]*[HfGABCD]`)

func rowShapes(b []byte) (rows, cursorLed int) {
	for _, l := range strings.Split(string(b), "\n") {
		rows++
		if rowCursorStart.MatchString(l) {
			cursorLed++
		}
	}
	return rows, cursorLed
}

// measureStages (Codex 04F baseline): the output read from a PTY WITHOUT the
// recorder, as the reads delivered it, is put through each stage of the
// recorder alone: the redactor only; the production durable write per read;
// and the production durable write per batch of up to maxBatch bytes (what
// the read-ahead pump does under load). Store stages run on a fresh
// database in a TempDir.
func measureStages(t *testing.T, label string, chunks [][]byte) {
	t.Helper()
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	mib := float64(total) / (1 << 20)
	var s redact.Stream
	t0 := time.Now()
	var worst time.Duration
	for _, c := range chunks {
		t1 := time.Now()
		s.Feed(c)
		worst = max(worst, time.Since(t1))
	}
	s.Finish()
	d := time.Since(t0)
	t.Logf("BASELINE %s redaction only: %d reads, %.2f MiB in %v (%.2f MiB/s), worst read %v", label, len(chunks), mib, d.Round(time.Millisecond), mib/d.Seconds(), worst.Round(time.Microsecond))
	write := func(name string, batches [][]byte) {
		st, err := store.Open(filepath.Join(t.TempDir(), "stage.db"), []byte("synthetic-stage-key"))
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		id, err := st.StartSession("baseline", "test", "test")
		if err != nil {
			t.Fatal(err)
		}
		cs := installCommitStats(t)
		var off, seq int64
		t0 := time.Now()
		for _, b := range batches {
			if err := st.WriteRaw(id, seq, off, b); err != nil {
				t.Fatal(err)
			}
			seq++
			off += int64(len(b))
		}
		d := time.Since(t0)
		store.SetCommitProfileHook(nil)
		t.Logf("BASELINE %s store %s: %d writes, %v (%.2f MiB/s); %s", label, name, len(batches), d.Round(time.Millisecond), mib/d.Seconds(), cs.summary())
	}
	write("per read", chunks)
	var batched [][]byte
	var cur []byte
	for _, c := range chunks {
		if len(cur)+len(c) > maxBatch && len(cur) > 0 {
			batched = append(batched, cur)
			cur = nil
		}
		cur = append(cur, c...)
	}
	if len(cur) > 0 {
		batched = append(batched, cur)
	}
	write("per maxBatch (8 KiB) batch", batched)
}
