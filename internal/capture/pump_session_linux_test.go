//go:build linux

package capture

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/sessionio"
)

// Codex 04F/04G: with the read-ahead pump a batch (up to maxBatch) is
// redacted and committed under this session's capture lock. While a large
// ConPTY-shaped output streams, the test measures for the SAME session and
// for a SECOND, idle session (own store, own lock):
//   - the round trip of control requests (they take the capture lock, like
//     input does) and, separately, how long each waited for the lock
//     (controlLockHook) — so lock waiting is told apart from scheduling,
//     crypto and transport on a slow machine;
//   - how long each batch held the lock (flowHook);
//
// in both modes, in the same environment and binary: one PTY read per
// durable write (pumpOneReadPerWrite, the loop before 04F) and batches.
//
// What must hold anywhere, fast or slow machine: all output arrives, pause
// and resume work during it; the idle session never waits for the busy
// session's lock; a request of the busy session waits at most about one
// batch for the lock (bounded by twice the longest hold plus the scheduling
// delay measured on the idle session). Absolute times are reported.
func TestPumpKeepsSessionResponsive(t *testing.T) {
	const abc = "abcdefghijklmnopqrstuvwxyz0123456789"
	var content []byte
	for i := 0; len(content) < 3<<20; i++ {
		content = append(content, "\x1b[30;1H"...)
		for k := 0; k < 120; k++ {
			j := i*120 + k
			content = append(content, abc[(j*7+j/97)%len(abc)])
		}
		content = append(content, "\r\n"...)
	}
	big := filepath.Join(t.TempDir(), "big.txt")
	if err := os.WriteFile(big, content, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []struct {
		name    string
		oneRead bool
	}{{"per-read (before 04F)", true}, {"batched (04F)", false}} {
		t.Run(mode.name, func(t *testing.T) {
			pumpOneReadPerWrite = mode.oneRead
			defer func() { pumpOneReadPerWrite = false }()
			r := pumpRun(t, big, len(content))
			t.Logf("PUMP %s: 3 MiB in %v, %d batches; busy session: status RTT max %v, lock wait max %v, batch lock hold max %v avg %v; off RTT %v (lock wait %v), on RTT %v; idle session: status RTT max %v, lock wait max %v",
				mode.name, r.total.Round(time.Millisecond), r.batches, r.busyRTT.Round(time.Microsecond), r.busyWait.Round(time.Microsecond),
				r.maxHeld.Round(time.Microsecond), r.avgHeld.Round(time.Microsecond), r.offRTT.Round(time.Millisecond), r.offWait.Round(time.Millisecond),
				r.onRTT.Round(time.Millisecond), r.idleRTT.Round(time.Microsecond), r.idleWait.Round(time.Microsecond))
			slack := r.idleRTT + 50*time.Millisecond // scheduling/transport, measured where no lock is contended
			if limit := 2*r.maxHeld + slack; r.busyWait > limit || r.offWait > limit {
				t.Fatalf("a request of the busy session waited %v (off %v) for the lock: more than about one batch (limit %v)", r.busyWait, r.offWait, limit)
			}
			if r.idleWait > slack {
				t.Fatalf("the idle session waited %v for its own lock (scheduling slack %v)", r.idleWait, slack)
			}
		})
	}
}

type pumpResult struct {
	total, busyRTT, busyWait, idleRTT, idleWait, offRTT, offWait, onRTT time.Duration
	maxHeld, avgHeld                                                    time.Duration
	batches                                                             int
}

func pumpRun(t *testing.T, big string, size int) pumpResult {
	var mu sync.Mutex
	var r pumpResult
	var heldSum time.Duration
	st, id, _, sock := sessionStore(t)
	st2, id2, _, sock2 := sessionStore(t)
	var lastOp string
	controlLockHook = func(session int64, op string, wait time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case session == id && op == "off":
			r.offWait = max(r.offWait, wait)
		case session == id:
			r.busyWait = max(r.busyWait, wait)
		case session == id2:
			r.idleWait = max(r.idleWait, wait)
		}
		lastOp = op
	}
	flowHook = func(s FlowSample) {
		if s.Session != id {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		r.batches++
		heldSum += s.Held
		r.maxHeld = max(r.maxHeld, s.Held)
	}
	defer func() { controlLockHook, flowHook = nil, nil; _ = lastOp }()

	done := make(chan error, 1)
	go func() {
		done <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", "read a; cat " + big + "; read b; printf AFTER_BIG; read c"}, Store: st, SessionID: id}, sock)
	}()
	done2 := make(chan error, 1)
	go func() {
		done2 <- RunServer(Options{Shell: "/bin/sh", Args: []string{"-c", "read a"}, Store: st2, SessionID: id2}, sock2)
	}()
	c2 := sessionConnect(t, sock2)
	defer c2.Close()
	c := sessionConnect(t, sock)
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Minute))
	if typ, _, err := sessionio.Read(c); err != nil || typ != sessionio.Hello {
		t.Fatal(typ, err)
	}
	w := sessionio.NewWriter(c)
	got := make(chan int, 1024)
	var screen bytes.Buffer
	var smu sync.Mutex
	tailHas := func(s string) bool {
		smu.Lock()
		defer smu.Unlock()
		return bytes.Contains(screen.Bytes()[max(0, screen.Len()-64):], []byte(s))
	}
	go func() {
		for {
			typ, p, err := sessionio.Read(c)
			if err != nil {
				close(got)
				return
			}
			if typ == sessionio.Output {
				smu.Lock()
				screen.Write(p)
				n := screen.Len()
				smu.Unlock()
				got <- n
			}
		}
	}()
	rtt := func(sock, op string) time.Duration {
		t.Helper()
		t0 := time.Now()
		s, err := sessionio.RequestControl(sock, op)
		if err != nil {
			t.Fatalf("%s: %v", op, err)
		}
		if (op == "off" && s.Recording) || (op == "on" && !s.Recording) {
			t.Fatalf("%s: %+v", op, s)
		}
		return time.Since(t0)
	}
	start := time.Now()
	w.Send(sessionio.Data, []byte("go\n"))
	toggled := false
	received := 0
	for received < size {
		select {
		case n, ok := <-got:
			if !ok {
				t.Fatal("session ended early")
			}
			received = n
		case <-time.After(2 * time.Minute):
			t.Fatalf("no output for 2 min at %d bytes", received)
		}
		r.busyRTT = max(r.busyRTT, rtt(sock, "status"))
		r.idleRTT = max(r.idleRTT, rtt(sock2, "status"))
		if !toggled && received > size/3 {
			toggled = true
			r.offRTT = rtt(sock, "off")
			r.onRTT = rtt(sock, "on")
		}
	}
	r.total = time.Since(start)
	w.Send(sessionio.Data, []byte("x\n"))
	deadline := time.After(5 * time.Minute)
	for !tailHas("AFTER_BIG") {
		select {
		case <-got:
		case <-deadline:
			t.Fatal("output after the big one did not arrive")
		}
	}
	w.Send(sessionio.Data, []byte("y\n"))
	for range got {
	}
	if err := awaitServerFor(t, done, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	c2.SetDeadline(time.Now().Add(time.Minute)) // sessionConnect's 20 s may be over
	if err := sessionio.NewWriter(c2).Send(sessionio.Data, []byte("z\n")); err != nil {
		t.Fatal(err)
	}
	if err := awaitServerFor(t, done2, 5*time.Minute); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if r.batches > 0 {
		r.avgHeld = heldSum / time.Duration(r.batches)
	}
	return r
}

func awaitServerFor(t *testing.T, ch <-chan error, d time.Duration) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		return fmt.Errorf("server did not finish in %v", d)
	}
}
