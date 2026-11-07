package sessionio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type shortWriter struct{ bytes.Buffer }

func (w *shortWriter) Write(b []byte) (int, error) {
	runtime.Gosched()
	if len(b) > 1 {
		b = b[:1]
	}
	return w.Buffer.Write(b)
}

func TestConcurrentFramesWithShortWrites(t *testing.T) {
	var buf shortWriter
	w := NewWriter(&buf)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				b := bytes.Repeat([]byte{byte(i)}, 16)
				if err := w.Send(Data, b); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	for i := 0; i < 800; i++ {
		typ, b, err := Read(&buf.Buffer)
		if err != nil {
			t.Fatal(err)
		}
		if typ != Data || len(b) != 16 || !bytes.Equal(b, bytes.Repeat(b[:1], 16)) {
			t.Fatalf("corrupt frame: type=%d payload=%x", typ, b)
		}
	}
	if buf.Len() != 0 {
		t.Fatal("trailing bytes")
	}
}

func TestResultAndUnexpectedDisconnect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result *Result
		want   string
	}{
		{"complete", &Result{}, ""},
		{"write failure", &Result{CaptureError: "disk full"}, "disk full"},
		{"shell failure", &Result{ExitCode: 7}, "status 7"},
		{"server died", nil, "completeness is unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wire, out bytes.Buffer
			w := NewWriter(&wire)
			w.Send(Hello, []byte(Version))
			w.Send(Output, []byte("evidence"))
			if tc.result != nil {
				b, _ := json.Marshal(tc.result)
				w.Send(Finished, b)
			}
			err := Receive(&wire, &out)
			if tc.want == "" && err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if out.String() != "evidence" {
				t.Fatal(out.String())
			}
		})
	}
}

func attach(t *testing.T, h *Hub) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	ready := make(chan struct{})
	var once sync.Once
	go h.ServeConn(server, func(byte, []byte) error { once.Do(func() { close(ready) }); return nil })
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := NewWriter(client).Send(Hello, []byte(Version)); err != nil {
		t.Fatal(err)
	}
	typ, b, err := Read(client)
	if err != nil || typ != Hello || string(b) != Version {
		t.Fatalf("hello: %d %s %v", typ, b, err)
	}
	client.SetDeadline(time.Time{})
	if err := NewWriter(client).Send(Data, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("client not registered")
	}
	return client
}

func withStallTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := stallTimeout
	stallTimeout = d
	t.Cleanup(func() { stallTimeout = old })
}

// type sends a keystroke frame, making this client the one that paces output.
func typeKey(t *testing.T, c net.Conn) {
	t.Helper()
	if err := NewWriter(c).Send(Data, []byte("x")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // let ServeConn record it
}

func readN(c net.Conn, n int, done chan<- int) {
	count := 0
	for count < n {
		typ, _, err := Read(c)
		if err != nil || typ != Output {
			break
		}
		count++
	}
	done <- count
}

// drain keeps reading until the connection ends (so Finish is not waiting on a
// test client that simply stopped reading).
func drain(c net.Conn) {
	go func() {
		for {
			if _, _, err := Read(c); err != nil {
				return
			}
		}
	}()
}

func peerCount(h *Hub) int { h.mu.Lock(); defer h.mu.Unlock(); return len(h.peers) }

// Codex review: several hung clients used to cost stallTimeout EACH, freezing
// the active terminal. Observers must never slow the session: hung ones are
// dropped at once, the active client receives everything without delay.
func TestHungObserversNeverStallActiveClient(t *testing.T) {
	withStallTimeout(t, 30*time.Second) // any wait on an observer would show
	h := NewHub()
	var hung []net.Conn
	for i := 0; i < 3; i++ { // attached first, never read
		c := attach(t, h)
		defer c.Close()
		hung = append(hung, c)
	}
	active := attach(t, h)
	defer active.Close()
	typeKey(t, active)
	const n = 4 * queueDepth
	got := make(chan int, 1)
	go readN(active, n, got)
	start := time.Now()
	for i := 0; i < n; i++ {
		h.Publish([]byte("burst"))
	}
	if c := <-got; c != n {
		t.Fatalf("active client received %d of %d", c, n)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("hung observers stalled the session for %v", el)
	}
	if pc := peerCount(h); pc != 1 {
		t.Fatalf("hung observers not dropped: %d peers left", pc)
	}
	// registration still works and the new client gets output
	late := attach(t, h)
	defer late.Close()
	late.SetReadDeadline(time.Now().Add(2 * time.Second))
	go func() { // keep the active client draining
		for {
			if _, _, err := Read(active); err != nil {
				return
			}
		}
	}()
	h.Publish([]byte("still alive"))
	if typ, b, err := Read(late); err != nil || typ != Output || string(b) != "still alive" {
		t.Fatalf("late attach: %d %s %v", typ, b, err)
	}
	late.SetReadDeadline(time.Time{})
	drain(late)
	h.Finish(Result{})
}

// While the active client is not reading (Publish is waiting for it, the
// shell is paused), new clients can attach and control requests succeed.
func TestAttachAndControlWhileActiveClientBlocks(t *testing.T) {
	withStallTimeout(t, 3*time.Second)
	h := NewHub()
	h.SetControl(func(op string) (ControlState, error) { return ControlState{SessionID: 7, Recording: true}, nil })
	blocked := attach(t, h) // first attached: paces output, never reads
	defer blocked.Close()
	published := make(chan struct{})
	go func() {
		for i := 0; i < queueDepth+5; i++ {
			h.Publish([]byte("x"))
		}
		close(published)
	}()
	time.Sleep(100 * time.Millisecond)
	t0 := time.Now()
	other := attach(t, h)
	defer other.Close()
	srv, cli := net.Pipe()
	go h.ServeConn(srv, nil)
	w := NewWriter(cli)
	cli.SetDeadline(time.Now().Add(2 * time.Second))
	if err := w.Send(Hello, []byte(Version+" control")); err != nil {
		t.Fatal(err)
	}
	if typ, _, err := Read(cli); err != nil || typ != Hello {
		t.Fatalf("control hello: %v", err)
	}
	w.Send(Control, []byte("status"))
	if typ, _, err := Read(cli); err != nil || typ != ControlReply {
		t.Fatalf("control reply: %v", err)
	}
	if el := time.Since(t0); el > time.Second {
		t.Fatalf("attach+control waited %v behind a blocked client", el)
	}
	go func() {
		for {
			if _, _, err := Read(other); err != nil {
				return
			}
		}
	}()
	select {
	case <-published: // the blocked pacer was dropped after stallTimeout
	case <-time.After(10 * time.Second):
		t.Fatal("publisher never released")
	}
	h.Finish(Result{})
}

// The client the user types into becomes the pacing one; the previous window
// (now idle and hung) is an observer and cannot hold the session.
func TestTypingClientBecomesPacer(t *testing.T) {
	withStallTimeout(t, 30*time.Second)
	h := NewHub()
	first := attach(t, h) // started the session, then stopped reading
	defer first.Close()
	second := attach(t, h)
	defer second.Close()
	typeKey(t, second)
	const n = 2 * queueDepth
	got := make(chan int, 1)
	go readN(second, n, got)
	start := time.Now()
	for i := 0; i < n; i++ {
		h.Publish([]byte("y"))
	}
	if c := <-got; c != n || time.Since(start) > 5*time.Second {
		t.Fatalf("typing client got %d/%d in %v", c, n, time.Since(start))
	}
	drain(second)
	h.Finish(Result{})
}

// Regression: a slow-but-progressing terminal (SSH over VPN, a slow emulator)
// was disconnected as soon as it fell 32 chunks behind a burst such as
// `seq 1 400000`. It must instead receive everything, in order, and the final
// status — backpressure, like a real terminal.
func TestSlowClientGetsBackpressureNotDisconnect(t *testing.T) {
	withStallTimeout(t, 2*time.Second)
	h := NewHub()
	slow := attach(t, h)
	defer slow.Close()
	const n = 4 * queueDepth
	done := make(chan error, 1)
	go func() {
		for i := 0; i < n; i++ {
			typ, b, err := Read(slow)
			if err != nil {
				done <- err
				return
			}
			if typ != Output || string(b) != fmt.Sprintf("chunk-%d", i) {
				done <- fmt.Errorf("chunk %d: got %d %q", i, typ, b)
				return
			}
			time.Sleep(3 * time.Millisecond) // slower than the producer
		}
		typ, b, err := Read(slow)
		if err != nil || typ != Finished {
			done <- fmt.Errorf("no final status: %d %s %v", typ, b, err)
			return
		}
		done <- nil
	}()
	for i := 0; i < n; i++ {
		h.Publish([]byte(fmt.Sprintf("chunk-%d", i)))
	}
	h.Finish(Result{})
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDetachAndFinalStatusAfterOutput(t *testing.T) {
	h := NewHub()
	first := attach(t, h)
	first.Close()
	second := attach(t, h)
	defer second.Close()
	errCh := make(chan error, 1)
	go func() {
		typ, b, err := Read(second)
		if err == nil && (typ != Output || string(b) != "after reattach") {
			err = io.ErrUnexpectedEOF
		}
		if err != nil {
			errCh <- err
			return
		}
		typ, b, err = Read(second)
		if err != nil {
			errCh <- err
			return
		}
		var r Result
		err = json.Unmarshal(b, &r)
		if err == nil && (typ != Finished || r.CaptureError != "flush failed") {
			err = io.ErrUnexpectedEOF
		}
		errCh <- err
	}()
	h.Publish([]byte("after reattach"))
	h.Finish(Result{CaptureError: "flush failed"})
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("final status timed out")
	}
}

func TestProtocolLimitsAndVersion(t *testing.T) {
	var b bytes.Buffer
	if err := NewWriter(&b).Send(Data, make([]byte, MaxFrame+1)); err == nil {
		t.Fatal("oversized send accepted")
	}
	b.Write([]byte{1, 0, 16, 0, 1})
	if _, _, err := Read(&b); err == nil {
		t.Fatal("oversized read accepted")
	}
	b.Reset()
	NewWriter(&b).Send(Hello, []byte("old"))
	if err := Receive(&b, io.Discard); err == nil {
		t.Fatal("old version accepted")
	}
}
