package sessionio

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// readChunks reads Output frames "c-<i>" until Finished/err and returns the
// indices in arrival order.
func readChunks(c net.Conn, out chan<- []int) {
	var got []int
	for {
		typ, b, err := Read(c)
		if err != nil || typ != Output {
			out <- got
			return
		}
		i, _ := strconv.Atoi(strings.TrimPrefix(string(b), "c-"))
		got = append(got, i)
	}
}

// Codex iteration 02, finding 1: the pacer used to be chosen once, before
// Publish blocked on its full queue. Input from another client only updated
// lastInput, so a healthy terminal the user switched to stayed frozen until
// stallTimeout (5 min by default). The takeover must happen while Publish is
// already blocked, quickly, in order and without losing the current chunk.
func TestTakeoverWhilePublishIsBlocked(t *testing.T) {
	for _, tc := range []struct {
		name        string
		attachLater bool // second client attaches only after Publish blocked
	}{
		{"second attached before the stall", false},
		{"second attached after the stall", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withStallTimeout(t, 30*time.Second) // a stall-timeout release would show
			h := NewHub()
			old := attach(t, h) // first attached: paces output, then stops reading
			defer old.Close()
			var second net.Conn
			if !tc.attachLater {
				second = attach(t, h)
				defer second.Close()
			}
			var got chan []int
			if !tc.attachLater {
				// the observer keeps reading meanwhile (it must not be dropped)
				got = make(chan []int, 1)
				go readChunks(second, got)
			}
			const n = 3 * queueDepth
			progress := make(chan int, n)
			published := make(chan struct{})
			go func() {
				for i := 0; i < n; i++ {
					h.Publish([]byte(fmt.Sprintf("c-%d", i)))
					progress <- i
					storeCommit()
				}
				close(published)
			}()
			// wait until Publish is really stuck on the old pacer's full queue
			last := -1
			for stable := 0; stable < 3; {
				select {
				case i := <-progress:
					last = i
					stable = 0
				case <-time.After(100 * time.Millisecond):
					stable++
				}
			}
			if last >= n-1 {
				t.Fatal("publisher was never blocked; the test does not reproduce the stall")
			}
			stuckAt := last + 1
			if tc.attachLater {
				second = attach(t, h)
				defer second.Close()
				got = make(chan []int, 1)
				go readChunks(second, got)
			}
			t0 := time.Now()
			typeKey(t, second) // the user switches to the healthy terminal
			select {
			case <-published:
			case <-time.After(5 * time.Second):
				t.Fatalf("publisher still blocked %v after the user typed in another terminal (stuck at chunk %d)", time.Since(t0), stuckAt)
			}
			el := time.Since(t0)
			if el > time.Second {
				t.Fatalf("takeover took %v (want < 1s)", el)
			}
			t.Logf("publisher released %v after input in the new terminal (stuck at chunk %d)", el, stuckAt)
			h.Finish(Result{})
			chunks := <-got
			if len(chunks) == 0 {
				t.Fatal("new pacer received nothing")
			}
			first := chunks[0]
			if !tc.attachLater && first != 0 {
				t.Fatalf("observer attached from the start began at chunk %d", first)
			}
			if first > stuckAt {
				t.Fatalf("chunk %d (being published at takeover) was lost for the new pacer; first received %d", stuckAt, first)
			}
			for k, c := range chunks {
				if c != first+k {
					t.Fatalf("out of order or missing at position %d: got %d want %d", k, c, first+k)
				}
			}
			if chunks[len(chunks)-1] != n-1 {
				t.Fatalf("new pacer stopped at chunk %d of %d", chunks[len(chunks)-1], n-1)
			}
		})
	}
}

// The only terminal, slow but progressing, is never disconnected or
// bypassed while a takeover mechanism exists (no-one else typed).
func TestSoleSlowTerminalKeepsEverything(t *testing.T) {
	withStallTimeout(t, 2*time.Second)
	h := NewHub()
	slow := attach(t, h)
	defer slow.Close()
	observer := attach(t, h) // never types, keeps up
	defer observer.Close()
	obs := make(chan []int, 1)
	go readChunks(observer, obs)
	const n = 3 * queueDepth
	got := make(chan []int, 1)
	go func() {
		var idx []int
		for {
			typ, b, err := Read(slow)
			if err != nil || typ != Output {
				got <- idx
				return
			}
			i, _ := strconv.Atoi(strings.TrimPrefix(string(b), "c-"))
			idx = append(idx, i)
			time.Sleep(2 * time.Millisecond)
		}
	}()
	for i := 0; i < n; i++ {
		h.Publish([]byte(fmt.Sprintf("c-%d", i)))
		storeCommit()
	}
	h.Finish(Result{})
	for name, ch := range map[string]chan []int{"slow pacer": got, "observer": obs} {
		c := <-ch
		if len(c) != n {
			t.Fatalf("%s received %d of %d", name, len(c), n)
		}
		for k, v := range c {
			if v != k {
				t.Fatalf("%s: position %d got %d", name, k, v)
			}
		}
	}
}

// storeCommit stands in for the store write that precedes every Publish in a
// real session; without it a tight loop can enqueue queueDepth chunks before
// an observer's writer goroutine is even scheduled (see SESSION-TRANSPORT.md).
func storeCommit() { time.Sleep(50 * time.Microsecond) }
