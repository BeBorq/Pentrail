//go:build windows

package localipc

import (
	"errors"
	"net"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// With go-winio v0.6.2 a listener Close that raced an in-flight client
// connect could consume the single close signal; the connect then ended with
// another error, the Accept loop returned, and Close waited forever
// (windows-2025 CI: TestDialReachesOldServerWhoseLeafGotShortAlias timed out
// in the deferred l.Close; go-winio issue #357, fixed by PR #388, v0.6.3).
// These checks use the real session endpoint (Listen/Dial: per-user pipe
// name, private security descriptor). Each Close must return within a bound,
// Accept must report net.ErrClosed, and afterwards no pipe instance of the
// endpoint is left (no leaked listener). The race is timing-dependent, so a
// pass is evidence, not proof, that it cannot occur.
const closeBound = 10 * time.Second

func stacks() string {
	b := make([]byte, 1<<20)
	return string(b[:runtime.Stack(b, true)])
}

func requireEndpointGone(t *testing.T, path string, i int) {
	t.Helper()
	c, err := Dial(path, 250*time.Millisecond)
	if err == nil {
		c.Close()
		t.Fatalf("iteration %d: the endpoint still accepts connections after Close", i)
	}
	if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		t.Fatalf("iteration %d: after Close the pipe still exists: %v", i, err)
	}
}

func TestEndpointListenerCloseRacesConnect(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 200 && !t.Failed(); i++ {
		path := filepath.Join(dir, "race.sock")
		l, err := Listen(path)
		if err != nil {
			t.Fatal(err)
		}
		acceptErr := make(chan error, 1)
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					acceptErr <- err
					return
				}
				c.Close()
			}
		}()
		dialed := make(chan struct{})
		go func() { // connect and disconnect at once: the server's connect may end in ERROR_NO_DATA
			defer close(dialed)
			if c, err := Dial(path, 250*time.Millisecond); err == nil {
				c.Close()
			}
		}()
		time.Sleep(time.Duration(i%5) * 100 * time.Microsecond) // vary the interleaving
		closed := make(chan error, 1)
		go func() { closed <- l.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatalf("iteration %d: Close: %v", i, err)
			}
		case <-time.After(closeBound):
			t.Fatalf("iteration %d: listener Close did not return within %v (lost close signal)\n%s", i, closeBound, stacks())
		}
		select {
		case err := <-acceptErr:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("iteration %d: Accept after Close: %v, want net.ErrClosed", i, err)
			}
		case <-time.After(closeBound):
			t.Fatalf("iteration %d: Accept did not end after Close\n%s", i, stacks())
		}
		<-dialed
		requireEndpointGone(t, path, i)
	}
}

func TestEndpointListenerParallelClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "parallel.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	acceptErr := make(chan error, 1)
	go func() { _, err := l.Accept(); acceptErr <- err }()
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- l.Close() }()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(closeBound):
		t.Fatalf("parallel Close did not return within %v\n%s", closeBound, stacks())
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
	select {
	case err := <-acceptErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("pending Accept after Close: %v, want net.ErrClosed", err)
		}
	case <-time.After(closeBound):
		t.Fatalf("pending Accept did not end after Close\n%s", stacks())
	}
	if _, err := l.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept on a closed listener: %v", err)
	}
	requireEndpointGone(t, path, 0)
}
