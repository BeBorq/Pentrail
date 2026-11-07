package background

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/localipc"
)

// Codex 04C, finding 3 (`pentrail off`: "key agent process did not exit",
// seen once in a full native suite). `off` sends L and then waits 5 s for the
// agent PROCESS to end. Before 04C the agent, after answering L, waited for
// every connection handler still running; a handler waits up to its 3 s
// deadline for a client that connected but has not (yet) sent its request —
// a busy or descheduled client, or a concurrent K/P poller. That spends most
// of the 5 s budget before the process can even start to exit.
//
// This test runs the real ServeAgent in a separate process (this test binary,
// built from the current source), keeps clients connected without a request,
// polls K and P concurrently, sends L, and requires the process to have
// ended and its endpoint to be gone well within the budget. Synthetic key,
// isolated home.

const helperKey = "synthetic-agent-shutdown-key"

func TestAgentHelperProcess(t *testing.T) {
	if os.Getenv("PENTRAIL_AGENT_HELPER") != "1" {
		t.Skip("helper process for TestAgentProcessEndsPromptlyWithBusyClients")
	}
	key := []byte(helperKey)
	err := ServeAgent(AgentSocket(), key)
	if err != nil {
		os.Stderr.WriteString("helper: " + err.Error() + "\n")
		os.Exit(3)
	}
	os.Exit(0)
}

func TestAgentProcessEndsPromptlyWithBusyClients(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Dir(AgentSocket()), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestAgentHelperProcess$", "-test.count=1")
	// GORACE: under -race the runtime otherwise sleeps 1 s at exit
	// (atexit_sleep_ms), which is not the agent's own shutdown time
	cmd.Env = append(os.Environ(), "PENTRAIL_AGENT_HELPER=1", "HOME="+home, "USERPROFILE="+home, "GORACE=atexit_sleep_ms=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var waitErr error
	exited := make(chan struct{})
	go func() { waitErr = cmd.Wait(); close(exited) }()
	t.Cleanup(func() { // only this test's own helper, if a failure left it running
		select {
		case <-exited:
		default:
			cmd.Process.Kill()
			<-exited
		}
	})
	until := time.Now().Add(10 * time.Second)
	for !AgentReady() {
		if time.Now().After(until) {
			t.Fatalf("agent did not start: %s", stderr.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	// clients connected without a request (busy / descheduled)
	var idle []interface{ Close() error }
	for i := 0; i < 3; i++ {
		c, err := localipc.Dial(AgentSocket(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		idle = append(idle, c)
	}
	defer func() {
		for _, c := range idle {
			c.Close()
		}
	}()
	// concurrent K/P polling
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var okN, errN, wrong atomic.Int64
	for i := 0; i < 4; i++ {
		op := byte("KP"[i%2])
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				b, err := AgentRequest(op)
				switch {
				case err != nil:
					errN.Add(1)
					time.Sleep(time.Millisecond)
				case op == 'K' && string(b) != helperKey, op == 'P' && string(b) != "ready":
					wrong.Add(1)
				default:
					okN.Add(1)
				}
			}
		}()
	}
	time.Sleep(200 * time.Millisecond)
	t0 := time.Now()
	if b, err := AgentRequest('L'); err != nil || string(b) != "locked" {
		t.Fatalf("L: %q %v", b, err)
	}
	var elapsed time.Duration
	select {
	case <-exited:
		elapsed = time.Since(t0)
		if waitErr != nil {
			t.Fatalf("agent process: %v %s", waitErr, stderr.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("agent process still running 2 s after answering L (off waits 5 s)")
	}
	close(stop)
	wg.Wait()
	if wrong.Load() != 0 {
		t.Fatalf("%d wrong answers", wrong.Load())
	}
	if c, err := localipc.Dial(AgentSocket(), 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("agent endpoint still accepts connections after the process ended")
	}
	if _, err := os.Stat(AgentSocket()); !os.IsNotExist(err) {
		t.Fatalf("agent endpoint file not removed: %v", err)
	}
	t.Logf("AGENT_STOP process ended %v after L; pollers ok=%d err=%d; endpoint gone", elapsed.Round(time.Millisecond), okN.Load(), errN.Load())
	if elapsed > time.Second {
		t.Fatalf("process ended only %v after L", elapsed)
	}
}
