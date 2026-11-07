//go:build windows

package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"golang.org/x/sys/windows"
)

// Unlike the ServeAgent helper test, this uses the actual packaged CLI,
// including maskStderr and its exit flush, while idle clients and K/P pollers
// are active. A pass improves coverage; it does not explain historical hangs.
func TestRealKeyAgentBusyShutdownAndRestart(t *testing.T) {
	source, dir := os.Getenv("PENTRAIL_TEST_BINARY"), os.Getenv("PENTRAIL_AGENT_DIAG_DIR")
	if source == "" || dir == "" {
		t.Skip("actual CLI and private diagnostic directory required")
	}
	b, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	bin := filepath.Join(t.TempDir(), "pentrail.exe")
	if err := os.WriteFile(bin, b, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PENTRAIL_TEST_BINARY", bin)
	_, home, cli := reviewNative(t)
	runCycle := func(cycle int) {
		cli(true, "on")
		endpoint := background.AgentSocket()
		data, err := os.ReadFile(endpoint)
		if err != nil {
			t.Fatal(err)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			t.Fatal(err)
		}
		h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			t.Fatal(err)
		}
		defer windows.CloseHandle(h)
		image := make([]uint16, 32768)
		n := uint32(len(image))
		if err := windows.QueryFullProcessImageName(h, 0, &image[0], &n); err != nil || !strings.EqualFold(windows.UTF16ToString(image[:n]), bin) {
			t.Fatal("agent is not the private CLI")
		}
		var idle []net.Conn
		defer func() {
			for _, c := range idle {
				c.Close()
			}
		}()
		for i := 0; i < 3; i++ {
			c, err := localipc.Dial(endpoint, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			idle = append(idle, c)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var stopOnce sync.Once
		stopPolling := func() {
			stopOnce.Do(func() {
				close(stop)
				for _, c := range idle {
					c.Close()
				}
				wg.Wait()
			})
		}
		defer stopPolling()
		var good, failed, wrong atomic.Int64
		for i := 0; i < 4; i++ {
			op := byte("KP"[i%2])
			wg.Add(1)
			go func(op byte) {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					b, err := background.AgentRequest(op)
					if err != nil {
						failed.Add(1)
						time.Sleep(time.Millisecond)
						continue
					}
					if (op == 'K' && string(b) != "synthetic-review-native-key") || (op == 'P' && string(b) != "ready") {
						wrong.Add(1)
					} else {
						good.Add(1)
					}
				}
			}(op)
		}
		time.Sleep(200 * time.Millisecond)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		command := exec.CommandContext(ctx, bin, "off")
		command.Env = os.Environ()
		start := time.Now()
		out, offErr := command.CombinedOutput()
		elapsed := time.Since(start)
		cancel()
		closed, waitErr := windows.WaitForSingleObject(h, 0)
		endpointReady := background.AgentReady()
		_, statErr := os.Stat(endpoint)
		stopPolling()
		report := map[string]interface{}{"cycle": cycle, "agent_pid": pid, "subject_sha256": hex.EncodeToString(sum[:]), "off_elapsed_ms": elapsed.Milliseconds(),
			"off_ok": offErr == nil, "process_ended": waitErr == nil && closed == windows.WAIT_OBJECT_0, "endpoint_answering": endpointReady,
			"endpoint_removed": os.IsNotExist(statErr), "successful_poll_replies": good.Load(), "expected_shutdown_errors": failed.Load(), "wrong_replies": wrong.Load()}
		if offErr != nil {
			report["off_error"] = offErr.Error()
			report["off_output"] = string(out)
		}
		encoded, _ := json.MarshalIndent(report, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("cycle-%d.json", cycle)), encoded, 0600); err != nil {
			t.Fatal(err)
		}
		if offErr != nil || waitErr != nil || closed != windows.WAIT_OBJECT_0 || endpointReady || !os.IsNotExist(statErr) || good.Load() == 0 || wrong.Load() != 0 {
			if log, err := os.ReadFile(filepath.Join(home, ".pentrail/run/key-agent.log")); err == nil {
				os.WriteFile(filepath.Join(dir, fmt.Sprintf("cycle-%d-agent.log", cycle)), log, 0600)
			}
			t.Fatalf("actual agent shutdown: %s", encoded)
		}
		t.Logf("AGENT_ACTUAL_BUSY cycle=%d/6 process_ended=true endpoint_gone=true correct_poll_replies=%d off=%v", cycle+1, good.Load(), elapsed.Round(time.Millisecond))
	}
	for cycle := 0; cycle < 6; cycle++ {
		runCycle(cycle)
	}
}
