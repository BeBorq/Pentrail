//go:build windows

package main

import (
	"fmt"
	"github.com/BeBorq/Pentrail/internal/background"
	"golang.org/x/sys/windows"
	"os"
	"strconv"
	"strings"
)

// Hold the exact old process handle before sending L. A failed readiness probe
// alone does not prove that Windows released all instances of its named pipe.
func agentExitWaiter() (func() error, error) {
	b, e := os.ReadFile(background.AgentSocket())
	if e != nil {
		return nil, e
	}
	pid, e := strconv.Atoi(strings.TrimSpace(string(b)))
	if e != nil {
		return nil, e
	}
	h, e := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if e != nil {
		return nil, e
	}
	return func() error {
		defer windows.CloseHandle(h)
		r, e := windows.WaitForSingleObject(h, 5000)
		if e != nil {
			return e
		}
		if r != windows.WAIT_OBJECT_0 {
			// safe facts only (no key): which process, how long
			return fmt.Errorf("key agent process did not exit (pid %d, waited 5 s)", pid)
		}
		return nil
	}, nil
}
