//go:build windows

package localipc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

func IsStaleError(e error) bool {
	return errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_PIPE_NOT_CONNECTED)
}

// EndpointOwnerRunning reports whether the process that wrote the endpoint
// file at path (Listen writes its PID there) is still running. A "not found"
// from Dial alone must not be read as "the session has ended" while that
// process may live.
//
// It answers (false, nil) only when the end is confirmed from data it could
// read: the file does not exist, no process has that PID, the process has
// exited, or the process started after the file was last written (with a
// small allowance for clock granularity), so it is a later process that
// reuses the PID of an ended server. It answers (true, nil) for a running
// writer. Anything it cannot check — the file cannot be read (for example it
// is locked), its content is not a PID, or the process cannot be queried —
// is an error: the caller must report the session as unknown, never skip it
// as ended. Nothing is done to the file or the process; they are only read
// and queried.
func EndpointOwnerRunning(path string) (bool, error) {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("endpoint %s: %w", filepath.Base(path), err)
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("endpoint %s cannot be read: %w", filepath.Base(path), err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return false, fmt.Errorf("endpoint %s does not name a process (%q)", filepath.Base(path), b)
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) { // no process with this ID
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("endpoint %s: process %d cannot be queried: %w", filepath.Base(path), pid, err)
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false, fmt.Errorf("endpoint %s: process %d: %w", filepath.Base(path), pid, err)
	}
	if code != 259 /* STILL_ACTIVE */ {
		return false, nil
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return false, fmt.Errorf("endpoint %s: process %d: %w", filepath.Base(path), pid, err)
	}
	if time.Unix(0, created.Nanoseconds()).After(fi.ModTime().Add(2 * time.Second)) {
		return false, nil // started after the file was written: PID reuse
	}
	return true, nil
}
