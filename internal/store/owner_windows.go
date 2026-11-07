//go:build windows

package store

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
)

func processIdentity(pid int) (string, error) {
	h, e := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if e != nil {
		return "", e
	}
	defer windows.CloseHandle(h)
	var code uint32
	if e = windows.GetExitCodeProcess(h, &code); e != nil {
		return "", e
	}
	if code != 259 {
		return "", windows.ERROR_INVALID_PARAMETER
	}
	var created, exited, kernel, user windows.Filetime
	if e = windows.GetProcessTimes(h, &created, &exited, &kernel, &user); e != nil {
		return "", e
	}
	return fmt.Sprintf("%08x%08x", created.HighDateTime, created.LowDateTime), nil
}
func processGone(e error) bool {
	return errors.Is(e, windows.ERROR_INVALID_PARAMETER) || errors.Is(e, windows.ERROR_NOT_FOUND)
}
