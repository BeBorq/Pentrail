//go:build linux

package store

import (
	"fmt"
	"os"
	"strings"
)

func processIdentity(pid int) (string, error) {
	b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if e != nil {
		return "", e
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 {
		return "", fmt.Errorf("invalid process identity")
	}
	fields := strings.Fields(string(b[i+1:]))
	if len(fields) <= 19 {
		return "", fmt.Errorf("incomplete process identity")
	}
	boot, e := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(string(boot)) + ":" + fields[19], nil
}
func processGone(e error) bool { return os.IsNotExist(e) }
