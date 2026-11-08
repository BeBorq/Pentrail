//go:build linux

package localipc

import (
	"errors"
	"syscall"
)

func IsStaleError(e error) bool {
	return errors.Is(e, syscall.ECONNREFUSED) || errors.Is(e, syscall.ENOENT)
}

// EndpointOwnerRunning is the Windows check of a named pipe's owner. On Linux
// a refused or missing Unix socket already means that no server listens on
// it, so it reports (false, nil).
func EndpointOwnerRunning(path string) (bool, error) { return false, nil }
