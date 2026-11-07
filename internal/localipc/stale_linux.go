//go:build linux

package localipc

import (
	"errors"
	"syscall"
)

func IsStaleError(e error) bool {
	return errors.Is(e, syscall.ECONNREFUSED) || errors.Is(e, syscall.ENOENT)
}
