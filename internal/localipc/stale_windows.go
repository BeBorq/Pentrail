//go:build windows

package localipc

import (
	"errors"
	"golang.org/x/sys/windows"
)

func IsStaleError(e error) bool {
	return errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_PIPE_NOT_CONNECTED)
}
