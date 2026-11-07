//go:build windows

package store

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Creating symlinks needs SeCreateSymbolicLinkPrivilege (or Developer Mode).
func symlinkUnavailable(err error) bool {
	return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}
