//go:build windows

package store

import (
	"errors"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

func openArtifact(path string) (*os.File, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if e != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: e}
	}
	var i windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &i); e != nil {
		windows.CloseHandle(h)
		return nil, e
	}
	if i.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		windows.CloseHandle(h)
		return nil, errUnsafeArtifact
	}
	return os.NewFile(uintptr(h), path), nil
}

func handleIdentity(h windows.Handle) (string, windows.ByHandleFileInformation, error) {
	var i windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(h, &i); e != nil {
		return "", i, e
	}
	return fmt.Sprintf("%x:%x:%x", i.VolumeSerialNumber, i.FileIndexHigh, i.FileIndexLow), i, nil
}

func fileIdentity(f *os.File) (string, error) {
	id, _, err := handleIdentity(windows.Handle(f.Fd()))
	return id, err
}

// removeVerified deletes path only if it is still the imported file. The file
// is opened without following reparse points and WITHOUT FILE_SHARE_DELETE or
// write sharing, verified through that handle (volume/file index, size,
// sha256 of the original bytes) and deleted through the same handle, so it
// cannot be swapped between the check and the deletion.
// quarantineLog is used by the Linux protocol only: on Windows the file is
// deleted through the verified handle, which no other process can rename or
// open for writing meanwhile (no FILE_SHARE_DELETE / FILE_SHARE_WRITE).
type quarantineLog func(qname, dirIdentity string) error

func recoverQuarantine(path, qname, dirIdentity, identity string, size int64, sum string, logq quarantineLog) (cleanupOutcome, string, bool) {
	if err := logq("", ""); err != nil { // never written on Windows
		return cleanupFailed, err.Error(), true
	}
	return 0, "", false
}

func removeVerified(path, identity string, size int64, sum string, _ quarantineLog) (cleanupOutcome, string) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return cleanupFailed, e.Error()
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.DELETE, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_SEQUENTIAL_SCAN, 0)
	if e != nil {
		if errors.Is(e, windows.ERROR_FILE_NOT_FOUND) || errors.Is(e, windows.ERROR_PATH_NOT_FOUND) {
			return cleanupGone, ""
		}
		if li, lerr := os.Lstat(path); lerr == nil && !li.Mode().IsRegular() {
			return cleanupMismatch, "reparse point or directory" // never retried as a "failure"
		}
		return cleanupFailed, e.Error() // e.g. still open by the tool: retry later
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	id, info, e := handleIdentity(h)
	if e != nil {
		return cleanupFailed, e.Error()
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return cleanupMismatch, "reparse point or directory"
	}
	if id != identity {
		return cleanupMismatch, "a different file (different identifier)"
	}
	if int64(info.FileSizeHigh)<<32|int64(info.FileSizeLow) != size {
		return cleanupMismatch, "zmieniony rozmiar"
	}
	if ok, why := hashMatches(f, size, sum); !ok {
		return cleanupMismatch, why
	}
	del := byte(1) // FILE_DISPOSITION_INFO{DeleteFile: TRUE}: deleted when the handle closes
	if e := windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &del, 1); e != nil {
		return cleanupFailed, e.Error()
	}
	return cleanupRemoved, ""
}
