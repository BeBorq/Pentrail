//go:build windows

package privatefs

import (
	"errors"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"golang.org/x/sys/windows"
	"os"
)

func protectDir(path string) error { return localipc.ProtectDir(path) }
func protectHandle(f *os.File) error {
	var info windows.ByHandleFileInformation
	if e := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); e != nil {
		return e
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return errors.New("private file must be regular and not a reparse point")
	}
	private, e := openPrivate(f.Name())
	if e != nil {
		return e
	}
	defer private.Close()
	var check windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(windows.Handle(private.Fd()), &check); e != nil {
		return e
	}
	if check.VolumeSerialNumber != info.VolumeSerialNumber || check.FileIndexHigh != info.FileIndexHigh || check.FileIndexLow != info.FileIndexLow {
		return errors.New("private file changed while securing it")
	}
	sid, e := localipc.UserSID()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + sid + ")")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetSecurityInfo(windows.Handle(private.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func openPrivate(path string) (*os.File, error) {
	p, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(h), path), nil
}
func Publish(from, to string) error {
	a, e := windows.UTF16PtrFromString(from)
	if e != nil {
		return e
	}
	b, e := windows.UTF16PtrFromString(to)
	if e != nil {
		return e
	}
	return windows.MoveFileEx(a, b, windows.MOVEFILE_WRITE_THROUGH)
}
