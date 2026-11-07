//go:build windows

package localipc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func UserSID() (string, error) {
	u, e := windows.GetCurrentProcessToken().GetTokenUser()
	if e != nil {
		return "", e
	}
	return u.User.Sid.String(), nil
}
func descriptor() (string, error) { sid, e := UserSID(); return "D:P(A;;GA;;;" + sid + ")", e }
func pipeName(path string) (string, error) {
	sid, e := UserSID()
	if e != nil {
		return "", e
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256([]byte(sid + "|" + strings.ToLower(abs)))
	return fmt.Sprintf(`\\.\pipe\pentrail-%x`, h[:20]), nil
}
func Listen(path string) (net.Listener, error) {
	name, e := pipeName(path)
	if e != nil {
		return nil, e
	}
	sd, e := descriptor()
	if e != nil {
		return nil, e
	}
	l, e := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sd, InputBufferSize: 65536, OutputBufferSize: 65536})
	if e != nil {
		return nil, e
	}
	if e = os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0600); e != nil {
		l.Close()
		return nil, e
	}
	return l, nil
}
func Dial(path string, t time.Duration) (net.Conn, error) {
	name, e := pipeName(path)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	return winio.DialPipeContext(ctx, name)
}

// Windows mode bits do not enforce privacy. Set an inheritable protected DACL.
func ProtectDir(path string) error {
	if e := os.MkdirAll(path, 0700); e != nil {
		return e
	}
	sid, e := UserSID()
	if e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + sid + ")")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
