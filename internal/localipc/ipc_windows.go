//go:build windows

package localipc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

// pathConv converts an existing path with GetLongPathName or GetShortPathName.
func pathConv(f func(*uint16, *uint16, uint32) (uint32, error)) func(string) (string, error) {
	return func(p string) (string, error) {
		u, e := windows.UTF16PtrFromString(p)
		if e != nil {
			return "", e
		}
		buf := make([]uint16, 1024)
		for {
			n, e := f(u, &buf[0], uint32(len(buf)))
			if e != nil {
				return "", e
			}
			if n == 0 {
				return "", windows.ERROR_INVALID_NAME
			}
			if int(n) < len(buf) {
				return windows.UTF16ToString(buf[:n]), nil
			}
			buf = make([]uint16, n+1)
		}
	}
}

var (
	longPath  = pathConv(windows.GetLongPathName)
	shortPath = pathConv(windows.GetShortPathName)
)

func hashName(sid, key string) string {
	h := sha256.Sum256([]byte(sid + "|" + key))
	return fmt.Sprintf(`\\.\pipe\pentrail-%x`, h[:20])
}

// pipeNames returns the pipe name of an endpoint path (canonical, see
// endpointKeys) and the names an older server may have used for it.
func pipeNames(path string) (canonical string, legacy []string, err error) {
	sid, e := UserSID()
	if e != nil {
		return "", nil, e
	}
	abs, e := filepath.Abs(path)
	if e != nil {
		return "", nil, e
	}
	key, old := endpointKeys(abs, longPath, shortPath)
	for _, k := range old {
		legacy = append(legacy, hashName(sid, k))
	}
	return hashName(sid, key), legacy, nil
}

func pipeName(path string) (string, error) {
	name, _, e := pipeNames(path)
	return name, e
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

// Dial connects to the endpoint under its canonical pipe name. Only if no
// such pipe exists does it try the names a server of an older version may
// have used for another spelling of the same path. Any other error (busy,
// timeout, access denied) is returned at once, never replaced by a later
// attempt; if no name exists, the "not found" error of the canonical name is
// returned.
func Dial(path string, t time.Duration) (net.Conn, error) {
	name, legacy, e := pipeNames(path)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), t)
	defer cancel()
	c, first := winio.DialPipeContext(ctx, name)
	if first == nil || !errors.Is(first, windows.ERROR_FILE_NOT_FOUND) {
		return c, first
	}
	for _, n := range legacy {
		c, e := winio.DialPipeContext(ctx, n)
		if e == nil {
			return c, nil
		}
		if !errors.Is(e, windows.ERROR_FILE_NOT_FOUND) {
			return nil, e
		}
	}
	return nil, first
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
