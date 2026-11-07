//go:build linux

package localipc

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// maxSunPath is the usable length of sockaddr_un.sun_path on Linux (108 bytes
// including the terminating NUL).
const maxSunPath = 107

// sockaddrPath returns a path the kernel accepts for bind/connect. Session and
// agent sockets live next to the user's database, and an engagement folder such
// as ~/Engagements/2026-10-Client-external-pentest/evidence easily pushes
// "<dir>/run/<16 hex>.sock" past the sun_path limit, which made `pentrail
// start` fail with a bare "bind: invalid argument". For such paths the socket
// is addressed through an open descriptor of its directory
// (/proc/self/fd/N/<name>); the socket file itself is still created in, and
// found at, the original location.
func sockaddrPath(path string) (string, func(), error) {
	if len(path) <= maxSunPath {
		return path, func() {}, nil
	}
	dir, err := os.OpenFile(filepath.Dir(path), os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, err
	}
	short := fmt.Sprintf("/proc/self/fd/%d/%s", dir.Fd(), filepath.Base(path))
	if len(short) > maxSunPath {
		dir.Close()
		return "", nil, fmt.Errorf("socket name too long: %s", filepath.Base(path))
	}
	return short, func() { dir.Close() }, nil
}

// ListenUnix binds a Unix socket at path, whatever its length. The caller owns
// removal of the socket file (it is NOT unlinked on Close: for a long path the
// listener only knows the /proc alias, whose descriptor is gone by then).
func ListenUnix(path string) (*net.UnixListener, error) {
	addr, done, err := sockaddrPath(path)
	if err != nil {
		return nil, err
	}
	defer done()
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: addr, Net: "unix"})
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(false)
	return l, nil
}

func Listen(path string) (net.Listener, error) { return ListenUnix(path) }

func Dial(path string, t time.Duration) (net.Conn, error) {
	addr, done, err := sockaddrPath(path)
	if err != nil {
		return nil, err
	}
	defer done()
	return net.DialTimeout("unix", addr, t)
}

func ProtectDir(path string) error { return os.MkdirAll(path, 0700) }
