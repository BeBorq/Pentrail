//go:build linux

package capture

import (
	"os"
	"syscall"
	"unsafe"
)

// Minimal termios handling via raw ioctls, so we depend on nothing outside the
// standard library. Linux-only (amd64/arm64 share this struct layout).

const (
	tcgets = 0x5401
	tcsets = 0x5402

	// c_lflag bits
	echoBit   = 0x0008
	echonlBit = 0x0040
	icanon    = 0x0002
	isig      = 0x0001
	iexten    = 0x8000
	// c_iflag bits
	ignbrk = 0x0001
	brkint = 0x0002
	parmrk = 0x0008
	istrip = 0x0020
	inlcr  = 0x0040
	igncr  = 0x0080
	icrnl  = 0x0100
	ixon   = 0x0400
	// c_oflag bits
	opost = 0x0001
	// c_cflag bits
	csize  = 0x0030
	parenb = 0x0100
	cs8    = 0x0030
)

type termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Line   uint8
	Cc     [19]uint8
	Ispeed uint32
	Ospeed uint32
}

func ioctl(fd uintptr, req uintptr, t *termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(t)))
	if errno != 0 {
		return errno
	}
	return nil
}

func getTermios(fd uintptr) (termios, error) {
	var t termios
	err := ioctl(fd, tcgets, &t)
	return t, err
}

func setTermios(fd uintptr, t termios) error {
	return ioctl(fd, tcsets, &t)
}

// MakeRaw puts fd into raw mode and returns the previous state for restoration.
// This is what keeps vim/ssh/tmux byte-for-byte identical to running without
// the wrapper (pillar #1).
func MakeRaw(fd uintptr) (termios, error) {
	old, err := getTermios(fd)
	if err != nil {
		return termios{}, err
	}
	raw := old
	raw.Iflag &^= ignbrk | brkint | parmrk | istrip | inlcr | igncr | icrnl | ixon
	raw.Oflag &^= opost
	raw.Lflag &^= echoBit | echonlBit | icanon | isig | iexten
	raw.Cflag &^= csize | parenb
	raw.Cflag |= cs8
	raw.Cc[6] = 1 // VMIN  = 1
	raw.Cc[5] = 0 // VTIME = 0
	if err := setTermios(fd, raw); err != nil {
		return termios{}, err
	}
	return old, nil
}

// Restore puts fd back to a saved state.
func Restore(fd uintptr, t termios) error { return setTermios(fd, t) }

// IsTerminal reports whether fd is a tty.
func IsTerminal(fd uintptr) bool {
	_, err := getTermios(fd)
	return err == nil
}

// ReadPassphrase reads a line from /dev/tty with echo disabled. The bytes are
// returned in a caller-owned slice so the caller can zero them after use.
func ReadPassphrase(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer tty.Close()

	fd := tty.Fd()
	old, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	noecho := old
	noecho.Lflag &^= echoBit
	noecho.Lflag |= echonlBit // still move to a new line on Enter
	if err := setTermios(fd, noecho); err != nil {
		return nil, err
	}
	defer setTermios(fd, old)

	tty.WriteString(prompt)

	buf := make([]byte, 0, 128)
	one := make([]byte, 1)
	for {
		n, err := tty.Read(one)
		if n > 0 {
			c := one[0]
			if c == '\n' || c == '\r' {
				break
			}
			buf = append(buf, c)
		}
		if err != nil {
			break
		}
	}
	return buf, nil
}

// Mlockall best-effort locks the process memory so the passphrase/key and the
// in-flight capture buffers cannot be paged to swap. Needs privilege or a
// raised RLIMIT_MEMLOCK; failure is non-fatal but worth warning about.
func Mlockall() error {
	const (
		sysMlockall = 151 // amd64
		mclCurrent  = 1
		mclFuture   = 2
	)
	_, _, errno := syscall.Syscall(sysMlockall, uintptr(mclCurrent|mclFuture), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
