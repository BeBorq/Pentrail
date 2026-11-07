//go:build linux

package capture

import (
	"errors"
	"github.com/creack/pty"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

type linuxPTY struct {
	*os.File
	cmd *exec.Cmd
}

func startPTY(shell string, args, env []string) (*linuxPTY, error) {
	c := exec.Command(shell, args...)
	c.Env = env
	f, e := pty.Start(c)
	if e != nil {
		return nil, e
	}
	return &linuxPTY{f, c}, nil
}
func (p *linuxPTY) Resize(rows, cols uint16) error {
	return pty.Setsize(p.File, &pty.Winsize{Rows: rows, Cols: cols})
}
func (p *linuxPTY) RootPID() int { return p.cmd.Process.Pid }
func (p *linuxPTY) ConsoleID() string {
	var n uint32
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, p.Fd(), 0x80045430, uintptr(unsafe.Pointer(&n)))
	if e != 0 {
		return ""
	}
	return "/dev/pts/" + strconv.Itoa(int(n))
}
func (p *linuxPTY) Kill() error { return p.cmd.Process.Kill() }
func (p *linuxPTY) Wait() (int, error) {
	e := p.cmd.Wait()
	if e == nil {
		return 0, nil
	}
	var x *exec.ExitError
	if errors.As(e, &x) {
		if ws, ok := x.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return x.ExitCode(), nil
	}
	return 0, e
}
