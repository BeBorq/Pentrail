//go:build windows

package capture

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/windows"
	"os"
)

type termios uint32

func IsTerminal(fd uintptr) bool {
	var m uint32
	return windows.GetConsoleMode(windows.Handle(fd), &m) == nil
}
func MakeRaw(fd uintptr) (termios, error) {
	h := windows.Handle(fd)
	var old uint32
	if e := windows.GetConsoleMode(h, &old); e != nil {
		return 0, e
	}
	m := old &^ (windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT)
	m |= windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	return termios(old), windows.SetConsoleMode(h, m)
}
func Restore(fd uintptr, t termios) error {
	return windows.SetConsoleMode(windows.Handle(fd), uint32(t))
}
func consoleSize() (uint16, uint16) {
	var i windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(windows.Handle(os.Stdout.Fd()), &i) == nil {
		return uint16(i.Window.Bottom - i.Window.Top + 1), uint16(i.Window.Right - i.Window.Left + 1)
	}
	return 30, 120
}
func ReadPassphrase(prompt string) ([]byte, error) {
	in, e := os.OpenFile("CONIN$", os.O_RDWR, 0)
	if e != nil {
		return nil, e
	}
	defer in.Close()
	out, e := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
	if e != nil {
		return nil, e
	}
	defer out.Close()
	var old uint32
	h := windows.Handle(in.Fd())
	if e = windows.GetConsoleMode(h, &old); e != nil {
		return nil, e
	}
	if e = windows.SetConsoleMode(h, (old|windows.ENABLE_LINE_INPUT|windows.ENABLE_PROCESSED_INPUT)&^windows.ENABLE_ECHO_INPUT); e != nil {
		return nil, e
	}
	defer windows.SetConsoleMode(h, old)
	fmt.Fprint(out, prompt)
	b, e := bufio.NewReader(in).ReadBytes('\n')
	fmt.Fprintln(out)
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b, e
}
func Mlockall() error { return nil } // Windows locks individual key buffers in its agent.
