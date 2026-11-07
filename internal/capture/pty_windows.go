//go:build windows

package capture

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"
)

type windowsPTY struct {
	in, out      *os.File
	hpc, process windows.Handle
	rootPID      int
	done         chan struct{}
	code         uint32
	waitErr      error
	closeOnce    sync.Once
}

func startPTY(shell string, args, env []string) (p *windowsPTY, err error) {
	if e := windows.NewLazySystemDLL("kernel32.dll").NewProc("CreatePseudoConsole").Find(); e != nil {
		return nil, fmt.Errorf("ConPTY requires Windows 10 1809 or later: %w", e)
	}
	var ir, iw, or, ow windows.Handle
	if err = windows.CreatePipe(&ir, &iw, nil, 0); err != nil {
		return nil, err
	}
	defer windows.CloseHandle(ir)
	if err = windows.CreatePipe(&or, &ow, nil, 0); err != nil {
		windows.CloseHandle(iw)
		return nil, err
	}
	defer windows.CloseHandle(ow)
	p = &windowsPTY{in: os.NewFile(uintptr(iw), "conpty-input"), out: os.NewFile(uintptr(or), "conpty-output"), done: make(chan struct{})}
	allocated := p
	defer func() {
		if err != nil {
			allocated.in.Close()
			allocated.out.Close()
			if allocated.hpc != 0 {
				windows.ClosePseudoConsole(allocated.hpc)
			}
		}
	}()
	if err = windows.CreatePseudoConsole(windows.Coord{X: 120, Y: 30}, ir, ow, 0, &p.hpc); err != nil {
		return nil, err
	}
	attrs, e := windows.NewProcThreadAttributeList(1)
	if e != nil {
		err = e
		return nil, err
	}
	defer attrs.Delete()
	update := windows.NewLazySystemDLL("kernel32.dll").NewProc("UpdateProcThreadAttribute")
	ok, _, e := update.Call(uintptr(unsafe.Pointer(attrs.List())), 0, windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, uintptr(p.hpc), unsafe.Sizeof(p.hpc), 0, 0)
	if ok == 0 {
		err = e
		return nil, err
	}
	si := windows.StartupInfoEx{}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))
	si.StartupInfo.Flags = windows.STARTF_USESTDHANDLES
	si.ProcThreadAttributeList = attrs.List()
	line, e := windows.UTF16PtrFromString(ptyCommandLine(shell, args))
	if e != nil {
		err = e
		return nil, err
	}
	if env == nil {
		env = os.Environ()
	}
	unique := make(map[string]string)
	for _, entry := range env {
		i := strings.IndexByte(entry, '=')
		if i == 0 {
			if j := strings.IndexByte(entry[1:], '='); j >= 0 {
				i = j + 1
			}
		}
		if i > 0 {
			unique[strings.ToUpper(entry[:i])] = entry
		}
	}
	env = make([]string, 0, len(unique))
	for _, entry := range unique {
		env = append(env, entry)
	}
	sort.Slice(env, func(i, j int) bool { return strings.ToUpper(env[i]) < strings.ToUpper(env[j]) })
	block := utf16.Encode([]rune(strings.Join(env, "\x00") + "\x00\x00"))
	var pi windows.ProcessInformation
	err = windows.CreateProcess(nil, line, nil, nil, false, windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_UNICODE_ENVIRONMENT, &block[0], nil, &si.StartupInfo, &pi)
	if err != nil {
		return nil, err
	}
	windows.CloseHandle(pi.Thread)
	p.process = pi.Process
	p.rootPID = int(pi.ProcessId)
	go func() {
		_, p.waitErr = windows.WaitForSingleObject(p.process, windows.INFINITE)
		if p.waitErr == nil {
			p.waitErr = windows.GetExitCodeProcess(p.process, &p.code)
		}
		p.closeOnce.Do(func() { windows.ClosePseudoConsole(p.hpc) })
		close(p.done)
	}()
	return p, nil
}
func (p *windowsPTY) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *windowsPTY) Write(b []byte) (int, error) { return p.in.Write(b) }
func (p *windowsPTY) Resize(rows, cols uint16) error {
	if rows == 0 || cols == 0 {
		return nil
	}
	return windows.ResizePseudoConsole(p.hpc, windows.Coord{X: int16(cols), Y: int16(rows)})
}
func (p *windowsPTY) Kill() error        { return windows.TerminateProcess(p.process, 1) }
func (p *windowsPTY) Wait() (int, error) { <-p.done; return int(p.code), p.waitErr }
func (p *windowsPTY) Close() error {
	p.in.Close()
	p.closeOnce.Do(func() { windows.ClosePseudoConsole(p.hpc) })
	p.out.Close()
	windows.CloseHandle(p.process)
	return nil
}

func ptyCommandLine(shell string, args []string) string {
	if strings.EqualFold(filepath.Base(shell), "cmd.exe") {
		for i, a := range args {
			if strings.EqualFold(a, "/c") || strings.EqualFold(a, "/k") {
				return windows.ComposeCommandLine(append([]string{shell}, args[:i+1]...)) + " " + strings.Join(args[i+1:], " ")
			}
		}
	}
	return windows.ComposeCommandLine(append([]string{shell}, args...))
}

func (p *windowsPTY) RootPID() int      { return p.rootPID }
func (p *windowsPTY) ConsoleID() string { return "" }
