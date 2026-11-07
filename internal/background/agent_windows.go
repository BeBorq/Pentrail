//go:build windows

package background

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"os"
	"sync"
	"time"
	"unsafe"
)

// The agent uses an ACL-isolated local named pipe; remote clients are rejected.
// Other processes of the same Windows user remain inside its trust boundary.
func AgentRequest(op byte) ([]byte, error) {
	c, err := localipc.Dial(AgentSocket(), time.Second)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte{op}); err != nil {
		return nil, err
	}
	var size [4]byte
	if _, err = io.ReadFull(c, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n > 16384 {
		return nil, errors.New("invalid key-agent response")
	}
	b := make([]byte, n)
	_, err = io.ReadFull(c, b)
	return b, err
}
func AgentReady() bool { b, err := AgentRequest('P'); return err == nil && string(b) == "ready" }
func ServeAgent(path string, key []byte) error {
	if len(key) > 0 {
		_ = windows.VirtualLock(uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)))
		defer windows.VirtualUnlock(uintptr(unsafe.Pointer(&key[0])), uintptr(len(key)))
	}
	defer func() {
		for i := range key {
			key[i] = 0
		}
	}()
	ln, err := localipc.Listen(path)
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(path)
	if err = os.Chmod(path, 0600); err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	// Codex 04C: after L the process must end promptly (`off` waits for it).
	// Connections still open then (a client that connected but has not sent
	// its request, a concurrent K/P poller) are closed instead of being waited
	// for up to their 3 s deadline each.
	conns := &agentConns{open: map[net.Conn]bool{}}
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if !conns.add(c) {
			c.Close() // accepted while stopping
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer conns.remove(c)
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))

			var op [1]byte
			if _, err := io.ReadFull(c, op[:]); err != nil {
				return
			}
			var b []byte
			switch op[0] {
			case 'P':
				b = []byte("ready")
			case 'K':
				b = key
			case 'L':
				b = []byte("locked")
			default:
				return
			}
			var hdr [4]byte
			binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
			if _, err := c.Write(hdr[:]); err == nil {
				_, _ = c.Write(b)
			}
			if op[0] == 'L' {
				n := conns.stop(c)
				ln.Close()
				// safe event for the agent's log (masked stderr): no key, no path
				fmt.Fprintf(os.Stderr, "pentrail key agent: lock requested, %d other open connection(s) closed, stopping\n", n)
			}
		}()
	}
}
func ReadKeyPipe() ([]byte, error) {
	f := os.Stdin
	if f == nil {
		return nil, errors.New("missing key pipe")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, err
	}
	if len(b) > 16384 {
		return nil, fmt.Errorf("key exceeds 16 KiB")
	}
	return b, nil
}
