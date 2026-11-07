package background

import (
	"net"
	"sync"
)

// agentConns tracks the key agent's open client connections so that a lock
// request (L) can end them at once.
type agentConns struct {
	mu       sync.Mutex
	open     map[net.Conn]bool
	stopping bool
}

// add registers c; false once the agent is stopping.
func (a *agentConns) add(c net.Conn) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.stopping {
		return false
	}
	a.open[c] = true
	return true
}

func (a *agentConns) remove(c net.Conn) {
	a.mu.Lock()
	delete(a.open, c)
	a.mu.Unlock()
}

// stop marks the agent stopping and closes every open connection except
// self (the L request, already answered). It returns how many it closed.
func (a *agentConns) stop(self net.Conn) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopping = true
	n := 0
	for c := range a.open {
		if c != self {
			c.Close()
			n++
		}
	}
	return n
}
