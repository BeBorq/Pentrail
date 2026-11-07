package sessionio

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// queueDepth is per client (PTY reads are at most 32 KiB, so up to ~4 MiB).
const queueDepth = 128

// finalDrain bounds how long Finish waits for clients to receive their last
// output and the final status.
var finalDrain = 30 * time.Second

// writeTimeout bounds the handshake and control replies.
const writeTimeout = time.Second

// Flow control. Exactly one attached client paces the session: the one that
// typed most recently (or, before anyone typed, the first one attached — the
// window that started the session). Like a real terminal, a slow pacing
// client slows the output: Publish waits, the session stops reading the PTY
// and the shell's writes block in the kernel. Input from another client
// re-evaluates the pacer even while Publish is already waiting (the user
// switched windows), see noteInput. Every other client is an observer: it
// never slows the session; if it is queueDepth chunks behind it is
// disconnected (it can re-attach), so hung observers cannot add up to a stall.
// Evidence never depends on any client: the store commits every chunk before
// it is published.
//
// stallTimeout is how long ONE chunk may wait for a free slot in the pacer's
// queue (and, in the writer goroutine, how long ONE frame write may take).
// It is not a measure of overall progress: a pacer that drains a frame every
// few minutes is never disconnected.
var stallTimeout = 5 * time.Minute

type peer struct {
	conn      net.Conn
	queue     chan []byte
	done      chan struct{}
	once      sync.Once
	result    []byte // assigned before queue is closed
	attached  int64  // attach order
	lastInput atomic.Int64
}

func (p *peer) stop() { p.once.Do(func() { close(p.done); p.conn.Close() }) }

// Hub never performs network I/O while publishing PTY output or holding mu.
// See stallTimeout for the flow-control rules.
type Hub struct {
	pubMu      sync.Mutex // serializes Publish with Finish (which closes queues)
	mu         sync.Mutex
	attachSeq  int64
	peers      map[*peer]bool
	closed     bool
	result     []byte
	wg         sync.WaitGroup
	controller func(string) (ControlState, error)
	onAttach   func()
	repace     chan struct{}        // closed (and replaced) when another client types
	typer      atomic.Pointer[peer] // client that sent the most recent input
}

func NewHub() *Hub { return &Hub{peers: make(map[*peer]bool), repace: make(chan struct{})} }

func (h *Hub) SetOnAttach(fn func()) { h.mu.Lock(); h.onAttach = fn; h.mu.Unlock() }

func (h *Hub) Publish(b []byte) {
	// One immutable copy can be shared by all client queues.
	b = append([]byte(nil), b...)
	h.pubMu.Lock()
	defer h.pubMu.Unlock()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	peers := make(map[*peer]bool, len(h.peers))
	for p := range h.peers {
		peers[p] = true
	}
	pacer := h.pacerLocked()
	repace := h.repace
	h.mu.Unlock()
	// Sends happen outside mu so attaches and control requests are never
	// blocked by a slow client. Queues are closed only by Finish, which takes
	// pubMu, so a queue cannot be closed under an in-flight send.
	for p := range peers {
		if p != pacer {
			h.offer(p, b)
		}
	}
	if pacer == nil {
		return
	}
	select {
	case pacer.queue <- b:
		return
	case <-pacer.done:
		return
	default:
	}
	timer := time.NewTimer(stallTimeout)
	defer timer.Stop()
	for {
		select {
		case pacer.queue <- b:
			return
		case <-pacer.done:
			return
		case <-timer.C:
			h.drop(pacer) // this chunk waited stallTimeout for a free slot
			return
		case <-repace:
			// Another client typed while we were waiting: the user switched
			// terminals. Re-evaluate who paces instead of waiting for the old
			// one (Codex iteration 02, finding 1).
			h.mu.Lock()
			next := h.pacerLocked()
			repace = h.repace
			h.mu.Unlock()
			if next == pacer {
				continue
			}
			// The old pacer is now an observer: same rule as every observer.
			h.offer(pacer, b)
			if next == nil || peers[next] {
				// next was in this chunk's snapshot, so it already has b
				// (or was dropped as a hung observer and is gone).
				return
			}
			// next attached after this chunk was taken: it gets the current
			// chunk too, then normal pacing applies to it.
			pacer = next
			peers[next] = true
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(stallTimeout)
		}
	}
}

// offer delivers b to an observer without ever waiting for it; an observer
// queueDepth chunks behind is disconnected (it can re-attach).
func (h *Hub) offer(p *peer, b []byte) {
	select {
	case p.queue <- b:
	case <-p.done:
	default:
		h.drop(p)
	}
}

// pacerLocked: the client that typed most recently, else the first attached.
func (h *Hub) pacerLocked() *peer {
	var pacer *peer
	for p := range h.peers {
		if pacer == nil || p.lastInput.Load() > pacer.lastInput.Load() ||
			(p.lastInput.Load() == pacer.lastInput.Load() && p.attached < pacer.attached) {
			pacer = p
		}
	}
	return pacer
}

// noteInput records keyboard input; if it comes from a different client than
// the previous input, a Publish blocked on the old pacer is woken up.
func (h *Hub) noteInput(p *peer) {
	p.lastInput.Store(time.Now().UnixNano())
	if h.typer.Swap(p) == p {
		return
	}
	h.mu.Lock()
	close(h.repace)
	h.repace = make(chan struct{})
	h.mu.Unlock()
}

func (h *Hub) drop(p *peer) {
	h.mu.Lock()
	delete(h.peers, p)
	h.mu.Unlock()
	p.stop()
}

// ServeConn validates the protocol before registering a client. Only framed
// Data/Resize input is accepted; the caller supplies the PTY operations.
func (h *Hub) ServeConn(c net.Conn, input func(byte, []byte) error) {
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	typ, b, err := Read(c)
	control := string(b) == Version+" control"
	if err != nil || typ != Hello || (string(b) != Version && !control) {
		return
	}
	c.SetReadDeadline(time.Time{})
	w := NewWriter(c)
	c.SetWriteDeadline(time.Now().Add(writeTimeout))
	if w.Send(Hello, []byte(Version)) != nil {
		return
	}
	if control {
		h.control(c, w)
		return
	}
	p := &peer{conn: c, queue: make(chan []byte, queueDepth), done: make(chan struct{})}
	h.mu.Lock()
	if h.closed {
		result := h.result
		h.mu.Unlock()
		_ = w.Send(Finished, result)
		return
	}
	if len(h.peers) >= 16 {
		h.mu.Unlock()
		return
	}
	h.attachSeq++
	p.attached = h.attachSeq
	h.peers[p] = true
	h.wg.Add(1)
	onAttach := h.onAttach
	h.mu.Unlock()
	if onAttach != nil {
		onAttach()
	}
	go func() {
		defer h.wg.Done()
		defer p.stop()
		defer func() { h.mu.Lock(); delete(h.peers, p); h.mu.Unlock() }()
		for {
			select {
			case <-p.done:
				return
			case b, ok := <-p.queue:
				// Per-frame deadline: a slow client that keeps draining is
				// never cut off; one that stops reading entirely is.
				c.SetWriteDeadline(time.Now().Add(stallTimeout))
				if !ok {
					_ = w.Send(Finished, p.result)
					return
				}
				if w.Send(Output, b) != nil {
					return
				}
			}
		}
	}()
	defer p.stop()
	for {
		typ, b, err = Read(c)
		if err != nil {
			return
		}
		if typ != Data && typ != Resize {
			return
		}
		if typ == Resize && len(b) != 4 {
			return
		}
		if typ == Data && len(b) > 0 {
			h.noteInput(p) // the typing client paces output
		}
		if err := input(typ, b); err != nil {
			return
		}
	}
}

// Finish delivers the result after queued output, with bounded shutdown time.
// Clients which cannot drain are closed and must report unknown completeness.
func (h *Hub) Finish(r Result) {
	b, err := json.Marshal(r)
	if err != nil {
		panic(fmt.Sprintf("marshal session result: %v", err))
	}
	h.pubMu.Lock()
	defer h.pubMu.Unlock()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	h.result = b
	peers := make([]*peer, 0, len(h.peers))
	for p := range h.peers {
		p.result = b
		close(p.queue)
		peers = append(peers, p)
	}
	h.mu.Unlock()
	done := make(chan struct{})
	go func() { h.wg.Wait(); close(done) }()
	// A slow client still draining its last queued output must receive the
	// final status rather than "completeness unknown", within finalDrain.
	select {
	case <-done:
	case <-time.After(finalDrain):
		for _, p := range peers {
			p.stop()
		}
		<-done
	}
}
