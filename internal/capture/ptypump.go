package capture

import "io"

// ptyPump reads the PTY ahead in its own goroutine (Codex 04F). While one
// batch is being made durable (the encrypted store commits every write with
// synchronous=FULL before anything is shown), the shell's output keeps
// flowing into a bounded queue instead of waiting in the PTY; the next batch
// then takes everything already read, up to max bytes, and commits it in
// ONE transaction. Nothing changes in what is stored, in what order, or
// that it is stored before it is shown: a batch is published only after its
// write returned, exactly as a single read was before. Bytes read but not
// yet written were never shown (as bytes in the PTY buffer before). When
// the output is idle a batch is a single read: no added latency.
type ptyPump struct {
	ch   chan pumpChunk
	done chan struct{}
	held *pumpChunk // read, did not fit into the previous batch
	err  error      // seen after the data of the previous batch
}

type pumpChunk struct {
	b   []byte
	err error
}

// pumpQueue chunks of at most 32 KiB may wait (bounded memory: 512 KiB).
const pumpQueue = 16

func newPTYPump(r io.Reader) *ptyPump {
	p := &ptyPump{ch: make(chan pumpChunk, pumpQueue), done: make(chan struct{})}
	go func() {
		for {
			buf := make([]byte, 32*1024)
			n, err := r.Read(buf)
			if n > 0 {
				select {
				case p.ch <- pumpChunk{b: buf[:n]}:
				case <-p.done:
					return
				}
			}
			if err != nil {
				select {
				case p.ch <- pumpChunk{err: err}:
				case <-p.done:
				}
				return
			}
		}
	}()
	return p
}

// take returns the next chunk: the held remainder first, else the next one
// read (waiting for it).
func (p *ptyPump) take() pumpChunk {
	if p.held != nil {
		c := *p.held
		p.held = nil
		return c
	}
	return <-p.ch
}

// next returns the next batch: the first available chunk (waiting for it)
// plus the chunks already queued — at most max bytes, strictly: a chunk
// that does not fit is split and its remainder starts the next batch (a
// single read can be 32 KiB). An error is returned only after all data read
// before it.
func (p *ptyPump) next(max int) ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	first := p.take()
	if first.err != nil {
		p.err = first.err
		return nil, first.err
	}
	if len(first.b) > max {
		p.held = &pumpChunk{b: first.b[max:]}
		return first.b[:max], nil
	}
	out := first.b
	for len(out) < max {
		var c pumpChunk
		select {
		case c = <-p.ch:
		default:
			return out, nil
		}
		if c.err != nil {
			p.err = c.err // after this batch
			return out, nil
		}
		if len(out) == len(first.b) {
			out = append(make([]byte, 0, max), out...)
		}
		if room := max - len(out); len(c.b) > room {
			out = append(out, c.b[:room]...)
			p.held = &pumpChunk{b: c.b[room:]}
			return out, nil
		}
		out = append(out, c.b...)
	}
	return out, nil
}

// nextRead returns exactly one PTY read, as the loop before 04F wrote it
// (TestPumpKeepsSessionResponsive's comparison mode; pumpOneReadPerWrite).
func (p *ptyPump) nextRead() ([]byte, error) {
	if p.err != nil {
		return nil, p.err
	}
	c := p.take()
	if c.err != nil {
		p.err = c.err
		return nil, c.err
	}
	return c.b, nil
}

// stop ends the reader goroutine if it is waiting to hand over a chunk.
func (p *ptyPump) stop() { close(p.done) }
