package capture

import (
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"time"
)

// Parser is Layer 3's real-time front half: it watches the output byte stream
// go past and recognises shell-integration markers to segment commands.
//
// It is strictly BEST-EFFORT and strictly observational. It never alters, holds
// up, or depends on the raw bytes. When markers are absent (ssh, msfconsole, a
// subshell that didn't load the hook) it simply emits nothing and the raw log
// still has every byte. A panic here is caught by the caller and parsing is
// disabled for the rest of the session — the terminal keeps working.
//
// Markers are AUTHENTICATED with a per-session token the hook receives in its
// environment and embeds in every marker. The token is a local secret: the
// hook writes markers to the local PTY, never to the remote peer, so output
// from a scanned host (or any tool) cannot forge a marker without the token.
// A marker with the wrong (or no) token is ignored — only the raw bytes are
// kept. Bare OSC 133 is treated as untrusted and ignored.
//
// Marker grammar (payload between OSC `ESC ]` and ST `BEL`/`ESC \`):
//
//	697;<tok>;A              prompt start
//	697;<tok>;C              command output start
//	697;<tok>;D;<N>          command end, exit code N
//	697;<tok>;CMD;<base64>   exact command line
//	697;<tok>;CWD;<path>     working directory
//	697;<tok>;ART;<tool>;<path>  structured-output artifact
type Parser struct {
	onPrompt   func(int64)
	onStart    func(CommandEvent)
	onCommand  func(CommandEvent)
	onArtifact func(tool, path string, cmdIndex int64) // ART marker (tool produced a file)
	onFinalize func(path string)                       // FIN marker (producer finished writing)
	now        func() int64
	token      string // expected per-session marker token

	// byte-stream scanner state (persists across Feed calls so markers split
	// over read boundaries are handled correctly)
	inOsc     bool
	pendingST bool
	oscBuf    []byte
	escStart  int64 // global offset of the ESC that opened the current OSC
	prevEsc   bool  // last byte (across calls) was a bare ESC

	// command assembly state
	cur      CommandEvent
	outOpen  bool
	haveData bool
	index    int64
}

// CommandEvent is a fully-observed command, handed to the caller to persist.
type CommandEvent struct {
	Index       int64
	Command     string
	Cwd         string
	StartedAt   int64
	EndedAt     int64
	ExitCode    int64
	OutStartOff int64
	OutEndOff   int64
	Complete    bool
	EndReason   string // non-empty: end not observed (see store.Command)
}

const oscMaxLen = 8192

// NewParser builds a parser that accepts only markers carrying token. onArtifact
// fires when a wrapped tool announces an output file (ART); onFinalize fires when
// that tool has finished writing it (FIN). Either callback may be nil.
func NewParser(token string, onCommand func(CommandEvent), onArtifact func(tool, path string, cmdIndex int64), onFinalize func(path string)) *Parser {
	return &Parser{token: token, onCommand: onCommand, onArtifact: onArtifact, onFinalize: onFinalize, now: func() int64 { return time.Now().UnixNano() }}
}

// Feed advances the parser over data, whose first byte sits at global offset
// CloseOpen closes a command whose output is still open (C seen, no D) at
// output offset off: on EOF (the shell ended, e.g. `exit` or a closed
// terminal) and when recording is paused. Its end was not observed, so it is
// recorded as incomplete with unknown exit status and the reason; the range
// up to off keeps everything that was captured.
func (p *Parser) CloseOpen(off int64, reason string) {
	if !p.outOpen {
		return
	}
	p.cur.EndedAt = p.now()
	if off > p.cur.OutStartOff {
		p.cur.OutEndOff = off
	}
	p.cur.ExitCode = -1
	p.cur.Complete = false
	p.cur.EndReason = reason
	if p.onCommand != nil {
		p.onCommand(p.cur)
	}
	p.reset()
}

// DiscardBoundary prevents one command spanning a recording pause while keeping
// command indices monotonic within the session.
func (p *Parser) DiscardBoundary() {
	p.reset()
	p.inOsc = false
	p.pendingST = false
	p.prevEsc = false
	p.oscBuf = p.oscBuf[:0]
}

// Feed advances the parser over data, whose first byte sits at global offset
// baseOffset in the session output stream.
func (p *Parser) Feed(data []byte, baseOffset int64) {
	for i := 0; i < len(data); i++ {
		off := baseOffset + int64(i)
		c := data[i]

		if p.inOsc {
			p.scanOsc(c, off)
			continue
		}

		// not in an OSC
		if p.prevEsc {
			p.prevEsc = false
			if c == ']' {
				p.inOsc = true
				p.pendingST = false
				p.oscBuf = p.oscBuf[:0]
				// ESC was the byte before c; its offset is off-1
				p.escStart = off - 1
				continue
			}
			// some other escape sequence (cursor move, color, ...) — ignore
		}
		if c == 0x1b {
			p.prevEsc = true
		}
	}
}

func (p *Parser) scanOsc(c byte, off int64) {
	// terminators: BEL, or ST = ESC '\'
	if p.pendingST {
		p.pendingST = false
		if c == '\\' {
			p.finishOsc(off) // ST is two bytes; terminator ends here
			return
		}
		// it was a lone ESC inside the payload; keep both
		p.oscBuf = append(p.oscBuf, 0x1b, c)
	} else if c == 0x07 {
		p.finishOsc(off)
		return
	} else if c == 0x1b {
		p.pendingST = true
		return
	} else {
		p.oscBuf = append(p.oscBuf, c)
	}

	if len(p.oscBuf) > oscMaxLen {
		// not a real marker; bail out and resync
		p.inOsc = false
		p.pendingST = false
		p.oscBuf = p.oscBuf[:0]
	}
}

// finishOsc is called when the OSC terminator at offset off has been consumed.
// markerStart = p.escStart, markerEnd = off+1.
func (p *Parser) finishOsc(off int64) {
	payload := string(p.oscBuf)
	markerStart := p.escStart
	markerEnd := off + 1
	p.inOsc = false
	p.pendingST = false
	p.oscBuf = p.oscBuf[:0]

	// Only our authenticated 697 markers are acted on. Everything else —
	// including bare OSC 133 that untrusted output could emit — is ignored.
	const pfx = "697;"
	if !strings.HasPrefix(payload, pfx) {
		return
	}
	rest := payload[len(pfx):]
	semi := strings.IndexByte(rest, ';')
	if semi < 0 {
		return
	}
	tok := rest[:semi]
	if subtle.ConstantTimeCompare([]byte(tok), []byte(p.token)) != 1 {
		return // wrong or missing token: a forged marker — ignore
	}
	rest = rest[semi+1:]
	verb, arg := rest, ""
	if s := strings.IndexByte(rest, ';'); s >= 0 {
		verb, arg = rest[:s], rest[s+1:]
	}

	switch verb {
	case "A":
		p.reset() // new prompt; discard any half-built, never-run command
		if p.onPrompt != nil {
			p.onPrompt(markerStart)
		}
	case "B":
		// user input region start — nothing to record
	case "C":
		p.cur.Index = p.index
		p.index++
		p.cur.ExitCode = -1
		p.cur.StartedAt = p.now()
		p.cur.OutStartOff = markerEnd
		p.outOpen = true
		p.haveData = true
		p.cur.OutEndOff = markerEnd
		if p.onStart != nil {
			p.onStart(p.cur)
		}
	case "D":
		p.cur.ExitCode = parseExitArg(arg)
		p.cur.EndedAt = p.now()
		p.cur.OutEndOff = markerStart
		p.cur.Complete = true
		if p.haveData {
			if !p.outOpen {
				p.cur.Index = p.index
				p.index++
			}
			if p.onCommand != nil {
				p.onCommand(p.cur)
			}
		}
		p.reset()
	case "CMD":
		if dec, err := base64.StdEncoding.DecodeString(arg); err == nil {
			p.cur.Command = string(dec)
			p.haveData = true
		}
	case "CWD":
		p.cur.Cwd = arg
		p.haveData = true
	case "ART":
		// arg: <tool>;<path>  (path may itself contain ';'). Recorded immediately
		// (not finalized yet) so background jobs are tracked even after their
		// command's D marker. p.index is the index this command will be assigned.
		if i := strings.IndexByte(arg, ';'); i >= 0 {
			tool, path := arg[:i], arg[i+1:]
			if tool != "" && path != "" && p.onArtifact != nil {
				idx := p.index
				if p.outOpen {
					idx = p.cur.Index
				}
				p.onArtifact(tool, path, idx)
			}
		}
	case "FIN":
		// arg: <path>  — the producing tool has finished writing the file.
		if arg != "" && p.onFinalize != nil {
			p.onFinalize(arg)
		}
	}
}

func (p *Parser) reset() {
	p.cur = CommandEvent{}
	p.outOpen = false
	p.haveData = false
}

func parseExitArg(arg string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(arg), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
