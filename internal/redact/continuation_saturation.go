package redact

import "bytes"

// Upper bound on score when the row has the same visible-byte map for every
// candidate. Mirrors line's CSI visibility, not any secret rule. mask cannot
// turn CR/LF into '*', and bytes already '*' cannot contribute to score.
func continuationMaskUpper(b []byte) int {
	n := 0
	for i := 0; i < len(b); i++ {
		if b[i] == 27 && i+1 < len(b) && b[i+1] == '[' {
			j := i + 2
			for j < len(b) && (b[j] < 0x40 || b[j] > 0x7e) {
				j++
			}
			if j < len(b) {
				i = j
				continue
			}
		}
		if b[i] != '*' && b[i] != '\r' && b[i] != '\n' {
			n++
		}
	}
	return n
}

// Called only for a row starting with a complete cursor CSI. An unfinished
// prefix CSI could consume part of that row CSI, exposing different bytes;
// decline the shortcut if ANY eligible overlap ends inside such a sequence.
// OSC processing is deliberately excluded. Normal/standalone-ESC prefix states
// leave the initial complete row CSI and all subsequent row bytes unchanged.
func continuationSaturationSafe(context, row, head []byte) bool {
	if bytes.Contains(context, []byte("\x1b]")) || bytes.Contains(row, []byte("\x1b]")) {
		return false
	}
	if continuationPlainSuffix(context, 64) {
		return true
	}
	var ends [65]bool
	limit := min(64, min(len(head), len(context)))
	ends[0] = true
	for overlap := 1; overlap <= limit; overlap++ {
		ends[overlap] = bytes.Equal(context[len(context)-overlap:], head[:overlap])
	}
	state := 0 // normal, standalone ESC, CSI
	for i, c := range context {
		switch state {
		case 0:
			if c == 27 {
				state = 1
			}
		case 1:
			if c == '[' {
				state = 2
			} else if c != 27 {
				state = 0
			}
		case 2:
			if c >= 0x40 && c <= 0x7e {
				state = 0
			}
		}
		overlap := len(context) - (i + 1)
		if overlap <= limit && ends[overlap] && state == 2 {
			return false
		}
	}
	return true
}

// Every possible cut lies after this suffix's first byte. That byte closes
// any earlier CSI, and the remaining printable ASCII bytes cannot open one.
// Thus all the cut positions are normal and the last tail bytes are visible.
func continuationPlainSuffix(context []byte, tail int) bool {
	start := len(context) - tail - 1
	if start < 0 {
		return false
	}
	for extra := 0; extra < 32 && start > 0 && (context[start] < 0x40 || context[start] > 0x7e); extra++ {
		start--
	}
	if context[start] < 0x40 || context[start] > 0x7e {
		return false
	}
	for _, c := range context[start:] {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
