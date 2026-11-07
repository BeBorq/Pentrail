package capture

import "strings"

// CMDPrompt returns the PROMPT for a recorded cmd.exe: the authenticated
// prompt marker, closed by BEL, followed by the user's prompt.
//
// Since 0.6.4 a second marker carries the prompt's VISIBLE text
// ("697;<token>;P;<text>"), expanded by cmd from the same $-codes at the
// same moment; the "A" marker itself is unchanged. ConPTY passes the marker through before it paints the text,
// so the marker cannot mark a position; the text lets the segmenter find
// the prompt where it really appears on screen, for any prompt shape.
// Codes that do not produce plain one-line text ($_ new line, $H backspace,
// $E other than a CSI attribute sequence, raw control characters) make the
// visible text unknowable: then the marker has no text and the default
// "X:\path>" shape is used.
func CMDPrompt(token, userPrompt string) string {
	if userPrompt == "" {
		userPrompt = "$P$G"
	}
	marker := "$E]697;" + token + ";A\a"
	if vis, ok := promptVisible(userPrompt); ok && vis != "" {
		marker += "$E]697;" + token + ";P;" + vis + "\a"
	}
	return marker + userPrompt
}

func promptVisible(p string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c < 0x20 || c == 0x7f {
			return "", false
		}
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		if i+1 >= len(p) {
			return "", false
		}
		i++
		code := p[i]
		if code >= 'A' && code <= 'Z' {
			code |= 0x20
		}
		switch code {
		case '_', 'h':
			return "", false
		case 'e':
			// only "$E[<params><final>" (colours, attributes) is dropped
			if i+1 >= len(p) || p[i+1] != '[' {
				return "", false
			}
			j := i + 2
			for j < len(p) && (p[j] < 0x40 || p[j] > 0x7e) {
				if p[j] < 0x20 {
					return "", false
				}
				j++
			}
			if j >= len(p) {
				return "", false
			}
			i = j
		default:
			b.WriteByte('$')
			b.WriteByte(p[i])
		}
	}
	return b.String(), true
}
