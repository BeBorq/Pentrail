//go:build windows

package capture

import (
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ConPTY's mode 9001 sends Win32 key records rather than plain UTF-8. Decode
// only for the best-effort CMD observer; original bytes still reach the shell.
type winInputDecoder struct {
	esc  []byte
	high uint16
}

func (d *winInputDecoder) Decode(b []byte) []byte {
	var out []byte
	for _, v := range b {
		if len(d.esc) == 0 {
			if v == 27 {
				d.esc = append(d.esc, v)
			} else {
				out = append(out, v)
			}
			continue
		}
		d.esc = append(d.esc, v)
		if len(d.esc) == 2 && v != '[' {
			out = append(out, 27)
			d.esc = nil
			continue
		}
		if len(d.esc) > 128 {
			out = append(out, 27)
			d.esc = nil
			continue
		}
		if v >= 0x40 && v <= 0x7e && len(d.esc) > 2 {
			if v != '_' {
				out = append(out, 27)
				d.esc = nil
				continue
			}
			parts := strings.Split(string(d.esc[2:len(d.esc)-1]), ";")
			d.esc = nil
			if len(parts) != 6 {
				out = append(out, 27)
				continue
			}
			vals := [6]int{0, 0, 0, 0, 0, 1}
			valid := true
			for i, s := range parts {
				if s != "" {
					n, e := strconv.Atoi(s)
					if e != nil || n < 0 || n > 65535 {
						valid = false
						break
					}
					vals[i] = n
				}
			}
			if !valid {
				out = append(out, 27)
				continue
			}
			if vals[3] == 0 {
				continue
			}
			u := uint16(vals[2])
			if u == 0 {
				if vals[0] != 16 && vals[0] != 17 && vals[0] != 18 {
					out = append(out, 27)
				}
				continue
			}
			if u >= 0xd800 && u <= 0xdbff {
				d.high = u
				continue
			}
			r := rune(u)
			if u >= 0xdc00 && u <= 0xdfff && d.high != 0 {
				r = utf16.DecodeRune(rune(d.high), r)
				d.high = 0
			} else if d.high != 0 {
				d.high = 0
				out = append(out, 27)
			}
			repeat := vals[5]
			if repeat > 64 {
				out = append(out, 27)
				continue
			}
			for i := 0; i < repeat; i++ {
				out = utf8.AppendRune(out, r)
			}
		}
	}
	return out
}
