//go:build windows

package capture

// Filter only the detach key; all other original Win32/VT bytes are preserved.
type detachFilter struct{ pending []byte }

func (f *detachFilter) Feed(b []byte) (out []byte, detached bool) {
	for _, v := range b {
		if len(f.pending) == 0 {
			if v == detachByte {
				return out, true
			}
			if v == 27 {
				f.pending = append(f.pending, v)
			} else {
				out = append(out, v)
			}
			continue
		}
		f.pending = append(f.pending, v)
		if len(f.pending) == 2 && v != '[' {
			out = append(out, f.pending...)
			f.pending = nil
			continue
		}
		if len(f.pending) > 128 {
			out = append(out, f.pending...)
			f.pending = nil
			continue
		}
		if len(f.pending) > 2 && v >= 0x40 && v <= 0x7e {
			if v == '_' {
				decoder := winInputDecoder{}
				decoded := decoder.Decode(f.pending)
				if indexByte(decoded, detachByte) >= 0 {
					f.pending = nil
					return out, true
				}
			}
			out = append(out, f.pending...)
			f.pending = nil
		}
	}
	return out, false
}
func (f *detachFilter) Flush() []byte { out := f.pending; f.pending = nil; return out }
