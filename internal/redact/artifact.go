package redact

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// Artifact sanitizes structured files field by field; a large single-line JSON
// or XML document must retain its structure rather than hit the PTY line cap.
// Damaged input with a valid beginning is handled fail-closed (see
// ArtifactPartial); input with nothing valid at all is an error.
func Artifact(tool string, data []byte) ([]byte, error) {
	out, _, err := ArtifactPartial(tool, data)
	return out, err
}

// ArtifactPartial is Artifact that also reports whether part of the input was
// malformed. Tools are routinely interrupted (Ctrl-C on nmap leaves XML without
// its closing tags; a killed nuclei leaves a half-written JSONL line). Rejecting
// such a file used to make every ingest fail forever: `pentrail serve`, `open`,
// `report`, `export` and `parse` all stopped working and the plaintext scan file
// stayed on disk. Now the well-formed part keeps structured, field-aware
// masking and the malformed remainder is masked completely: nothing is
// published unsanitized, and the valid evidence before the break survives.
// A file with no valid part at all (nothing to salvage) is still an error, so
// the caller can leave the original for manual handling.
func ArtifactPartial(tool string, data []byte) (out []byte, partial bool, err error) {
	switch tool {
	case "ffuf":
		// One JSON document: there is no record boundary to salvage from.
		safe, e := JSON(data)
		return safe, false, e
	case "nuclei":
		var buf bytes.Buffer
		valid := 0
		for _, raw := range bytes.Split(data, []byte("\n")) {
			if len(bytes.TrimSpace(raw)) == 0 {
				continue
			}
			safe, e := JSON(raw)
			if e != nil {
				safe = append([]byte(nil), raw...)
				mask(safe)
				partial = true
			} else {
				valid++
			}
			buf.Write(safe)
			buf.WriteByte('\n')
		}
		if partial && valid == 0 {
			return nil, false, fmt.Errorf("nuclei jsonl: no valid record")
		}
		return buf.Bytes(), partial, nil
	case "nmap":
		return nmapXML(data)
	default:
		return nil, false, fmt.Errorf("unsupported artifact tool: %s", tool)
	}
}

func nmapXML(data []byte) ([]byte, bool, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	var out bytes.Buffer
	e := xml.NewEncoder(&out)
	var secret []bool
	var consumed int64 // input bytes fully represented in out
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			if consumed == 0 {
				return nil, false, fmt.Errorf("nmap xml: %w", err) // nothing to salvage
			}
			// Truncated or corrupt: keep the sanitized prefix, mask the rest.
			if ferr := e.Flush(); ferr != nil {
				return nil, false, ferr
			}
			if consumed < int64(len(data)) {
				tail := append([]byte(nil), data[consumed:]...)
				mask(tail)
				out.Write(tail)
			}
			return out.Bytes(), true, nil
		}
		switch t := token.(type) {
		case xml.StartElement:
			hidden := sensitive(t.Name.Local)
			if len(secret) > 0 && secret[len(secret)-1] {
				hidden = true
			}
			for i := range t.Attr {
				a := &t.Attr[i]
				if (a.Name.Local == "key" || a.Name.Local == "name") && sensitive(a.Value) {
					hidden = true
				}
				if sensitive(a.Name.Local) {
					a.Value = strings.Repeat("*", len([]byte(a.Value)))
				} else {
					a.Value = String(a.Value)
				}
			}
			secret = append(secret, hidden)
			token = t
		case xml.EndElement:
			if len(secret) > 0 {
				secret = secret[:len(secret)-1]
			}
		case xml.CharData:
			if len(secret) > 0 && secret[len(secret)-1] {
				safe := append([]byte(nil), t...)
				mask(safe)
				token = xml.CharData(safe)
			} else {
				token = xml.CharData([]byte(String(string(t))))
			}
		}
		if err := e.EncodeToken(token); err != nil {
			return nil, false, err
		}
		consumed = d.InputOffset()
	}
	if err := e.Flush(); err != nil {
		return nil, false, err
	}
	return out.Bytes(), false, nil
}
