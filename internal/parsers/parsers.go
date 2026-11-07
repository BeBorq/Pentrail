// Package parsers is the high-confidence half of Layer 3: it turns a tool's
// STRUCTURED output (nmap XML, ffuf JSON, nuclei JSONL) into typed entities.
// Unlike the regex pass, a structured parser knows exactly what each field is,
// so these entities carry confidence "high" and rich details (port state,
// service/version, finding severity).
//
// Each parser is a pure function: bytes in, entities out. No I/O, no database —
// trivially testable and safe to re-run over an old capture.
package parsers

import "fmt"

// Entity is a parser-level result. The store maps it to a row with provenance.
type Entity struct {
	Type    string            // host, hostname, port, endpoint, finding
	Value   string            // canonical value
	Details map[string]string // optional structured attributes
}

// Tool names pentrail recognizes for structured parsing.
const (
	ToolNmap   = "nmap"
	ToolFfuf   = "ffuf"
	ToolNuclei = "nuclei"
)

// Parse dispatches to the right parser by tool name.
func Parse(tool string, data []byte) ([]Entity, error) {
	switch tool {
	case ToolNmap:
		return ParseNmapXML(data)
	case ToolFfuf:
		return ParseFfufJSON(data)
	case ToolNuclei:
		return ParseNucleiJSONL(data)
	default:
		return nil, fmt.Errorf("no structured parser for tool %q", tool)
	}
}

// Supported reports whether a tool has a structured parser.
func Supported(tool string) bool {
	switch tool {
	case ToolNmap, ToolFfuf, ToolNuclei:
		return true
	}
	return false
}

func d(kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	return m
}
