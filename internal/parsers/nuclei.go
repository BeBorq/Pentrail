package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// nuclei -jsonl writes one JSON object per line.
type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
	Type      string `json:"type"`
}

// ParseNucleiJSONL turns nuclei JSONL output into finding entities, one per
// line, with severity, template and the matched location in details.
func ParseNucleiJSONL(data []byte) ([]Entity, error) {
	var out []Entity
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var n nucleiLine
		if err := json.Unmarshal([]byte(line), &n); err != nil {
			continue // skip malformed lines; best-effort over a stream
		}
		if n.TemplateID == "" {
			continue
		}
		name := n.Info.Name
		if name == "" {
			name = n.TemplateID
		}
		out = append(out, Entity{
			Type:  "finding",
			Value: name,
			Details: d(
				"severity", n.Info.Severity,
				"template", n.TemplateID,
				"matched", n.MatchedAt,
				"host", n.Host,
			),
		})
	}
	return out, sc.Err()
}
