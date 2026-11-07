package parsers

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// ffuf -o out.json writes a single JSON object with a "results" array.
type ffufFile struct {
	Results []struct {
		URL         string            `json:"url"`
		Status      int               `json:"status"`
		Length      int               `json:"length"`
		Words       int               `json:"words"`
		Lines       int               `json:"lines"`
		ContentType string            `json:"content-type"`
		RedirectLoc string            `json:"redirectlocation"`
		Input       map[string]string `json:"input"`
	} `json:"results"`
}

// ParseFfufJSON turns ffuf JSON output into endpoint entities (one per hit),
// with status code and size in details.
func ParseFfufJSON(data []byte) ([]Entity, error) {
	var f ffufFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("ffuf json: %w", err)
	}
	var out []Entity
	for _, r := range f.Results {
		if r.URL == "" {
			continue
		}
		out = append(out, Entity{
			Type:  "endpoint",
			Value: r.URL,
			Details: d(
				"status", strconv.Itoa(r.Status),
				"length", strconv.Itoa(r.Length),
				"content_type", r.ContentType,
				"redirect", r.RedirectLoc,
			),
		})
	}
	return out, nil
}
