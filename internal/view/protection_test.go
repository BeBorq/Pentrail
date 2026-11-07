package view

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestJSONMasksLegacyCommandAndNestedFields(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, map[string]any{"command": "tool --password viewSecret", "details": "{\"api_key\":\"viewSecret\"}"})
	if strings.Contains(w.Body.String(), "viewSecret") || !strings.Contains(w.Body.String(), "***") || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Body.String(), w.Header())
	}
}
