package view

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/BeBorq/Pentrail/internal/store"
)

// Operator notes API. The evidence stays read-only; notes are the only thing
// the viewer writes. Reads go through guard (loopback Host, same-origin Origin,
// session token). Every change additionally needs (mutation):
//   - POST or PUT (never GET), checked per route;
//   - an Origin header naming exactly this viewer (a browser sends it on every
//     POST/PUT), and Sec-Fetch-Site same-origin when the browser sends it;
//   - Content-Type application/json;
//   - the X-Pentrail-Write header with the write token. The page reads it from
//     /api/notes/token (guarded, no-store); another site cannot read it, as
//     there is no CORS and guard rejects foreign origins;
//   - a body of at most noteRequestMax bytes, with no unknown fields.
// No CORS headers are ever sent.

const noteRequestMax = store.NoteBodyMax + store.NoteTitleMax + store.NoteNodeIDMax + 4096

// writeToken is derived from the session token: it changes with every viewer
// start and is never part of a URL.
func (s *Server) writeToken() string {
	m := hmac.New(sha256.New, []byte(s.token))
	m.Write([]byte("pentrail notes write v1"))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) mutation(methods string, next http.HandlerFunc) http.HandlerFunc {
	return s.guard(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(" "+methods+" ", " "+r.Method+" ") {
			w.Header().Set("Allow", methods)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		o := r.Header.Get("Origin")
		u, err := url.Parse(o)
		if o == "" || err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
			http.Error(w, "a change needs a same-origin request", http.StatusForbidden)
			return
		}
		if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" {
			http.Error(w, "a change needs a same-origin request", http.StatusForbidden)
			return
		}
		if !tokenOK(r.Header.Get("X-Pentrail-Write"), s.writeToken()) {
			http.Error(w, "missing or wrong write token", http.StatusForbidden)
			return
		}
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
		if r.ContentLength > noteRequestMax {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, noteRequestMax)
		next(w, r)
	})
}

func decodeNoteRequest(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return false
	}
	return true
}

func writeNoteError(w http.ResponseWriter, n store.Note, err error) {
	switch {
	case errors.Is(err, store.ErrNoteConflict):
		writeJSONCode(w, http.StatusConflict, map[string]any{"error": "conflict", "current": n})
	case errors.Is(err, store.ErrNoteNotFound):
		http.Error(w, "note not found", http.StatusNotFound)
	case errors.Is(err, store.ErrNoteInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, "the note could not be saved", http.StatusInternalServerError)
	}
}

func (s *Server) handleNotesToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Not through writeJSON: its secret masking hides any value of a "token" key.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	b, _ := json.Marshal(map[string]string{"write_token": s.writeToken()})
	_, _ = w.Write(b)
}

// /api/notes: GET ?session=N lists; POST creates.
func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		id, err := strconv.ParseInt(r.URL.Query().Get("session"), 10, 64)
		if err != nil {
			http.Error(w, "bad session", 400)
			return
		}
		notes, err := s.st.ListNotes(id)
		if err != nil {
			http.Error(w, "could not read the notes", 500)
			return
		}
		writeJSON(w, notes)
		return
	}
	s.mutation("POST", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Session int64            `json:"session"`
			Anchor  store.NoteAnchor `json:"anchor"`
			Title   string           `json:"title"`
			Body    string           `json:"body"`
		}
		if !decodeNoteRequest(w, r, &req) {
			return
		}
		n, err := s.st.CreateNote(req.Session, req.Anchor, req.Title, req.Body)
		if err != nil {
			writeNoteError(w, n, err)
			return
		}
		writeJSONCode(w, http.StatusCreated, n)
	})(w, r)
}

// /api/notes/<id> (PUT: title and text) and /api/notes/<id>/archive (POST).
func (s *Server) handleNote(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/notes/")
	id, action, _ := strings.Cut(rest, "/")
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" || (action != "" && action != "archive") {
		http.NotFound(w, r)
		return
	}
	if action == "" {
		s.mutation("PUT", func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Session  int64  `json:"session"`
				Revision int64  `json:"revision"`
				Title    string `json:"title"`
				Body     string `json:"body"`
			}
			if !decodeNoteRequest(w, r, &req) {
				return
			}
			n, err := s.st.UpdateNote(req.Session, id, req.Revision, req.Title, req.Body)
			if err != nil {
				writeNoteError(w, n, err)
				return
			}
			writeJSON(w, n)
		})(w, r)
		return
	}
	s.mutation("POST", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Session  int64 `json:"session"`
			Revision int64 `json:"revision"`
			Archived bool  `json:"archived"`
		}
		if !decodeNoteRequest(w, r, &req) {
			return
		}
		n, err := s.st.SetNoteArchived(req.Session, id, req.Revision, req.Archived)
		if err != nil {
			writeNoteError(w, n, err)
			return
		}
		writeJSON(w, n)
	})(w, r)
}
