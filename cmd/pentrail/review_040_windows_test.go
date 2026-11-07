//go:build windows

package main

import (
	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/dbidentity"
	"github.com/BeBorq/Pentrail/internal/localipc"
	"github.com/BeBorq/Pentrail/internal/sessionio"
	"github.com/BeBorq/Pentrail/internal/store"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReview040StatusMustNotListOtherDatabase(t *testing.T) {
	home := reviewHome(t)
	a := filepath.Join(home, "a.db")
	b := filepath.Join(home, "b.db")
	run := filepath.Join(home, "run")
	os.MkdirAll(run, 0700)
	path := filepath.Join(run, "0123456789abcdef.sock")
	l, e := localipc.Listen(path)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	hub := sessionio.NewHub()
	hub.SetControl(func(string) (sessionio.ControlState, error) {
		return sessionio.ControlState{SessionID: 77, Recording: true, DatabaseID: dbidentity.ID(b)}, nil
	})
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go hub.ServeConn(c, func(byte, []byte) error { return nil })
		}
	}()
	background.Save(background.State{Database: a})
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	e = cmdStatus()
	w.Close()
	os.Stdout = old
	data, _ := io.ReadAll(r)
	r.Close()
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(data), "session=77 recording=true") {
		t.Fatalf("status for database A lists database B: %s", data)
	}
}
func TestReview040ReportMustPropagateExtractionFailure(t *testing.T) {
	st, e := store.Open(filepath.Join(t.TempDir(), "data.db"), []byte("synthetic-key"))
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	id, e := st.StartSession("bash", "test", "test")
	if e != nil {
		t.Fatal(e)
	}
	_, e = st.DB().Exec("INSERT INTO commands(session_id,cmd_index,command,out_start_off,out_end_off,complete) VALUES(?,0,'echo',0,10,1)", id)
	if e != nil {
		t.Fatal(e)
	}
	_, e = st.DB().Exec("INSERT INTO raw_chunks(session_id,seq,byte_offset,ts,data) VALUES(?,0,0,0,?)", id, []byte("192.0.2.1\n"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = st.DB().Exec("CREATE TRIGGER review_failure BEFORE INSERT ON entities BEGIN SELECT RAISE(FAIL,'review extraction failed'); END")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = st.ExtractRegex(id); e == nil {
		t.Fatal("fault injection did not trigger")
	}
	if _, e = assembleBundle(st, id); e == nil {
		t.Fatal("report assembly returned success despite extraction failure")
	}
}
