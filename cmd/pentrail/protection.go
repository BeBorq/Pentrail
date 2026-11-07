package main

import (
	"errors"
	"fmt"
	"github.com/BeBorq/Pentrail/internal/background"
	"github.com/BeBorq/Pentrail/internal/store"
	"path/filepath"
	"time"
)

func cmdBackup(args []string) error {
	if !store.Encrypted() {
		return errors.New("backup requires SQLCipher")
	}
	unlock, e := background.Lock()
	if e != nil {
		return e
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	state, e := userState()
	if e != nil {
		return e
	}
	db, args := flagValue(args, "--db", state.Database)
	out, _ := flagValue(args, "--out", "")
	if out == "" {
		token, e := newToken()
		if e != nil {
			return e
		}
		out = filepath.Join(filepath.Dir(db), "backups", "pentrail-"+time.Now().Format("20060102-150405")+"-"+token[:8]+".db")
	}
	if e = controlAll(db, "flush"); e != nil {
		return fmt.Errorf("could not flush active sessions: %w", e)
	}
	unlock()
	unlock = nil
	key, e := getPassphrase()
	if e != nil {
		return e
	}
	defer zero(key)
	digest, e := store.BackupFile(db, out, key)
	if e != nil {
		return e
	}
	fmt.Printf("encrypted backup verified: %s\nsha256=%s\n", out, digest)
	return nil
}
func cmdVerify(args []string) error {
	s, e := userState()
	if e != nil {
		return e
	}
	file, _ := flagValue(args, "--file", s.Database)
	key, e := getPassphrase()
	if e != nil {
		return e
	}
	defer zero(key)
	if e = store.VerifyFile(file, key); e != nil {
		return e
	}
	fmt.Println("encrypted database integrity: OK")
	return nil
}

func selectDatabaseForStart(db string, key []byte) error {
	s, e := userState()
	if e != nil {
		return e
	}
	if sameDatabase(s.Database, db) {
		return nil
	}
	if s.Enabled {
		return errors.New("disable recording before changing projects")
	}
	if e = checkNoRecordingSessions(s.Database); e != nil {
		return e
	}
	st, e := store.Open(db, key)
	if e != nil {
		return e
	}
	if e = st.Close(); e != nil {
		return e
	}
	s.Database = db
	return background.Save(s)
}

func cmdFlush(args []string) error {
	unlock, e := background.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	state, e := userState()
	if e != nil {
		return e
	}
	db, _ := flagValue(args, "--db", state.Database)
	if e = controlAll(db, "flush"); e != nil {
		return fmt.Errorf("recording flush failed: %w", e)
	}
	fmt.Println("pentrail: recording queues committed to database files")
	return nil
}
