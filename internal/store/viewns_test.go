package store

import (
	"path/filepath"
	"sync"
	"testing"
)

// Codex 04J: the viewer's namespace for a database — stable across
// reopen, different for another database (even with the same sessions),
// random (no path, key or token in it).
func TestViewNamespace(t *testing.T) {
	dir := t.TempDir()
	open := func(name string) *Store {
		st, err := Open(filepath.Join(dir, name), []byte("synthetic-ns-key"))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	a := open("a.db")
	nsA := a.ViewNamespace()
	if !validNamespace(nsA) {
		t.Fatalf("namespace %q", nsA)
	}
	a.Close()
	a2 := open("a.db")
	if a2.ViewNamespace() != nsA {
		t.Fatalf("reopened: %q, first open %q", a2.ViewNamespace(), nsA)
	}
	a2.Close()
	b := open("b.db")
	defer b.Close()
	if b.ViewNamespace() == nsA {
		t.Fatal("two databases share a namespace")
	}
	for _, leak := range []string{dir, "a.db", "synthetic-ns-key", a2.Identity()} {
		if leak != "" && (nsA == leak || len(leak) >= 8 && contains(nsA, leak)) {
			t.Fatalf("namespace contains %q", leak)
		}
	}
	// concurrent first opens of one new database agree
	c1, err := Open(filepath.Join(dir, "c.db"), []byte("synthetic-ns-key"))
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	var wg sync.WaitGroup
	got := make([]string, 4)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st, err := Open(filepath.Join(dir, "c.db"), []byte("synthetic-ns-key"))
			if err != nil {
				t.Error(err)
				return
			}
			got[i] = st.ViewNamespace()
			st.Close()
		}(i)
	}
	wg.Wait()
	for _, g := range got {
		if g != c1.ViewNamespace() {
			t.Fatalf("namespaces of one database differ: %q vs %q", g, c1.ViewNamespace())
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
