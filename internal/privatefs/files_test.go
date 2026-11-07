package privatefs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicPrivateOutputDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	if e := WriteNew(path, []byte("masked report")); e != nil {
		t.Fatal(e)
	}
	if e := WriteNew(path, []byte("replacement")); e == nil {
		t.Fatal("overwritten")
	}
	b, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(b, []byte("masked report")) {
		t.Fatal(string(b), e)
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".pentrail-private-*"))
	if len(left) > 0 {
		t.Fatal(left)
	}
}
