package store

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"
)

func TestCommandBurstIsNotDroppedAndStartIsUpdated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "burst.db")
	key := []byte("synthetic-burst-key")
	st, e := Open(path, key)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := st.StartSession("test", "test", "test")
	var expected bytes.Buffer
	const count = 1536
	for i := 0; i < count; i++ {
		line := []byte(fmt.Sprintf("RESULT_%04d\n", i))
		off := int64(expected.Len())
		st.WriteRaw(id, int64(i), off, line)
		expected.Write(line)
		c := Command{SessionID: id, Index: int64(i), Command: fmt.Sprintf("command_%d", i), StartedAt: 1, ExitCode: -1, OutStartOff: off}
		st.WriteCommand(c)
		c.Complete = true
		c.EndedAt = 2
		c.ExitCode = 0
		c.OutEndOff = off + int64(len(line))
		st.WriteCommand(c)
	}
	if e = st.FinishSession(id); e != nil {
		t.Fatal(e)
	}
	st, e = Open(path, key)
	if e != nil {
		t.Fatal(e)
	}
	defer st.Close()
	cmds, e := st.ListCommands(id)
	if e != nil || len(cmds) != count {
		t.Fatal("commands lost or duplicated", len(cmds), e)
	}
	for _, c := range cmds {
		if !c.Complete || c.ExitCode != 0 {
			t.Fatal("start record not updated", c)
		}
	}
	raw, missing, e := st.ReadRange(id, 0, int64(expected.Len()))
	if e != nil || missing != 0 || !bytes.Equal(raw, expected.Bytes()) {
		t.Fatal("raw mismatch", missing, e)
	}
	t.Logf("reopened_file commands=%d/%d raw_bytes=%d missing=0 exact_match=true", len(cmds), count, len(raw))
}
