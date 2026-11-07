package capture

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

type chunkReader struct {
	chunks [][]byte
	err    error
	gate   chan struct{} // each Read waits for a token (nil: no waiting)
}

func (r *chunkReader) Read(b []byte) (int, error) {
	if r.gate != nil {
		<-r.gate
	}
	if len(r.chunks) == 0 {
		return 0, r.err
	}
	n := copy(b, r.chunks[0])
	r.chunks = r.chunks[1:]
	return n, nil
}

// Every byte in order, error only after the data, batches never above max,
// and an idle stream gives single reads at once.
func TestPTYPumpOrderBatchesAndEOF(t *testing.T) {
	var want bytes.Buffer
	var chunks [][]byte
	for i := 0; i < 200; i++ {
		c := bytes.Repeat([]byte{byte('a' + i%26)}, 1+i*37%4000)
		chunks = append(chunks, c)
		want.Write(c)
	}
	r := &chunkReader{chunks: chunks, err: io.EOF}
	p := newPTYPump(r)
	defer p.stop()
	time.Sleep(50 * time.Millisecond) // let the reader queue chunks
	var got bytes.Buffer
	batches := 0
	for {
		b, err := p.next(20000)
		if len(b) > 20000 {
			t.Fatalf("batch of %d bytes > max", len(b))
		}
		got.Write(b)
		if err != nil {
			if !errors.Is(err, io.EOF) || len(b) != 0 {
				t.Fatalf("err %v with %d bytes", err, len(b))
			}
			break
		}
		batches++
	}
	if !bytes.Equal(got.Bytes(), want.Bytes()) {
		t.Fatalf("bytes differ: %d vs %d", got.Len(), want.Len())
	}
	if batches >= len(chunks) {
		t.Fatalf("no coalescing: %d batches for %d reads", batches, len(chunks))
	}
	if _, err := p.next(20000); !errors.Is(err, io.EOF) {
		t.Fatalf("after EOF: %v", err)
	}
	// idle: a single read is returned without waiting for more
	g := make(chan struct{}, 1)
	r2 := &chunkReader{chunks: [][]byte{[]byte("one"), []byte("two")}, err: io.EOF, gate: g}
	p2 := newPTYPump(r2)
	defer p2.stop()
	g <- struct{}{}
	t0 := time.Now()
	b, err := p2.next(1 << 20)
	if err != nil || string(b) != "one" || time.Since(t0) > time.Second {
		t.Fatalf("idle batch %q %v after %v", b, err, time.Since(t0))
	}
	close(g)
}

// Codex 04H: max is a hard limit, also when a single read (or the held
// remainder) is larger — a 32 KiB read with an 8 KiB limit — with every
// byte in order and the error only after the data; nextRead (comparison
// mode) returns whole reads, never split.
func TestPTYPumpStrictMax(t *testing.T) {
	mk := func(sizes ...int) ([][]byte, []byte) {
		var chunks [][]byte
		var all []byte
		for i, n := range sizes {
			c := bytes.Repeat([]byte{byte('a' + i%26)}, n)
			c[0] = byte('A' + i%26) // chunk boundaries visible in the data
			chunks = append(chunks, c)
			all = append(all, c...)
		}
		return chunks, all
	}
	errStorage := errors.New("read error")
	for _, tc := range []struct {
		name  string
		sizes []int
		max   int
		end   error
	}{
		{"first 32KiB, max 8KiB", []int{32768}, 8192, io.EOF},
		{"first exactly max", []int{8192, 8192}, 8192, io.EOF},
		{"max+1 then small", []int{8193, 10}, 8192, io.EOF},
		{"many reads straddling", []int{5000, 5000, 32768, 1, 8191, 8192, 3}, 8192, io.EOF},
		{"32KiB reads then read error", []int{32768, 32768}, 8192, errStorage},
		{"max 1 byte", []int{3, 2}, 1, io.EOF},
		{"empty stream", nil, 8192, io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chunks, want := mk(tc.sizes...)
			p := newPTYPump(&chunkReader{chunks: chunks, err: tc.end})
			defer p.stop()
			time.Sleep(20 * time.Millisecond) // let reads queue (coalescing and splitting paths)
			var got []byte
			for {
				b, err := p.next(tc.max)
				if len(b) > tc.max {
					t.Fatalf("batch of %d bytes > max %d", len(b), tc.max)
				}
				got = append(got, b...)
				if err != nil {
					if !errors.Is(err, tc.end) || len(b) != 0 {
						t.Fatalf("error %v with %d bytes, want %v after the data", err, len(b), tc.end)
					}
					break
				}
				if len(b) == 0 {
					t.Fatal("empty batch without an error")
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("bytes differ or out of order: %d vs %d", len(got), len(want))
			}
			// comparison mode: whole reads
			p2 := newPTYPump(&chunkReader{chunks: chunks, err: tc.end})
			defer p2.stop()
			for i := 0; ; i++ {
				b, err := p2.nextRead()
				if err != nil {
					if i != len(chunks) || !errors.Is(err, tc.end) {
						t.Fatalf("nextRead: %v after %d reads of %d", err, i, len(chunks))
					}
					break
				}
				if !bytes.Equal(b, chunks[i]) {
					t.Fatalf("nextRead %d: %d bytes, want the whole read of %d", i, len(b), len(chunks[i]))
				}
			}
		})
	}
}
