package redact

import (
	"bytes"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func repeatedReferenceFeed(s *Stream, input []byte) (out []byte) {
	old := prefilterOff
	prefilterOff = true
	defer func() { prefilterOff = old }()
	return s.feedRef(input)
}

func repeatedReferenceFinish(s *Stream) (out []byte) {
	old := prefilterOff
	prefilterOff = true
	defer func() { prefilterOff = old }()
	if len(s.pending) > 0 {
		return s.finishLineRef()
	}
	return nil
}

func TestRepeatedLinesMatchFullReferenceAndState(t *testing.T) {
	const cursor = "\x1b[30;1H"
	row := cursor + "PUBLIC_VISIBLE_42 token=synthetic;\r\n"
	warm := strings.Repeat(row, 180)
	cases := []struct {
		name    string
		input   []byte
		changed int64
	}{
		{"matching", []byte(strings.Repeat(row, 360)), 0},
		{"changed_input", []byte(warm + strings.Replace(row, "synthetic", "different", 1) + warm), 0},
		{"quiet", []byte(strings.Repeat(cursor+"ordinary public output\r\n", 360)), 0},
		{"unicode", []byte(strings.Repeat(cursor+"żółć 🧪 token='synthetic';\r\n", 250)), 0},
		{"invalid_utf8", []byte(strings.Repeat(cursor+"\xff\xc0 token=synthetic;\r\n", 250)), 0},
		{"open_quote", []byte("password=\"\r\n" + strings.Repeat(cursor+"ordinary public output\r\n", 350)), 0},
		{"state_changes", []byte(warm + "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat(cursor+"opaque body\n", 12) + "-----END PRIVATE KEY-----\npassword:\n" + cursor + "secret on next line\n" + warm), 0},
		{"oversized", []byte(warm + strings.Repeat("x", MaxLine+8) + "\n" + warm), 0},
		{"changed_overflow", []byte(warm), (1 << 63) - 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, chunk := range []int{127, 8192, 1 << 20} {
				fast, reference := Stream{Changed: tc.changed}, Stream{Changed: tc.changed}
				var got, want []byte
				for offset := 0; offset < len(tc.input); {
					end := min(len(tc.input), offset+chunk)
					fast = fast.Clone()
					reference = reference.Clone()
					got = append(got, fast.Feed(tc.input[offset:end])...)
					want = append(want, repeatedReferenceFeed(&reference, tc.input[offset:end])...)
					if !bytes.Equal(got, want) || !reflect.DeepEqual(fast, reference) {
						t.Fatalf("chunk=%d offset=%d output/state differs", chunk, end)
					}
					offset = end
				}
				got = append(got, fast.Finish()...)
				want = append(want, repeatedReferenceFinish(&reference)...)
				if !bytes.Equal(got, want) || !reflect.DeepEqual(fast, reference) {
					t.Fatalf("chunk=%d final output/state differs", chunk)
				}
				if len(got) != len(tc.input) {
					t.Fatal("output length changed")
				}
				if tc.name == "matching" && bytes.Count(got, []byte("PUBLIC_VISIBLE_42")) != 360 {
					t.Fatal("a repeated row was lost or duplicated")
				}
			}
		})
	}
}

func TestRepeatedLinesCheckpointRestore(t *testing.T) {
	row := "\x1b[30;1HPUBLIC_VISIBLE_42 token=synthetic;\r\n"
	input := []byte(strings.Repeat(row, 450))
	var fast, reference Stream
	var got, want []byte
	for offset := 0; offset < len(input); offset += 8192 {
		end := min(len(input), offset+8192)
		got = append(got, fast.Feed(input[offset:end])...)
		want = append(want, repeatedReferenceFeed(&reference, input[offset:end])...)
		checkpoint := fast.Checkpoint()
		if !reflect.DeepEqual(checkpoint, reference.Checkpoint()) {
			t.Fatal("checkpoint differs from full reference")
		}
		var err error
		fast, err = Restore(checkpoint)
		if err != nil {
			t.Fatal(err)
		}
		reference, err = Restore(reference.Checkpoint())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) || !reflect.DeepEqual(fast, reference) {
			t.Fatal("restored data/state differs")
		}
	}
	got = append(got, fast.Finish()...)
	want = append(want, repeatedReferenceFinish(&reference)...)
	if !bytes.Equal(got, want) || !reflect.DeepEqual(fast, reference) || bytes.Count(got, []byte("PUBLIC_VISIBLE_42")) != 450 {
		t.Fatal("checkpoint continuation lost data or state")
	}
}

func TestRepeatedLineResultsAreIndependentAcrossStreams(t *testing.T) {
	input := []byte(strings.Repeat("\x1b[30;1HPUBLIC_VISIBLE_42 token=synthetic;\r\n", 250))
	var reference Stream
	want := repeatedReferenceFeed(&reference, input)
	want = append(want, repeatedReferenceFinish(&reference)...)
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var fast Stream
			got := fast.Feed(input)
			got = append(got, fast.Finish()...)
			if !bytes.Equal(got, want) || !reflect.DeepEqual(fast, reference) {
				t.Error("concurrent stream reused another stream's result")
			}
			saved := append([]byte(nil), got...)
			fast.Feed([]byte("\x1b[30;1Ha different subsequent line\r\n"))
			if !bytes.Equal(got, saved) {
				t.Error("later Feed changed an earlier returned result")
			}
		}()
	}
	wg.Wait()
}
