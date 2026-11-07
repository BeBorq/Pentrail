package redact

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCheckpointRoundTripEveryByte(t *testing.T) {
	cases := []string{"żółć 日本語🙂\npublic partial żółć", "PASSWORD=SecretA\nPUBLIC\nPASSWORD=SecretB", "PASSWORD:\nSecretA\nPUBLIC", "-----BEGIN PRIVATE KEY-----\nsecretpayload\n-----END PRIVATE KEY-----\nPUBLIC", "SYNTHETIC_PASSWORD\r\n\x1b[37mD=SecretA\nPUBLIC"}
	for _, input := range cases {
		expected, _ := Text([]byte(input))
		for split := 0; split <= len(input); split++ {
			var s Stream
			out := s.Feed([]byte(input[:split]))
			encoded, err := json.Marshal(s.Checkpoint())
			if err != nil {
				t.Fatal(err)
			}
			var cp Checkpoint
			if err = json.Unmarshal(encoded, &cp); err != nil {
				t.Fatal(err)
			}
			restored, err := Restore(cp)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, restored.Feed([]byte(input[split:]))...)
			out = append(out, restored.Finish()...)
			if !bytes.Equal(out, expected) {
				t.Fatalf("split=%d input=%q got=%q want=%q", split, input, out, expected)
			}
		}
	}
	t.Log("CHECKPOINT all_byte_boundaries=PASS unicode=PASS masking=PASS")
}
