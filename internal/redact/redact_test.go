package redact

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSecretsAcrossEverySplit(t *testing.T) {
	cases := []string{"PASSWORD=hunter42\n", "--password 'long secret'\n", "Authorization: Bearer abcDEF123\n", "https://user:supersecret@host/path\n", "{\"password\":\"hidden\",\"port\":443}\n", "pass\x1b[31mword=colored\x1b[0m\n", "-----BEGIN PRIVATE KEY-----\nABCSECRETDEF\n-----END PRIVATE KEY-----\n"}
	secrets := []string{"hunter42", "long secret", "abcDEF123", "supersecret", "hidden", "colored", "ABCSECRETDEF"}
	for i, raw := range cases {
		for cut := 0; cut <= len(raw); cut++ {
			var s Stream
			out := s.Feed([]byte(raw[:cut]))
			out = append(out, s.Feed([]byte(raw[cut:]))...)
			out = append(out, s.Finish()...)
			if len(out) != len(raw) || bytes.Contains(out, []byte(secrets[i])) {
				t.Fatalf("cut=%d input=%q output=%q", cut, raw, out)
			}
		}
	}
}
func TestEncodedCommandAndSafePort(t *testing.T) {
	cmd := "tool --password hidden"
	raw := "\x1b]697;token;CMD;" + base64.StdEncoding.EncodeToString([]byte(cmd)) + "\a\n"
	out, _ := Text([]byte(raw))
	if bytes.Contains(out, []byte(base64.StdEncoding.EncodeToString([]byte(cmd)))) {
		t.Fatal("encoded secret survived")
	}
	in := []byte("nmap -p 443 host\n")
	b, _ := Text(in)
	if !bytes.Equal(in, b) {
		t.Fatal(string(b))
	}
}
func TestBoundedAndTimeoutFailClosed(t *testing.T) {
	var s Stream
	s.Feed([]byte("pass"))
	out := s.Timeout()
	out = append(out, s.Feed([]byte("word=hidden\npublic\n"))...)
	if bytes.Contains(out, []byte("hidden")) || !bytes.Contains(out, []byte("public")) {
		t.Fatal(string(out))
	}
	b := bytes.Repeat([]byte("a"), MaxLine+10)
	out = TextOnly(b)
	if len(out) != len(b) || bytes.Contains(out, []byte("a")) {
		t.Fatal("long line leaked")
	}
}
func TextOnly(b []byte) []byte { v, _ := Text(b); return v }
func TestJSONRecursion(t *testing.T) {
	in := []byte(`{"command":"tool --password \"secret\"","details":"{\"api_key\":\"abcdef\"}","password":"hidden"}`)
	b, e := JSON(in)
	if e != nil || !json.Valid(b) || bytes.Contains(b, []byte("secret")) || bytes.Contains(b, []byte("abcdef")) || bytes.Contains(b, []byte("hidden")) {
		t.Fatal(string(b), e)
	}
}

func TestCommonCredentialCommands(t *testing.T) {
	for _, raw := range []string{`curl -u user:hidden http://host/`, `hydra -l user -p hidden host ssh`, `net user alice hidden /add`, `$secure = ConvertTo-SecureString 'hidden' -AsPlainText`, `CREATE USER alice IDENTIFIED BY 'hidden'`, `Cookie: SID=hidden`, `hasło: hidden`, `password is hidden`} {
		out, _ := Text([]byte(raw))
		if bytes.Contains(out, []byte("hidden")) {
			t.Fatalf("not masked: %s", out)
		}
	}
}

func TestSensitiveLabelOnNextLineAndInternalTokens(t *testing.T) {
	for _, raw := range []string{"Password:\nhidden\npublic\n", "http://127.0.0.1:45678/?t=abcdef123456\n", "\x1b]697;abcdef123456;A\a\n"} {
		b, _ := Text([]byte(raw))
		if bytes.Contains(b, []byte("hidden")) || bytes.Contains(b, []byte("abcdef123456")) {
			t.Fatal(string(b))
		}
	}
}
