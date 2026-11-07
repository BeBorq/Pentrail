package redact

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

func TestFastAssignmentRulesCurrent(t *testing.T) {
	if !fastAssignments || !fastQuotedPassword || !fastPasswordIs || !fastNetUser {
		t.Fatal("fast paths must be reviewed when reference rules change")
	}
}

func TestFastTailPreservesOriginalMatchChain(t *testing.T) {
	texts := []string{
		`token="one password=two; token=three"; password=four`,
		"net user first one net user second two\nnet.exe user third /add net user fourth four",
		strings.Repeat("token=prefix; net user synthetic value; ", 160) + `password="tail token=inside"`,
		"token='' password=abc\nsecret='x token=y' token=z",
	}
	r := rand.New(rand.NewSource(61922))
	for n := 0; n < 400; n++ {
		texts = append(texts, strings.Repeat("token=a; ", r.Intn(20))+`password="x token=y"; `+strings.Repeat("net user a b; ", r.Intn(20)))
	}
	for _, s := range texts {
		b := []byte(s)
		facts := assignmentFactsForPatterns(b, ^uint64(0))
		for _, rule := range []int{2, 7} {
			original := patterns[rule].FindAllSubmatchIndex(b, -1)
			for from := 0; from <= len(b); from++ {
				got, supported := fastTailMatches(rule, b, from, facts)
				if !supported {
					continue
				}
				var want [][]int
				for _, match := range original {
					if match[1] > from {
						want = append(want, match)
					}
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("rule=%d from=%d input=%q got=%v want=%v", rule, from, b, got, want)
				}
			}
		}
	}
}

func TestFastAssignmentExactIndices(t *testing.T) {
	if prefilterOff {
		t.Fatal("requires optimized path")
	}
	check := func(b []byte) {
		t.Helper()
		for _, i := range []int{2, 4, 6, 7} {
			got := patternMatches(i, patterns[i], b)
			want := patterns[i].FindAllSubmatchIndex(b, -1)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("rule%d input=%q\ngot=%v\nwant=%v", i, b, got, want)
			}
		}
	}
	for _, text := range []string{"net user admin first", "NET.EXE USER admin token=a", "net user admin /add net user other secret", "net user net user /add", "net user admin\npassword", "net user abc foo\r\nnet user def bar", "net user admin \vsecret", "foo-net user admin p", `net user "a b" /add`, `net user "" secret`, `net user 'x y' 'abc def'`, "net user admin hasło"} {
		check([]byte(text))
	}
	keys := []string{"password", "PASSWORD", "x-password", "password_password", "passwd", "passphrase", "secret", "token", "api_key", "API-KEY", "pwd", "haslo", "hasło", "ſecret", "---token", "_--token", "foo-pwd", "foo_pwd", "foo-haslo", "foo--haslo", "foo-pwd_password", "password--pwd"}
	values := []string{"", `"`, `'`, `""`, `''`, `"abc def"`, `'abc def'`, `"a\"b"`, `"a\\"`, `"a\`, "\"a\\\nb", "\"a\\\rb", "'a\rb'", ";", "<", ">", ",", "abc", "\vabc", "\x00abc", "a:b@host/path", "a=b", "'password=inner'", `"password='inner'"`}
	for _, k := range keys {
		for _, v := range values {
			for _, space := range []string{"", " ", "\t\n\f\r", "\v"} {
				check([]byte("prefix " + k + "=" + space + v + ";token=second"))
			}
		}
	}
	alphabet := []byte("ab pwd='\";\\\n\r\v:=<>\t\x00")
	r := rand.New(rand.NewSource(61719))
	for n := 0; n < 20000; n++ {
		b := make([]byte, r.Intn(320))
		for i := range b {
			b[i] = alphabet[r.Intn(len(alphabet))]
		}
		pos := r.Intn(len(b) + 1)
		seed := []byte(keys[r.Intn(len(keys))] + "=" + values[r.Intn(len(values))])
		b = append(append(append([]byte(nil), b[:pos]...), seed...), b[pos:]...)
		check(b)
	}
	keyAlphabet := []byte("aB_pWd-019")
	for n := 0; n < 20000; n++ {
		prefix := make([]byte, r.Intn(30))
		for i := range prefix {
			prefix[i] = keyAlphabet[r.Intn(len(keyAlphabet))]
		}
		check([]byte("prefix " + string(prefix) + keys[r.Intn(len(keys))] + "=\"a\\\"b\";token=next"))
	}
	for a := 0; a < 128; a++ {
		for b := 0; b < 128; b++ {
			for _, quote := range []byte{'"', '\'', 0} {
				text := []byte("password=")
				if quote != 0 {
					text = append(text, quote)
				}
				text = append(text, byte(a), byte(b))
				if quote != 0 {
					text = append(text, quote)
				}
				text = append(text, []byte(";token=next")...)
				check(text)
			}
		}
	}
	for _, word := range []string{"password", "identified", "with", "haslo"} {
		for _, space := range []string{" ", "\t", "\n", "\r", "\f", "\v"} {
			check([]byte(strings.ToUpper(word) + space + `"value"`))
		}
	}
}

func TestFastNetUserExactIndices(t *testing.T) {
	r := rand.New(rand.NewSource(61822))
	commands := []string{"net", "NET.EXE", "netx", "foo-net", "_net", "net.ExEwrong"}
	spaces := []string{" ", "\t", "\r\n", "\f", "\v", ""}
	users := []string{"admin", "net", "net.exe", "/u", "n\x00x", "a:b", "_", ""}
	passwords := []string{"secret", "/add", "", "\vxxx", "token=public", "abc/def", "net user next /add"}
	for n := 0; n < 18000; n++ {
		b := []byte(commands[r.Intn(len(commands))] + spaces[r.Intn(len(spaces))] + "user" + spaces[r.Intn(len(spaces))] + users[r.Intn(len(users))] + spaces[r.Intn(len(spaces))] + passwords[r.Intn(len(passwords))] + "; net user next final")
		got, want := patternMatches(2, patterns[2], b), patterns[2].FindAllSubmatchIndex(b, -1)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("input=%q got=%v want=%v", b, got, want)
		}
	}
}
