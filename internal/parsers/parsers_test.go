package parsers

import "testing"

const nmapSample = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="45.33.32.156" addrtype="ipv4"/>
    <hostnames><hostname name="scanme.nmap.org" type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>`

func TestNmap(t *testing.T) {
	ents, err := ParseNmapXML([]byte(nmapSample))
	if err != nil {
		t.Fatal(err)
	}
	var hosts, hostnames, ports int
	for _, e := range ents {
		switch e.Type {
		case "host":
			hosts++
			if e.Value != "45.33.32.156" {
				t.Errorf("host value = %q", e.Value)
			}
		case "hostname":
			hostnames++
		case "port":
			ports++
			if e.Details["host"] != "45.33.32.156" {
				t.Errorf("port not linked to host: %v", e.Details)
			}
		}
	}
	if hosts != 1 || hostnames != 1 || ports != 2 { // 443 is closed -> skipped
		t.Fatalf("got hosts=%d hostnames=%d ports=%d (want 1,1,2)", hosts, hostnames, ports)
	}
	// check ssh service details survived
	foundSSH := false
	for _, e := range ents {
		if e.Type == "port" && e.Value == "45.33.32.156:22/tcp" {
			foundSSH = true
			if e.Details["service"] != "ssh" || e.Details["product"] != "OpenSSH" || e.Details["version"] != "8.2p1" {
				t.Errorf("ssh details wrong: %v", e.Details)
			}
		}
	}
	if !foundSSH {
		t.Error("ssh port not found")
	}
}

const ffufSample = `{"results":[
  {"url":"http://t/admin","status":200,"length":1024,"content-type":"text/html","input":{"FUZZ":"admin"}},
  {"url":"http://t/login","status":302,"length":0,"redirectlocation":"/","input":{"FUZZ":"login"}}
]}`

func TestFfuf(t *testing.T) {
	ents, err := ParseFfufJSON([]byte(ffufSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(ents))
	}
	if ents[0].Type != "endpoint" || ents[0].Details["status"] != "200" {
		t.Errorf("endpoint 0 wrong: %+v", ents[0])
	}
}

const nucleiSample = `{"template-id":"CVE-2021-1234","info":{"name":"Example RCE","severity":"critical"},"host":"t.example.com","matched-at":"http://t.example.com/x"}
garbage line that should be skipped
{"template-id":"tech-detect","info":{"name":"nginx","severity":"info"},"host":"t.example.com","matched-at":"http://t.example.com"}`

func TestNuclei(t *testing.T) {
	ents, err := ParseNucleiJSONL([]byte(nucleiSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 2 {
		t.Fatalf("got %d findings, want 2 (garbage skipped)", len(ents))
	}
	if ents[0].Details["severity"] != "critical" {
		t.Errorf("severity = %q", ents[0].Details["severity"])
	}
}
