package parsers

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"
)

// Subset of the nmap XML schema (-oX) that we care about.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames struct {
		Hostname []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Port []nmapPort `xml:"port"`
	} `xml:"ports"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
	} `xml:"service"`
}

// ParseNmapXML turns nmap -oX output into host, hostname, port and service
// entities. Ports link back to their host via Details["host"].
func ParseNmapXML(data []byte) ([]Entity, error) {
	hosts, err := nmapHosts(data)
	if err != nil {
		return nil, err
	}
	var out []Entity
	for _, h := range hosts {
		// primary IP (prefer ipv4/ipv6 over mac)
		ip := ""
		for _, a := range h.Addresses {
			if a.Type == "ipv4" || a.Type == "ipv6" {
				ip = a.Addr
				break
			}
		}
		if ip == "" && len(h.Addresses) > 0 {
			ip = h.Addresses[0].Addr
		}
		if ip != "" {
			out = append(out, Entity{Type: "host", Value: ip, Details: d("state", h.Status.State)})
		}
		for _, hn := range h.Hostnames.Hostname {
			if hn.Name != "" {
				out = append(out, Entity{Type: "hostname", Value: strings.ToLower(hn.Name), Details: d("host", ip)})
			}
		}
		for _, p := range h.Ports.Port {
			if p.State.State != "open" {
				continue
			}
			val := fmt.Sprintf("%s:%s/%s", ip, p.PortID, p.Protocol)
			out = append(out, Entity{
				Type:  "port",
				Value: val,
				Details: d(
					"host", ip,
					"port", p.PortID,
					"proto", p.Protocol,
					"service", p.Service.Name,
					"product", p.Service.Product,
					"version", p.Service.Version,
				),
			})
		}
	}
	return out, nil
}

// nmapHosts decodes the <host> records. An interrupted scan (Ctrl-C) leaves the
// XML without its closing tags; every <host> element nmap finished writing is
// still complete evidence, so it is kept and only the unfinished one is dropped.
func nmapHosts(data []byte) ([]nmapHost, error) {
	var run nmapRun
	firstErr := xml.Unmarshal(data, &run)
	if firstErr == nil {
		return run.Hosts, nil
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	var hosts []nmapHost
	inRun := false
scan:
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch {
		case se.Name.Local == "nmaprun":
			inRun = true
		case se.Name.Local == "host" && inRun:
			var h nmapHost
			if err := d.DecodeElement(&h, &se); err != nil {
				break scan // the unfinished trailing host
			}
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("nmap xml: %w", firstErr)
	}
	return hosts, nil
}
