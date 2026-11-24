package bind

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/dns"
	mdns "github.com/miekg/dns"
)

const testSecret = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0IQ=="

// fakeBIND is an authoritative server for one zone that requires TSIG for transfers and updates.
type fakeBIND struct {
	mu  sync.Mutex
	rrs []mdns.RR
}

func (f *fakeBIND) ServeDNS(w mdns.ResponseWriter, r *mdns.Msg) {
	m := new(mdns.Msg)
	m.SetReply(r)
	signed := r.IsTsig() != nil && w.TsigStatus() == nil
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Opcode == mdns.OpcodeUpdate:
		if !signed {
			m.Rcode = mdns.RcodeRefused
			break
		}
		for _, rr := range r.Ns {
			h := rr.Header()
			if h.Class == mdns.ClassANY { // delete an RRset
				keep := f.rrs[:0]
				for _, x := range f.rrs {
					if !(strings.EqualFold(x.Header().Name, h.Name) && x.Header().Rrtype == h.Rrtype) {
						keep = append(keep, x)
					}
				}
				f.rrs = keep
				continue
			}
			f.rrs = append(f.rrs, rr)
		}
	case r.Question[0].Qtype == mdns.TypeAXFR:
		if !signed {
			m.Rcode = mdns.RcodeRefused
			break
		}
		m.Answer = append(append(append([]mdns.RR{}, f.rrs[0]), f.rrs[1:]...), f.rrs[0])
	case r.Question[0].Qtype == mdns.TypeSOA:
		m.Authoritative = true
		m.Answer = []mdns.RR{f.rrs[0]}
	}
	if r.IsTsig() != nil {
		m.SetTsig(r.IsTsig().Hdr.Name, mdns.HmacSHA256, 300, time.Now().Unix())
	}
	_ = w.WriteMsg(m)
}

func rr(s string) mdns.RR {
	r, err := mdns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return r
}

func start(t *testing.T) (*fakeBIND, string) {
	f := &fakeBIND{rrs: []mdns.RR{
		rr("home.lan. 3600 IN SOA ns1.home.lan. admin.home.lan. 7 3600 600 86400 300"),
		rr("home.lan. 3600 IN NS ns1.home.lan."),
		rr("ns1.home.lan. 300 IN A 192.168.1.53"),
		rr("nas.home.lan. 300 IN A 192.168.1.50"),
		rr("home.lan. 300 IN MX 10 mail.home.lan."),
	}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &mdns.Server{Listener: l, Handler: f, TsigSecret: map[string]string{"ncc-key.": testSecret},
		MsgAcceptFunc: func(mdns.Header) mdns.MsgAcceptAction { return mdns.MsgAccept }}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return f, l.Addr().String()
}

func TestBINDReadAndUpdate(t *testing.T) {
	_, addr := start(t)
	ctx := context.Background()
	s := dns.Server{Name: "bind", Kind: "bind", Address: addr, Options: map[string]string{OptZones: "home.lan", OptTSIGName: "ncc-key"}}
	creds := map[string]string{SecretTSIG: testSecret}
	p := Provider{}

	if err := p.Check(ctx, s, creds); err != nil {
		t.Fatal(err)
	}
	zones, err := p.ListZones(ctx, s, creds)
	if err != nil || len(zones) != 1 || zones[0].Name != "home.lan." || zones[0].Serial != 7 {
		t.Fatalf("zones %+v %v", zones, err)
	}
	sets, err := p.ListRecords(ctx, s, creds, "home.lan")
	if err != nil {
		t.Fatal(err)
	}
	find := func(sets []dns.RRSet, name, typ string) *dns.RRSet {
		for i := range sets {
			if sets[i].Name == name && sets[i].Type == typ {
				return &sets[i]
			}
		}
		return nil
	}
	if a := find(sets, "nas.home.lan.", "A"); a == nil || a.Records[0] != "192.168.1.50" || a.TTL != 300 {
		t.Fatalf("nas A: %+v", a)
	}
	if mx := find(sets, "home.lan.", "MX"); mx == nil || mx.Records[0] != "10 mail.home.lan." {
		t.Fatalf("MX: %+v", mx)
	}
	n := 0
	for _, x := range sets {
		if x.Type == "SOA" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the closing SOA of the transfer was listed: %d SOA sets", n)
	}

	err = p.Apply(ctx, s, creds, "home.lan.", []dns.Change{
		{Op: dns.Replace, RRSet: dns.RRSet{Name: "nas.home.lan.", Type: "A", TTL: 600, Records: []string{"192.168.1.51"}}},
		{Op: dns.Replace, RRSet: dns.RRSet{Name: "www.home.lan.", Type: "CNAME", TTL: 300, Records: []string{"nas.home.lan."}}},
		{Op: dns.Delete, RRSet: dns.RRSet{Name: "home.lan.", Type: "MX"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sets, _ = p.ListRecords(ctx, s, creds, "home.lan")
	if a := find(sets, "nas.home.lan.", "A"); a == nil || len(a.Records) != 1 || a.Records[0] != "192.168.1.51" || a.TTL != 600 {
		t.Fatalf("nas A after replace: %+v", a)
	}
	if c := find(sets, "www.home.lan.", "CNAME"); c == nil {
		t.Fatal("CNAME not added")
	}
	if find(sets, "home.lan.", "MX") != nil {
		t.Fatal("MX not deleted")
	}

	// a wrong key is refused
	if _, err := p.ListRecords(ctx, s, map[string]string{SecretTSIG: "d3Jvbmc="}, "home.lan"); err == nil {
		t.Fatal("transfer with a wrong key succeeded")
	}
}
