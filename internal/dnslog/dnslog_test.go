package dnslog

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/store"
)

func TestDecodeRoundTrip(t *testing.T) {
	in := Query{From: netip.MustParseAddr("192.168.1.61"), Name: "r3---sn-x.googlevideo.com", QType: 28, Time: time.Unix(1700000000, 0).UTC()}
	q, ok, err := Decode(Encode(in))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if q.From != in.From || q.Name != in.Name || q.QType != 28 || !q.Time.Equal(in.Time) {
		t.Fatalf("got %+v", q)
	}
	// IPv6 sources and a response message (type 2) that must be skipped
	v6 := in
	v6.From = netip.MustParseAddr("fd00::61")
	q, ok, _ = Decode(Encode(v6))
	if !ok || q.From != v6.From {
		t.Fatalf("v6: %+v", q)
	}
	resp := Encode(in)
	resp[1] = 2 // field 1 (type) varint value
	if _, ok, _ := Decode(resp); ok {
		t.Fatal("a response was counted as a query")
	}
	if _, _, err := Decode(Encode(in)[:10]); err == nil {
		t.Fatal("truncated message accepted")
	}
}

func TestSite(t *testing.T) {
	cases := map[string]string{
		"r3---sn-ab5l6n7s.googlevideo.com.": "googlevideo.com",
		"WWW.YouTube.com":                   "youtube.com",
		"www.bbc.co.uk":                     "bbc.co.uk",
		"github.com":                        "github.com",
		"61.1.168.192.in-addr.arpa":         "",
		"nas.home.lan":                      "",
		"wpad":                              "",
		"192.168.1.1":                       "",
	}
	for in, want := range cases {
		if got := Site(in); got != want {
			t.Errorf("Site(%q) = %q, want %q", in, got, want)
		}
	}
	if Service("nflxvideo.net") != "Netflix" {
		t.Error("service lookup")
	}
}

func TestCollectorServe(t *testing.T) {
	st, err := store.OpenPath(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{DB: st.DB, Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	go func() { _ = c.Serve(ctx, addr) }()

	var conn net.Conn
	for i := 0; i < 50; i++ {
		if conn, err = net.Dial("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	tv, phone := netip.MustParseAddr("192.168.1.61"), netip.MustParseAddr("192.168.1.70")
	for _, q := range []Query{
		{From: tv, Name: "a.nflxvideo.net"}, {From: tv, Name: "b.nflxvideo.net"}, {From: tv, Name: "www.youtube.com"},
		{From: phone, Name: "i.instagram.com"}, {From: phone, Name: "nas.home.lan"},
	} {
		q.Time = time.Now()
		if err := Send(conn, q); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for c.Status().Received < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	top, err := c.TopSites(ctx, time.Now().Add(-time.Hour), 10)
	if err != nil {
		t.Fatal(err)
	}
	if l := top["192.168.1.61"]; len(l) != 2 || l[0].Site != "nflxvideo.net" || l[0].Count != 2 || l[0].Service != "Netflix" {
		t.Errorf("tv sites: %+v", l)
	}
	if l := top["192.168.1.70"]; len(l) != 1 || l[0].Site != "instagram.com" {
		t.Errorf("phone sites (local names must be skipped): %+v", l)
	}
	if len(top[""]) != 3 {
		t.Errorf("network-wide: %+v", top[""])
	}
	if s := c.Status(); !s.Enabled || len(s.Senders) != 1 {
		t.Errorf("status: %+v", s)
	}
}

func TestCollectorRefusesUnknownSender(t *testing.T) {
	c := &Collector{Allow: []netip.Prefix{netip.MustParsePrefix("192.168.1.70/32")}}
	if c.allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("sender outside the allow list accepted")
	}
	if !c.allowed(netip.MustParseAddr("::ffff:192.168.1.70")) {
		t.Fatal("IPv4-mapped allowed sender refused")
	}
}
