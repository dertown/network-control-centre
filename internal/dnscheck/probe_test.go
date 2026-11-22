package dnscheck

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestBuildQuery(t *testing.T) {
	m, id, err := buildQuery("www.google.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{byte(id >> 8), byte(id), 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	if string(m) != string(want) {
		t.Fatalf("query % x", m)
	}
	if _, _, err := buildQuery("a..b", TypeA); err == nil {
		t.Fatal("empty label must fail")
	}
}

// A real UDP round trip against a tiny server that refuses everything.
func TestQueryReadsTheResponseCode(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := append([]byte{}, buf[:n]...)
			resp[2] |= 0x80 // QR
			resp[3] = 0x80 | 5
			_, _ = pc.WriteTo(resp, addr)
		}
	}()
	// Query always uses port 53, so call the same code on the test port
	port := pc.LocalAddr().(*net.UDPAddr).Port
	rc, err := queryPort(context.Background(), "127.0.0.1", port, "example.com", TypeA)
	if err != nil || rc != "REFUSED" {
		t.Fatalf("got %q %v", rc, err)
	}
}

func TestProbeServer(t *testing.T) {
	q := func(_ context.Context, server, name string, _ uint16) (string, error) {
		if server != "192.168.1.70" {
			t.Errorf("server %q", server)
		}
		if name == InternetTestName {
			return "REFUSED", nil
		}
		return "NOERROR", nil
	}
	l := ProbeServer(context.Background(), q, "http://192.168.1.70:8082", "izanami.org.")
	if l.InternetOK || l.InternetResult != "REFUSED" || !l.InternalOK || l.Internal != "izanami.org" {
		t.Fatalf("%+v", l)
	}
	slow := func(ctx context.Context, _, _ string, _ uint16) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}
	start := time.Now()
	l = ProbeServer(context.Background(), slow, "10.0.0.1", "")
	if l.InternetResult != "no answer" || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout: %+v", l)
	}
	if r, ok := outcome("", errors.New("dial udp: connect: connection refused")); r != "port 53 closed" || ok {
		t.Fatal(r)
	}
}

// liveCheck results for the authoritative-only server the user has.
func TestLiveChecks(t *testing.T) {
	res := resolver("203.0.113.53")
	res.Live = []Live{{Server: "192.168.1.10", Internet: InternetTestName, InternetResult: "REFUSED", Internal: "izanami.org", InternalResult: "NOERROR", InternalOK: true}}
	r := Evaluate([]Router{router(lan("lan", "Default", "192.168.1.10", "1.1.1.1"), wan(true, "203.0.113.53"))}, []Resolver{res})
	c := byID(t, r, "live-7-192.168.1.10")
	if c.Status != Fail || c.Action != ActionRecursorAPI || r.Status != Fail {
		t.Fatalf("%+v", c)
	}
	res.Live[0].InternetResult, res.Live[0].InternetOK = "NOERROR", true
	r = Evaluate([]Router{router(lan("lan", "Default", "192.168.1.10", "1.1.1.1"), wan(true, "203.0.113.53"))}, []Resolver{res})
	if c := byID(t, r, "live-7-192.168.1.10"); c.Status != Pass || r.Status != Pass {
		t.Fatalf("%+v %s", c, r.Status)
	}
}
