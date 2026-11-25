package syslog

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dertown/network-control-centre/internal/siem"
)

func events() []siem.Event {
	return []siem.Event{
		{ID: 1, Source: siem.SourceAudit, Time: time.Unix(1700000000, 0), Type: "login.failed", Severity: 7, Actor: "eve", Message: "Failed sign-in"},
		{ID: 2, Source: siem.SourceNetwork, Time: time.Unix(1700000001, 0), Type: "connection.down", Severity: 7, Message: "udm down\nsecond line"},
	}
}

func readLines(t *testing.T, ln net.Listener, n int) chan []string {
	out := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(c)
		var lines []string
		for len(lines) < n {
			l, err := r.ReadString('\n')
			if err != nil {
				break
			}
			lines = append(lines, strings.TrimSuffix(l, "\n"))
		}
		out <- lines
	}()
	return out
}

func TestTCPLEEF(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tg := siem.Target{Kind: "syslog", Address: ln.Addr().String(), Options: map[string]string{OptTransport: "tcp", OptFormat: "leef", OptFacility: "13"}}
	got := readLines(t, ln, 2)
	if _, err := (Provider{}).Send(context.Background(), tg, nil, events()); err != nil {
		t.Fatal(err)
	}
	lines := <-got
	if len(lines) != 2 {
		t.Fatalf("lines %q", lines)
	}
	// log audit (13) * 8 + error (3) = 107
	if !strings.HasPrefix(lines[0], "<107>1 ") || !strings.Contains(lines[0], "LEEF:1.0|NCC|Network Control Centre|") || !strings.Contains(lines[0], "usrName=eve") {
		t.Errorf("line %q", lines[0])
	}
	if !strings.Contains(lines[1], "udm down second line") {
		t.Errorf("newlines must not split an event: %q", lines[1])
	}
	// Test only opens the connection
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()
	if res, err := (Provider{}).Test(context.Background(), tg, nil); err != nil || !strings.Contains(res.Info, "is listening") {
		t.Errorf("test: %v %+v", err, res)
	}
}

func TestOctetFraming(t *testing.T) {
	b := string(frame("<1>1 x", "tcp", "octet"))
	if b != "6 <1>1 x" {
		t.Errorf("got %q", b)
	}
}

func TestUDPCEF(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	tg := siem.Target{Kind: "syslog", Address: pc.LocalAddr().String(), Options: map[string]string{OptTransport: "udp", OptFormat: "cef"}}
	if _, err := (Provider{}).Send(context.Background(), tg, nil, events()[:1]); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 9000)
	_ = pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "CEF:0|NCC|") || !strings.HasPrefix(got, "<163>1 ") {
		t.Errorf("got %q", got)
	}
}

func TestTLSPinAndDefaultPort(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.StartTLS() // just for its certificate
	cert := srv.TLS.Certificates[0]
	srv.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	tg := siem.Target{Kind: "syslog", Address: "tls://" + ln.Addr().String(), Options: map[string]string{OptTransport: "tls", OptFormat: "json"}}
	got := readLines(t, ln, 1)
	res, err := Provider{}.Send(context.Background(), tg, nil, events()[:1])
	if err != nil {
		t.Fatal(err)
	}
	if res.OptionUpdates[siem.OptFingerprint] == "" {
		t.Error("the certificate should be pinned on first use")
	}
	if lines := <-got; len(lines) != 1 || !strings.Contains(lines[0], `"action":"login.failed"`) {
		t.Errorf("lines %q", lines)
	}
	tg.Options[siem.OptFingerprint] = strings.Repeat("ab", 32)
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			_ = c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	if _, err := (Provider{}).Send(context.Background(), tg, nil, events()[:1]); err == nil {
		t.Error("a different certificate must be refused")
	}

	d, err := destOf(siem.Target{Address: "siem.example.com", Options: map[string]string{OptTransport: "tls"}})
	if err != nil || d.addr != "siem.example.com:6514" {
		t.Errorf("default port: %v %+v", err, d)
	}
}

func TestQRadarAPI(t *testing.T) {
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/system/about" || r.Header.Get("SEC") != "tok" {
			w.WriteHeader(401)
			return
		}
		w.Write([]byte(`{"external_version":"7.5.0 UP10"}`))
	}))
	defer api.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	tg := siem.Target{Kind: "syslog", Address: ln.Addr().String(), Options: map[string]string{OptTransport: "tcp", OptFormat: "leef", OptAPIURL: api.URL}}
	res, err := Provider{}.Test(context.Background(), tg, map[string]string{SecretAPI: "tok"})
	if err != nil || !strings.Contains(res.Info, "QRadar 7.5.0 UP10") || res.OptionUpdates["api_tls_fingerprint"] == "" {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := (Provider{}).Test(context.Background(), tg, map[string]string{SecretAPI: "bad"}); err == nil {
		t.Error("bad token should fail")
	}
}
