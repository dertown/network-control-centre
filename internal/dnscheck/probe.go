package dnscheck

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Live is a real lookup sent to an internal DNS server, the way a client would: does it
// answer internet names, and the internal zone?
type Live struct {
	Server string `json:"server"`
	// Internet is the internet name asked for, InternetResult the answer: "NOERROR",
	// "REFUSED", "SERVFAIL", "NXDOMAIN", "no answer" (timeout) or an error.
	Internet       string `json:"internet"`
	InternetResult string `json:"internet_result"`
	InternetOK     bool   `json:"internet_ok"`
	// Internal is a zone on the internal DNS server (its SOA is asked for); empty when NCC
	// doesn't know one.
	Internal       string `json:"internal,omitempty"`
	InternalResult string `json:"internal_result,omitempty"`
	InternalOK     bool   `json:"internal_ok,omitempty"`
}

// InternetTestName is looked up to see whether a server resolves internet names.
const InternetTestName = "www.google.com"

// Query types used by the probe.
const (
	TypeA   = 1
	TypeSOA = 6
)

// Prober sends one query; replaced in tests.
type Prober func(ctx context.Context, server, name string, qtype uint16) (string, error)

// ProbeServer asks server for an internet name and (when zone is set) the internal zone.
func ProbeServer(ctx context.Context, q Prober, server, zone string) Live {
	if q == nil {
		q = Query
	}
	one := func(name string, qtype uint16) (string, bool) {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		res, err := q(cctx, norm(server), name, qtype)
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			return outcome(res, err)
		}
		return "no answer", false
	}
	l := Live{Server: norm(server), Internet: InternetTestName}
	l.InternetResult, l.InternetOK = one(InternetTestName, TypeA)
	if zone = strings.TrimSuffix(zone, "."); zone != "" {
		l.Internal = zone
		l.InternalResult, l.InternalOK = one(zone, TypeSOA)
	}
	return l
}

func outcome(rcode string, err error) (string, bool) {
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return "no answer", false
		}
		if strings.Contains(err.Error(), "refused") {
			return "port 53 closed", false
		}
		return err.Error(), false
	}
	return rcode, rcode == "NOERROR"
}

var rcodes = map[int]string{0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

// Query sends one recursive (RD) query over UDP port 53 and returns the response code.
func Query(ctx context.Context, server, name string, qtype uint16) (string, error) {
	return queryPort(ctx, server, 53, name, qtype)
}

func queryPort(ctx context.Context, server string, port int, name string, qtype uint16) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
	}
	msg, id, err := buildQuery(name, qtype)
	if err != nil {
		return "", err
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(msg); err != nil {
		return "", err
	}
	buf := make([]byte, 1500)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return "", err
		}
		if n < 12 || binary.BigEndian.Uint16(buf) != id {
			continue // not our answer
		}
		return rcodeName(int(buf[3] & 0x0f)), nil
	}
}

func rcodeName(rc int) string {
	if s, ok := rcodes[rc]; ok {
		return s
	}
	return fmt.Sprintf("RCODE%d", rc)
}

func buildQuery(name string, qtype uint16) ([]byte, uint16, error) {
	var idb [2]byte
	_, _ = rand.Read(idb[:])
	id := binary.BigEndian.Uint16(idb[:])
	m := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(m[0:], id)
	m[2] = 0x01                          // RD
	binary.BigEndian.PutUint16(m[4:], 1) // QDCOUNT
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" || len(label) > 63 {
			return nil, 0, fmt.Errorf("bad name %q", name)
		}
		m = append(m, byte(len(label)))
		m = append(m, label...)
	}
	m = append(m, 0, byte(qtype>>8), byte(qtype), 0, 1) // root, QTYPE, QCLASS IN
	return m, id, nil
}
