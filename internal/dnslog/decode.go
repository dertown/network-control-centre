// Package dnslog receives DNS query logs from PowerDNS Recursor or dnsdist and counts,
// per client address, which sites (e.g. youtube.com) it looks up each hour.
//
// Both servers stream "protobuf" query logs over TCP: each message is a 2-byte big-endian
// length followed by a PBDNSMessage (dnsmessage.proto). Only the few fields NCC needs are
// decoded, so no generated code or protobuf library is required.
package dnslog

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"time"
)

// PBDNSMessage field numbers and values (from PowerDNS dnsmessage.proto).
const (
	fType     = 1
	fFrom     = 6
	fTimeSec  = 9
	fQuestion = 12
	fQName    = 1 // inside DNSQuestion
	fQType    = 2 // inside DNSQuestion

	typeQuery = 1 // DNSQueryType: a query received from a client
)

// Query is one client lookup.
type Query struct {
	From  netip.Addr
	Name  string // lower case, no trailing dot
	QType uint32
	Time  time.Time
}

var errTruncated = errors.New("dnslog: truncated protobuf message")

// Decode reads one PBDNSMessage. ok is false for messages that are not client queries
// (responses, outgoing queries) or lack a source address or name.
func Decode(b []byte) (q Query, ok bool, err error) {
	var msgType uint64
	var sec uint64
	var question []byte
	err = walk(b, func(field int, wire int, v uint64, data []byte) {
		switch {
		case field == fType && wire == 0:
			msgType = v
		case field == fFrom && wire == 2:
			if a, good := netip.AddrFromSlice(data); good {
				q.From = a.Unmap()
			}
		case field == fTimeSec && wire == 0:
			sec = v
		case field == fQuestion && wire == 2:
			question = data
		}
	})
	if err != nil {
		return q, false, err
	}
	if question != nil {
		err = walk(question, func(field int, wire int, v uint64, data []byte) {
			switch {
			case field == fQName && wire == 2:
				q.Name = strings.TrimSuffix(strings.ToLower(string(data)), ".")
			case field == fQType && wire == 0:
				q.QType = uint32(v)
			}
		})
		if err != nil {
			return q, false, err
		}
	}
	if sec > 0 {
		q.Time = time.Unix(int64(sec), 0).UTC()
	} else {
		q.Time = time.Now().UTC()
	}
	return q, msgType == typeQuery && q.From.IsValid() && q.Name != "", nil
}

// walk calls fn for every top-level field. Varints come as v, length-delimited as data.
func walk(b []byte, fn func(field, wire int, v uint64, data []byte)) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return errTruncated
		}
		b = b[n:]
		field, wire := int(key>>3), int(key&7)
		switch wire {
		case 0: // varint
			v, n := binary.Uvarint(b)
			if n <= 0 {
				return errTruncated
			}
			b = b[n:]
			fn(field, wire, v, nil)
		case 1: // 64-bit
			if len(b) < 8 {
				return errTruncated
			}
			b = b[8:]
		case 2: // length-delimited
			l, n := binary.Uvarint(b)
			if n <= 0 || uint64(len(b)-n) < l {
				return errTruncated
			}
			data := b[n : n+int(l)]
			b = b[n+int(l):]
			fn(field, wire, 0, data)
		case 5: // 32-bit
			if len(b) < 4 {
				return errTruncated
			}
			b = b[4:]
		default:
			return errors.New("dnslog: unsupported protobuf wire type")
		}
	}
	return nil
}

// Encode builds a minimal PBDNSMessage for a client query. NCC's demo and tests use it to
// stand in for a real resolver.
func Encode(q Query) []byte {
	var b []byte
	b = appendVarintField(b, fType, typeQuery)
	from := q.From.AsSlice()
	b = appendBytesField(b, fFrom, from)
	b = appendVarintField(b, fTimeSec, uint64(q.Time.Unix()))
	var qb []byte
	qb = appendBytesField(qb, fQName, []byte(q.Name+"."))
	qb = appendVarintField(qb, fQType, uint64(q.QType))
	b = appendBytesField(b, fQuestion, qb)
	return b
}

func appendVarintField(b []byte, field int, v uint64) []byte {
	b = binary.AppendUvarint(b, uint64(field)<<3)
	return binary.AppendUvarint(b, v)
}

func appendBytesField(b []byte, field int, data []byte) []byte {
	b = binary.AppendUvarint(b, uint64(field)<<3|2)
	b = binary.AppendUvarint(b, uint64(len(data)))
	return append(b, data...)
}
