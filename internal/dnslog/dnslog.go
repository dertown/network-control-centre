package dnslog

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Collector listens for protobuf query logs and keeps hourly per-client site counts.
type Collector struct {
	DB *sql.DB
	// Allow lists the resolver addresses that may send logs. Empty allows any sender,
	// which is only sensible on a trusted network.
	Allow []netip.Prefix
	// Retain is how long counts are kept (default 7 days).
	Retain time.Duration
	Log    *slog.Logger

	mu       sync.Mutex
	pending  map[key]int64
	lastMsg  time.Time
	received int64
	senders  map[string]time.Time
	listen   string
}

type key struct {
	ip, site string
	hour     int64
}

// Status describes the collector for the UI.
type Status struct {
	Enabled  bool      `json:"enabled"`
	Listen   string    `json:"listen,omitempty"`
	Received int64     `json:"received"`
	LastMsg  time.Time `json:"last_message,omitempty"`
	Senders  []string  `json:"senders,omitempty"`
}

// Status reports what the collector has seen since NCC started.
func (c *Collector) Status() Status {
	if c == nil {
		return Status{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st := Status{Enabled: true, Listen: c.listen, Received: c.received, LastMsg: c.lastMsg}
	for s := range c.senders {
		st.Senders = append(st.Senders, s)
	}
	sort.Strings(st.Senders)
	return st
}

// Add counts one query. Names that are local or not sites are ignored.
func (c *Collector) Add(q Query) {
	site := Site(q.Name)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.received++
	c.lastMsg = time.Now().UTC()
	if site == "" {
		return
	}
	if c.pending == nil {
		c.pending = map[key]int64{}
	}
	c.pending[key{q.From.String(), site, q.Time.Truncate(time.Hour).Unix()}]++
}

// Flush writes pending counts to the database and drops counts older than Retain.
func (c *Collector) Flush(ctx context.Context) error {
	c.mu.Lock()
	p := c.pending
	c.pending = nil
	retain := c.Retain
	c.mu.Unlock()
	if retain <= 0 {
		retain = 7 * 24 * time.Hour
	}
	tx, err := c.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for k, n := range p {
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns_queries (client_ip, site, hour, count) VALUES (?,?,?,?)
			ON CONFLICT (client_ip, site, hour) DO UPDATE SET count = count + excluded.count`, k.ip, k.site, k.hour, n); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns_queries WHERE hour < ?`, time.Now().Add(-retain).Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// SiteCount is how often a site was looked up.
type SiteCount struct {
	Site    string `json:"site"`
	Service string `json:"service,omitempty"`
	Count   int64  `json:"count"`
}

// TopSites returns, per client address, its most looked-up sites since a time, and the
// same for the whole network under the key "". limit caps each list.
func (c *Collector) TopSites(ctx context.Context, since time.Time, limit int) (map[string][]SiteCount, error) {
	if err := c.Flush(ctx); err != nil {
		return nil, err
	}
	rows, err := c.DB.QueryContext(ctx, `SELECT client_ip, site, SUM(count) FROM dns_queries
		WHERE hour >= ? GROUP BY client_ip, site`, since.Truncate(time.Hour).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]SiteCount{}
	all := map[string]int64{}
	for rows.Next() {
		var ip, site string
		var n int64
		if err := rows.Scan(&ip, &site, &n); err != nil {
			return nil, err
		}
		out[ip] = append(out[ip], SiteCount{Site: site, Service: Service(site), Count: n})
		all[site] += n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for site, n := range all {
		out[""] = append(out[""], SiteCount{Site: site, Service: Service(site), Count: n})
	}
	for ip, l := range out {
		sort.Slice(l, func(i, j int) bool {
			if l[i].Count != l[j].Count {
				return l[i].Count > l[j].Count
			}
			return l[i].Site < l[j].Site
		})
		if limit > 0 && len(l) > limit {
			l = l[:limit]
		}
		out[ip] = l
	}
	return out, nil
}

func (c *Collector) allowed(a netip.Addr) bool {
	if len(c.Allow) == 0 {
		return true
	}
	for _, p := range c.Allow {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

// Serve accepts resolver connections on addr until ctx ends, and flushes counts every
// 30 seconds.
func (c *Collector) Serve(ctx context.Context, addr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.listen = l.Addr().String()
	c.mu.Unlock()
	go func() { <-ctx.Done(); _ = l.Close() }()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = c.Flush(context.Background())
				return
			case <-t.C:
				if err := c.Flush(ctx); err != nil && c.Log != nil {
					c.Log.Warn("dns log flush", "err", err)
				}
			}
		}
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go c.handle(ctx, conn)
	}
}

func (c *Collector) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ap, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil || !c.allowed(ap.Addr()) {
		if c.Log != nil {
			c.Log.Warn("dns log: refused connection from a sender not in dns_log.allow", "from", conn.RemoteAddr().String())
		}
		return
	}
	c.mu.Lock()
	if c.senders == nil {
		c.senders = map[string]time.Time{}
	}
	c.senders[ap.Addr().Unmap().String()] = time.Now()
	c.mu.Unlock()
	go func() { <-ctx.Done(); _ = conn.Close() }()
	r := bufio.NewReader(conn)
	buf := make([]byte, 65535)
	for {
		var hdr [2]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(hdr[:]))
		if _, err := io.ReadFull(r, buf[:n]); err != nil {
			return
		}
		q, ok, err := Decode(buf[:n])
		if err != nil {
			if c.Log != nil {
				c.Log.Warn("dns log: bad message, closing connection", "from", ap.String(), "err", err)
			}
			return
		}
		if ok {
			c.Add(q)
		} else {
			c.mu.Lock()
			c.received++
			c.lastMsg = time.Now().UTC()
			c.mu.Unlock()
		}
	}
}

// Send writes one query in the framing PowerDNS uses. Used by the demo and tests.
func Send(w io.Writer, q Query) error {
	b := Encode(q)
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}
