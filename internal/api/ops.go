package api

import (
	"context"
	"crypto/subtle"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/core"
)

// ---- readiness ----

// ready is for load balancers and orchestrators: 200 when NCC can serve (its database
// answers), 503 when it can't. A sealed vault still counts as ready, since the UI is needed to
// unseal it; the answer says so.
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	out := map[string]any{"status": "ready", "version": s.Version}
	code := http.StatusOK
	if err := s.Store.DB.PingContext(ctx); err != nil {
		out["status"], out["database"] = "unavailable", err.Error()
		code = http.StatusServiceUnavailable
	} else {
		out["database"] = "ok"
	}
	st := s.Vault.Status(ctx)
	switch {
	case !st.Initialized:
		out["vault"] = "not initialized"
	case st.Sealed:
		out["vault"] = "sealed"
	default:
		out["vault"] = "unsealed"
	}
	writeJSON(w, code, out)
}

// ---- Prometheus metrics ----

type metricsReg struct {
	mu       sync.Mutex
	requests map[[2]string]uint64 // method, status code
	reqSum   float64
	reqCount uint64
	polls    map[[3]string]uint64 // category, kind, ok|error
	pollSum  map[string]float64   // category
	pollCnt  map[string]uint64
}

var regOnce sync.Map // *Server -> *metricsReg

func (s *Server) metrics() *metricsReg {
	if m, ok := regOnce.Load(s); ok {
		return m.(*metricsReg)
	}
	m, _ := regOnce.LoadOrStore(s, &metricsReg{requests: map[[2]string]uint64{}, polls: map[[3]string]uint64{},
		pollSum: map[string]float64{}, pollCnt: map[string]uint64{}})
	return m.(*metricsReg)
}

func (m *metricsReg) request(method string, code int, d time.Duration) {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		method = "OTHER" // keep label values bounded
	}
	m.mu.Lock()
	m.requests[[2]string{method, strconv.Itoa(code)}]++
	m.reqSum += d.Seconds()
	m.reqCount++
	m.mu.Unlock()
}

// ObservePoll records one finished poll; wire it to core.Poller.Observe.
func (s *Server) ObservePoll(category, kind string, err error, took time.Duration) {
	m := s.metrics()
	res := "ok"
	if err != nil {
		res = "error"
	}
	m.mu.Lock()
	m.polls[[3]string{category, kind, res}]++
	m.pollSum[category] += took.Seconds()
	m.pollCnt[category]++
	m.mu.Unlock()
}

// serveMetrics writes the Prometheus text format by hand (no client library needed for this
// handful of series). Labels hold only fixed words, kinds and categories, never names.
func (s *Server) serveMetrics(w http.ResponseWriter, r *http.Request) {
	if s.MetricsToken != "" {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.MetricsToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ncc metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	var b strings.Builder
	head := func(name, typ, help string) { fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ) }
	head("ncc_build_info", "gauge", "NCC version.")
	fmt.Fprintf(&b, "ncc_build_info{version=%q} 1\n", s.Version)

	m := s.metrics()
	m.mu.Lock()
	head("ncc_http_requests_total", "counter", "HTTP requests by method and status code.")
	keys := make([][2]string, 0, len(m.requests))
	for k := range m.requests {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0]+keys[i][1] < keys[j][0]+keys[j][1] })
	for _, k := range keys {
		fmt.Fprintf(&b, "ncc_http_requests_total{method=%q,code=%q} %d\n", k[0], k[1], m.requests[k])
	}
	head("ncc_http_request_duration_seconds", "summary", "Time spent answering HTTP requests.")
	fmt.Fprintf(&b, "ncc_http_request_duration_seconds_sum %g\nncc_http_request_duration_seconds_count %d\n", m.reqSum, m.reqCount)
	head("ncc_polls_total", "counter", "Connection polls by category, kind and result.")
	pk := make([][3]string, 0, len(m.polls))
	for k := range m.polls {
		pk = append(pk, k)
	}
	sort.Slice(pk, func(i, j int) bool { return strings.Join(pk[i][:], "|") < strings.Join(pk[j][:], "|") })
	for _, k := range pk {
		fmt.Fprintf(&b, "ncc_polls_total{category=%q,kind=%q,result=%q} %d\n", k[0], k[1], k[2], m.polls[k])
	}
	head("ncc_poll_duration_seconds", "summary", "Time spent polling connections, by category.")
	cats := make([]string, 0, len(m.pollCnt))
	for c := range m.pollCnt {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		fmt.Fprintf(&b, "ncc_poll_duration_seconds_sum{category=%q} %g\nncc_poll_duration_seconds_count{category=%q} %d\n", c, m.pollSum[c], c, m.pollCnt[c])
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if ts, err := s.Targets.List(ctx, ""); err == nil {
		head("ncc_connections", "gauge", "Connections by category and state (ok, error, unchecked, disabled).")
		count := map[[2]string]int{}
		for _, t := range ts {
			state := "ok"
			switch {
			case !t.Enabled:
				state = "disabled"
			case t.LastError != "":
				state = "error"
			case t.LastPoll == nil:
				state = "unchecked"
			}
			count[[2]string{t.Category, state}]++
		}
		for _, c := range []string{core.CategoryDevice, core.CategoryDNS, core.CategoryHypervisor, core.CategoryStorage, core.CategorySmartHome, core.CategorySIEM} {
			for _, st := range []string{"ok", "error", "unchecked", "disabled"} {
				fmt.Fprintf(&b, "ncc_connections{category=%q,state=%q} %d\n", c, st, count[[2]string{c, st}])
			}
		}
		var sent, failed, pending strings.Builder
		f := s.siemForwarder()
		for i := range ts {
			t := &ts[i]
			if t.Category != core.CategorySIEM {
				continue
			}
			st, err := f.StatusOf(ctx, t)
			if err != nil {
				continue
			}
			fmt.Fprintf(&sent, "ncc_siem_events_sent_total{connection=%q} %d\n", t.Name, st.Sent)
			fmt.Fprintf(&failed, "ncc_siem_events_failed_total{connection=%q} %d\n", t.Name, st.Failed)
			var n int64
			for _, v := range st.Pending {
				n += v
			}
			fmt.Fprintf(&pending, "ncc_siem_events_pending{connection=%q} %d\n", t.Name, n)
		}
		if sent.Len() > 0 {
			head("ncc_siem_events_sent_total", "counter", "Events delivered to each SIEM connection.")
			b.WriteString(sent.String())
			head("ncc_siem_events_failed_total", "counter", "Events a SIEM connection refused or could not be reached for (they are retried).")
			b.WriteString(failed.String())
			head("ncc_siem_events_pending", "gauge", "Events waiting to be delivered to each SIEM connection.")
			b.WriteString(pending.String())
		}
	}
	vs := s.Vault.Status(ctx)
	head("ncc_vault_sealed", "gauge", "1 while the vault is sealed or not initialized (polling is paused).")
	sealed := 0
	if vs.Sealed || !vs.Initialized {
		sealed = 1
	}
	fmt.Fprintf(&b, "ncc_vault_sealed{backend=%q} %d\n", vs.Backend, sealed)
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

// ---- audit export ----

// exportAudit downloads the whole audit log, oldest first, as CSV (default) or JSON Lines for
// a SIEM. The hash columns let the receiver check the chain itself.
func (s *Server) exportAudit(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format != "" && format != "csv" && format != "jsonl" {
		writeErr(w, 400, "format is csv or jsonl")
		return
	}
	// recorded first: the database has one connection, which the export's query then holds
	_ = s.Audit.Record(r.Context(), actor(r), "audit.export", "ncc", map[string]string{"format": format})
	rows, err := s.Store.DB.QueryContext(r.Context(), `SELECT id, ts, actor, action, target, detail, prev_hash, hash FROM audit_log ORDER BY id`)
	if err != nil {
		s.fail(w, err)
		return
	}
	defer rows.Close()
	stamp := time.Now().UTC().Format("20060102-150405")
	if format == "jsonl" {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="ncc-audit-`+stamp+`.jsonl"`)
		enc := json.NewEncoder(w)
		for rows.Next() {
			var id int64
			var ts, a, act, tg, d, prev, h string
			if err := rows.Scan(&id, &ts, &a, &act, &tg, &d, &prev, &h); err != nil {
				return
			}
			_ = enc.Encode(map[string]any{"id": id, "ts": ts, "actor": a, "action": act, "target": tg, "detail": d, "prev_hash": prev, "hash": h})
		}
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="ncc-audit-`+stamp+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "ts", "actor", "action", "target", "detail", "prev_hash", "hash"})
	for rows.Next() {
		var id int64
		var ts, a, act, tg, d, prev, h string
		if err := rows.Scan(&id, &ts, &a, &act, &tg, &d, &prev, &h); err != nil {
			break
		}
		_ = cw.Write([]string{strconv.FormatInt(id, 10), ts, csvSafe(a), act, csvSafe(tg), csvSafe(d), prev, h})
	}
	cw.Flush()
}

// csvSafe stops a spreadsheet from running a cell as a formula (CSV injection): a user name
// or detail starting with = + - @ gets a leading quote.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
