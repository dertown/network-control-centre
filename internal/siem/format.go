package siem

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The wire formats NCC can write: ArcSight CEF, IBM LEEF, JSON documents (Splunk, Sentinel,
// Elastic in ECS, Graylog GELF) and RFC 5424 syslog lines carrying any of them.

// CEF formats an event as ArcSight Common Event Format (CEF:0).
func CEF(e Event) string {
	var b strings.Builder
	b.WriteString("CEF:0|")
	for _, h := range []string{VendorName, ProductName, Version, e.Type, e.Message} {
		b.WriteString(cefHeader(h))
		b.WriteByte('|')
	}
	b.WriteString(strconv.Itoa(clampSev(e.Severity)))
	b.WriteByte('|')
	ext := [][2]string{
		{"rt", strconv.FormatInt(e.Time.UnixMilli(), 10)},
		{"externalId", e.ExternalID()},
		{"cat", e.Category()},
		{"outcome", e.Outcome()},
		{"dvchost", Host},
		{"suser", e.Actor},
		{"cs1Label", "target"}, {"cs1", e.Target},
		{"cs2Label", "source"}, {"cs2", e.Source},
		{"msg", e.Message},
	}
	if e.Detail != "" {
		ext = append(ext, [2]string{"cs3Label", "detail"}, [2]string{"cs3", e.Detail})
	}
	if ip := e.ClientIP(); ip != "" {
		ext = append(ext, [2]string{"src", ip})
	}
	first := true
	for _, kv := range ext {
		if kv[1] == "" {
			continue
		}
		if !first {
			b.WriteByte(' ')
		}
		first = false
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(cefExt(kv[1]))
	}
	return b.String()
}

func cefHeader(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", " ", "\n", " ").Replace(s)
}

func cefExt(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r", `\r`, "\n", `\n`).Replace(s)
}

// LEEF formats an event as IBM QRadar Log Event Extended Format 1.0 (tab-separated attributes).
func LEEF(e Event) string {
	var b strings.Builder
	b.WriteString("LEEF:1.0|")
	for _, h := range []string{VendorName, ProductName, Version, e.Type} {
		b.WriteString(strings.NewReplacer(`|`, `\|`, "\t", " ", "\r", " ", "\n", " ").Replace(h))
		b.WriteByte('|')
	}
	attrs := [][2]string{
		{"devTime", e.Time.UTC().Format("Jan 02 2006 15:04:05")},
		{"devTimeFormat", "MMM dd yyyy HH:mm:ss"},
		{"sev", strconv.Itoa(clampSev(e.Severity))},
		{"cat", e.Category()},
		{"usrName", e.Actor},
		{"resource", e.Target},
		{"outcome", e.Outcome()},
		{"externalId", e.ExternalID()},
		{"msg", e.Message},
		{"detail", e.Detail},
		{"src", e.ClientIP()},
	}
	first := true
	for _, kv := range attrs {
		if kv[1] == "" {
			continue
		}
		if !first {
			b.WriteByte('\t')
		}
		first = false
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(kv[1]))
	}
	return b.String()
}

// Doc is the event as a flat JSON object with CIM-friendly names (Splunk, Sentinel and the
// syslog "json" format use it): action, user, src, dest, severity, vendor_product...
func Doc(e Event) map[string]any {
	d := map[string]any{
		"time": e.Time.UTC().Format(time.RFC3339Nano), "id": e.ExternalID(), "source": e.Source, "category": e.Category(),
		"action": e.Type, "signature": e.Type, "severity": SeverityWord(e.Severity), "severity_id": e.Severity, "outcome": e.Outcome(),
		"message": e.Message, "vendor_product": VendorName + " " + ProductName, "dvc": Host,
	}
	if e.Actor != "" {
		d["user"] = e.Actor
	}
	if e.Target != "" {
		d["dest"] = e.Target
		d["object"] = e.Target
	}
	if ip := e.ClientIP(); ip != "" {
		d["src"] = ip
	}
	if det := e.DetailValue(); det != nil {
		d["detail"] = det
	}
	for k, v := range e.Fields {
		if _, taken := d[k]; !taken {
			d[k] = v
		}
	}
	return d
}

// ECS is the event as an Elastic Common Schema document, so Elastic Security's views and
// detection rules can read it.
func ECS(e Event) map[string]any {
	d := map[string]any{
		"@timestamp": e.Time.UTC().Format(time.RFC3339Nano),
		"message":    e.Message,
		"event": map[string]any{
			"kind": "event", "id": e.ExternalID(), "action": e.Type, "severity": e.Severity, "outcome": e.Outcome(),
			"category": ecsCategory(e), "type": ecsType(e), "module": "ncc", "dataset": "ncc." + e.Source, "provider": e.Source,
		},
		"observer": map[string]any{"vendor": VendorName, "product": ProductName, "hostname": Host, "version": Version, "type": "network-management"},
		"ecs":      map[string]any{"version": "8.11.0"},
		"labels":   map[string]any{"ncc_target": e.Target},
	}
	if e.Actor != "" {
		d["user"] = map[string]any{"name": e.Actor}
	}
	if ip := e.ClientIP(); ip != "" {
		d["source"] = map[string]any{"ip": ip}
	}
	ncc := map[string]any{"target": e.Target}
	if det := e.DetailValue(); det != nil {
		ncc["detail"] = det
	}
	for k, v := range e.Fields {
		ncc[k] = v
	}
	d["ncc"] = ncc
	return d
}

func ecsCategory(e Event) []string {
	switch e.Category() {
	case "authentication":
		return []string{"authentication"}
	case "network":
		return []string{"network"}
	case "test":
		return []string{"process"}
	}
	return []string{"configuration"}
}

func ecsType(e Event) []string {
	t := strings.ToLower(e.Type)
	switch {
	case e.Category() == "authentication" && strings.HasPrefix(t, "login"):
		return []string{"start"}
	case strings.Contains(t, "create"), strings.Contains(t, "add"):
		return []string{"creation"}
	case strings.Contains(t, "delete"), strings.Contains(t, "remove"):
		return []string{"deletion"}
	case e.Category() == "network":
		return []string{"connection"}
	}
	return []string{"change"}
}

// GELF formats an event as a Graylog Extended Log Format 1.1 message.
func GELF(e Event) map[string]any {
	d := map[string]any{
		"version": "1.1", "host": Host, "short_message": e.Message,
		"timestamp": float64(e.Time.UnixMilli()) / 1000, "level": SyslogSeverity(e.Severity),
		"_ncc_id": e.ExternalID(), "_ncc_source": e.Source, "_event_type": e.Type, "_category": e.Category(),
		"_severity": e.Severity, "_outcome": e.Outcome(), "_application_name": "ncc",
	}
	if e.Actor != "" {
		d["_user"] = e.Actor
	}
	if e.Target != "" {
		d["_target"] = e.Target
	}
	if ip := e.ClientIP(); ip != "" {
		d["_src_ip"] = ip
	}
	if e.Detail != "" {
		d["full_message"] = e.Detail
	}
	for k, v := range e.Fields {
		k = "_" + strings.Map(func(r rune) rune {
			if r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
				return r
			}
			return '_'
		}, k)
		if _, taken := d[k]; !taken && k != "_id" {
			d[k] = v
		}
	}
	return d
}

// Syslog wraps a message in an RFC 5424 syslog line (without framing). facility is the
// syslog facility number (16 = local0 ... 23 = local7).
func Syslog(e Event, facility int, msg string) string {
	pri := facility*8 + SyslogSeverity(e.Severity)
	msgid := strings.Map(func(r rune) rune {
		if r <= 32 || r >= 127 {
			return '_'
		}
		return r
	}, e.Type)
	if len(msgid) > 32 {
		msgid = msgid[:32]
	}
	if msgid == "" {
		msgid = "-"
	}
	host := Host
	if host == "" {
		host = "-"
	}
	return fmt.Sprintf("<%d>1 %s %s ncc - %s - %s", pri, e.Time.UTC().Format("2006-01-02T15:04:05.000Z"), host, msgid, msg)
}

// DetailValue is the audit detail as JSON when it parses, else the text, or nil when empty.
func (e Event) DetailValue() any {
	if e.Detail == "" {
		return nil
	}
	var v any
	if json.Unmarshal([]byte(e.Detail), &v) == nil {
		return v
	}
	return e.Detail
}

// ClientIP is the client address recorded with sign-ins ("ip" in the audit detail), if any.
func (e Event) ClientIP() string {
	if ip := e.Fields["src"]; ip != "" {
		return ip
	}
	if !strings.Contains(e.Detail, `"ip"`) {
		return ""
	}
	var m map[string]any
	if json.Unmarshal([]byte(e.Detail), &m) != nil {
		return ""
	}
	s, _ := m["ip"].(string)
	return s
}

func clampSev(s int) int {
	if s < 0 {
		return 0
	}
	if s > 10 {
		return 10
	}
	return s
}
