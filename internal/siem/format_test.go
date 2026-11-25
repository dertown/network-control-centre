package siem

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var at = time.Date(2026, 11, 25, 3, 4, 5, 0, time.UTC)

func sample() Event {
	return Event{ID: 42, Source: SourceAudit, Time: at, Type: "login.failed", Severity: SevHigh, Actor: "eve",
		Target: "ncc", Message: "Failed NCC sign-in as eve | from x=y", Detail: `{"ip":"10.0.0.9"}`}
}

func TestCEF(t *testing.T) {
	Host = "ncc-host"
	got := CEF(sample())
	for _, want := range []string{
		"CEF:0|NCC|Network Control Centre|", "|login.failed|Failed NCC sign-in as eve \\| from x=y|7|",
		"rt=" + "1795575845000", "externalId=audit-42", "suser=eve", "src=10.0.0.9", "cat=authentication", "outcome=failure",
		`msg=Failed NCC sign-in as eve | from x\=y`, `cs3={"ip":"10.0.0.9"}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("CEF missing %q in\n%s", want, got)
		}
	}
	e := sample()
	e.Message = "two\nlines"
	if strings.Contains(CEF(e), "\n") {
		t.Error("CEF must stay on one line")
	}
}

func TestLEEF(t *testing.T) {
	got := LEEF(sample())
	if !strings.HasPrefix(got, "LEEF:1.0|NCC|Network Control Centre|") {
		t.Fatalf("header: %s", got)
	}
	parts := strings.SplitN(got, "|", 6)
	attrs := map[string]string{}
	for _, kv := range strings.Split(parts[5], "\t") {
		k, v, _ := strings.Cut(kv, "=")
		attrs[k] = v
	}
	if attrs["usrName"] != "eve" || attrs["sev"] != "7" || attrs["src"] != "10.0.0.9" || attrs["devTime"] != "Nov 25 2026 03:04:05" {
		t.Errorf("attrs %v", attrs)
	}
}

func TestSyslogLine(t *testing.T) {
	Host = "ncc-host"
	got := Syslog(sample(), 20, "payload")
	// local4 (20) * 8 + error (3) = 163
	if got != "<163>1 2026-11-25T03:04:05.000Z ncc-host ncc - login.failed - payload" {
		t.Errorf("got %q", got)
	}
}

func TestDocAndECS(t *testing.T) {
	d := Doc(sample())
	if d["user"] != "eve" || d["src"] != "10.0.0.9" || d["severity"] != "high" || d["action"] != "login.failed" {
		t.Errorf("doc %v", d)
	}
	b, _ := json.Marshal(ECS(sample()))
	var ecs struct {
		Event struct {
			Category []string `json:"category"`
			Outcome  string   `json:"outcome"`
		} `json:"event"`
		Source struct {
			IP string `json:"ip"`
		} `json:"source"`
	}
	_ = json.Unmarshal(b, &ecs)
	if ecs.Event.Category[0] != "authentication" || ecs.Event.Outcome != "failure" || ecs.Source.IP != "10.0.0.9" {
		t.Errorf("ecs %s", b)
	}
	g := GELF(Event{Source: SourceNetwork, Time: at, Type: "connection.down", Severity: SevHigh, Message: "m", Fields: map[string]string{"id": "x", "a b": "1"}})
	if g["level"] != 3 || g["_a_b"] != "1" || g["_id"] != nil {
		t.Errorf("gelf %v", g)
	}
}

func TestWants(t *testing.T) {
	opts := map[string]string{OptAudit: "on", OptMinSeverity: "5"}
	if Wants(opts, Event{Source: SourceAudit, Severity: SevLow}) {
		t.Error("low event passed a medium threshold")
	}
	if !Wants(opts, Event{Source: SourceAudit, Severity: SevHigh}) {
		t.Error("high audit event dropped")
	}
	if Wants(opts, Event{Source: SourceNetwork, Severity: SevCritical}) {
		t.Error("network events are off")
	}
	if !Wants(opts, Event{Source: SourceTest, Severity: SevCritical}) {
		t.Error("test events always pass the source check")
	}
}

func TestSeverityFor(t *testing.T) {
	if SeverityFor("login.failed") != SevHigh || SeverityFor("target.delete") != SevMedium || SeverityFor("login") != SevLow {
		t.Error("severity mapping changed")
	}
}
