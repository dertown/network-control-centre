// SIEM Forwarding page (admins): every SIEM connection (Splunk Enterprise Security, Microsoft
// Sentinel, Elastic Security, QRadar, Graylog, ArcSight, syslog) with whether its connection test
// passes, how many events it has taken, what is still waiting and the last delivery error; a
// "Send test event" button; and the network events NCC has noticed lately. Connections are
// added with the Add connection wizard (SIEM group) and edited in Settings.
import { useState } from "react";
import { api, SIEMEvent, SIEMSource, User } from "../api";
import { ago } from "../format";
import { Icon } from "../icons";
import { PageHeader, PageLoading, Tile } from "../ui";
import { ConnectionPicker, RefreshButton, useConnectionAdder, useSourceData } from "../connections";

const addGroup = "siem";

function sevTone(sev: number): "bad" | "warn" | "" {
  return sev >= 7 ? "bad" : sev >= 5 ? "warn" : "";
}

function sevWord(sev: number): string {
  return sev >= 9 ? "critical" : sev >= 7 ? "high" : sev >= 5 ? "medium" : sev >= 3 ? "low" : "info";
}

const minSeverity: Record<string, string> = { "0": "everything", "3": "low and above", "5": "medium and above", "7": "high and above" };

function what(s: SIEMSource): string {
  const parts = [];
  if (s.options.forward_audit === "on") parts.push("audit log");
  if (s.options.forward_network === "on") parts.push("network events");
  if (!parts.length) return "Nothing is selected to send";
  const sev = minSeverity[s.options.min_severity ?? "0"];
  return `Sends the ${parts.join(" and ")}${sev && sev !== "everything" ? `, ${sev}` : ""}`;
}

type Data = { sources: SIEMSource[]; events: SIEMEvent[] };

export function SIEM({ tick, user }: { tick: number; user: User }) {
  const { data, err, setErr, busy, refetch, refresh } = useSourceData<Data>("/api/siem", tick, (d) => d.sources);
  const adder = useConnectionAdder(addGroup, user, refetch);
  const [testing, setTesting] = useState<number | null>(null);
  const [tested, setTested] = useState<Record<number, string>>({});

  if (!data) return <PageLoading title="SIEM Forwarding" err={err} />;
  const { sources, events } = data;

  const sendTest = async (s: SIEMSource) => {
    setTesting(s.id);
    setErr("");
    try {
      await api("POST", `/api/siem/${s.id}/test`);
      setTested((m) => ({ ...m, [s.id]: `Test event sent ${new Date().toLocaleTimeString()}. Search for action ncc.test in ${s.vendor}.` }));
    } catch (e) {
      setTested((m) => ({ ...m, [s.id]: "" }));
      setErr(`${s.name}: ${(e as Error).message}`);
    }
    setTesting(null);
    refetch();
  };

  if (sources.length === 0) {
    return (
      <>
        <h1>SIEM Forwarding</h1>
        <p className="muted lede">Send NCC's audit log and the network events it notices to your SIEM, so security monitoring sees who changed what and when the network had trouble.</p>
        <section className="card">
          <div className="empty" style={{ alignItems: "flex-start", textAlign: "left", padding: 0 }}>
            <span className="tile-icon"><Icon name="shield" size={17} /></span>
            <p style={{ margin: "4px 0 10px" }}>
              No SIEM connected yet. Splunk Enterprise Security takes events through the HTTP Event Collector, Microsoft Sentinel through the Logs
              Ingestion API, Elastic Security through the bulk API, Graylog through a GELF input, and QRadar, ArcSight or any other SIEM over syslog
              in LEEF, CEF or JSON. Tokens and secrets are kept in the vault.
            </p>
          </div>
          <ConnectionPicker group={addGroup} onDone={refetch} primary />
        </section>
        <RecentEvents events={events} />
      </>
    );
  }

  const live = sources.filter((s) => s.enabled);
  const sent = live.reduce((n, s) => n + s.status.sent, 0);
  const pending = live.reduce((n, s) => n + Object.values(s.status.pending).reduce((a, b) => a + b, 0), 0);
  const failing = live.filter((s) => s.last_error || s.status.last_error);

  return (
    <>
      <PageHeader title="SIEM Forwarding">
        {adder.button}
        <RefreshButton user={user} busy={busy} onClick={refresh} />
      </PageHeader>
      {adder.panel}
      <p className="muted lede">
        NCC sends new audit log entries and network events to each connection every few seconds, and keeps retrying until the SIEM accepts them.
      </p>
      {err && <div className="error block">{err}</div>}
      <div className="tiles">
        <Tile label="Connections" value={live.length} sub={`${sources.length - live.length} disabled`} icon="shield" iconTone="c1" />
        <Tile label="Events Sent" value={sent.toLocaleString()} icon="upload" iconTone="c2" />
        <Tile label="Waiting" value={pending.toLocaleString()} sub={pending ? "delivered within seconds when the SIEM answers" : "all caught up"}
          icon="gauge" tone={pending > 1000 ? "warn" : undefined} iconTone="c3" />
        <Tile label="Problems" value={failing.length} sub={failing.length ? failing.map((s) => s.name).join(", ") : "none"} icon="alert"
          tone={failing.length ? "bad" : "good"} />
      </div>
      <section className="card flush">
        <table>
          <thead><tr><th>Connection</th><th>Connection test</th><th>Delivery</th><th>Waiting</th><th /></tr></thead>
          <tbody>
            {sources.map((s) => {
              const waiting = Object.entries(s.status.pending).filter(([, n]) => n > 0);
              return (
                <tr key={s.id}>
                  <td>
                    <strong>{s.name}</strong> <span className="muted small">{s.vendor}</span>
                    <div className="mono small muted">{s.address}</div>
                    <div className="small muted">{what(s)}</div>
                  </td>
                  <td>
                    {!s.enabled ? <span className="pill">disabled</span> : s.last_error ? <span className="pill bad">failing</span>
                      : !s.last_poll ? <span className="pill">not checked</span> : <span className="pill good">ok</span>}
                    {s.last_poll && <span className="muted small"> {ago(s.last_poll)}</span>}
                    {s.last_error ? <div className="error small">{s.last_error}</div> : s.status.info && <div className="small muted">{s.status.info}</div>}
                  </td>
                  <td>
                    <div><strong>{s.status.sent.toLocaleString()}</strong> sent{s.status.failed > 0 && <span className="muted small"> · {s.status.failed.toLocaleString()} retried</span>}</div>
                    <div className="small muted">{s.status.last_sent_at ? `last ${ago(s.status.last_sent_at)}` : "nothing sent yet"}</div>
                    {s.status.last_error && <div className="error small">{s.status.last_error}</div>}
                  </td>
                  <td>{waiting.length ? waiting.map(([k, n]) => <div key={k} className="small">{n.toLocaleString()} {k}</div>) : <span className="muted small">none</span>}</td>
                  <td className="actions">
                    <button className="link" disabled={testing === s.id || !s.enabled} onClick={() => sendTest(s)}>{testing === s.id ? "Sending…" : "Send Test Event"}</button>
                    {tested[s.id] && <div className="small muted">{tested[s.id]}</div>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
      <p className="small"><a href="#/settings">Edit or remove SIEM connections in Settings →</a></p>
      <RecentEvents events={events} />
    </>
  );
}

function RecentEvents({ events }: { events: SIEMEvent[] }) {
  return (
    <section className="card">
      <h2>Recent Network Events</h2>
      <p className="muted small">What NCC noticed while polling: connections going down and coming back, switching loops, storage health. Audit log entries are sent too; see the <a href="#/audit">Audit Log</a>.</p>
      {events.length === 0 ? <p className="muted">No network events yet.</p> : (
        <div className="scroll-x"><table style={{ minWidth: 640 }}>
          <thead><tr><th>When</th><th>Severity</th><th>Event</th><th>Message</th></tr></thead>
          <tbody>
            {events.map((e) => (
              <tr key={e.id}>
                <td className="small">{new Date(e.time).toLocaleString()}</td>
                <td><span className={`pill ${sevTone(e.severity)}`}>{sevWord(e.severity)}</span></td>
                <td className="mono small">{e.type}</td>
                <td className="small wrap">{e.message}</td>
              </tr>
            ))}
          </tbody>
        </table></div>
      )}
    </section>
  );
}
