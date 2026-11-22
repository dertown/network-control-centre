// DNS page: browse a PowerDNS server's zones and records and add, change or delete records,
// always through a preview of the exact changes (including the automatic PTR records).
import { useEffect, useMemo, useState } from "react";
import { api, Change, RRSet, Target, User, Zone, ZonePlan } from "../api";

const TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "SRV", "PTR", "NS", "CAA"];

function hashParams(): URLSearchParams {
  const h = window.location.hash;
  const i = h.indexOf("?");
  return new URLSearchParams(i >= 0 ? h.slice(i + 1) : "");
}

function relative(name: string, zone: string) {
  if (name === zone) return "@";
  return name.endsWith("." + zone) ? name.slice(0, -(zone.length + 1)) : name;
}

export function DNS({ user }: { user: User }) {
  const canWrite = user.role !== "viewer";
  const [servers, setServers] = useState<Target[]>([]);
  const [server, setServer] = useState<number | null>(null);
  const [zones, setZones] = useState<Zone[]>([]);
  const [zone, setZone] = useState("");
  const [records, setRecords] = useState<RRSet[]>([]);
  const [filter, setFilter] = useState("");
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const pre = hashParams();
  const [form, setForm] = useState({ name: pre.get("name") ?? "", type: pre.get("ip")?.includes(":") ? "AAAA" : "A", ttl: 3600, value: pre.get("ip") ?? "", ptr: true });
  const [plan, setPlan] = useState<{ plan: ZonePlan[]; warnings: string[] | null; changes: Change[] } | null>(null);

  useEffect(() => {
    api<Target[]>("GET", "/api/targets?category=dns").then((ts) => {
      setServers(ts);
      if (ts.length && server === null) setServer(ts[0].id);
    }).catch((e) => setErr(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (server === null) return;
    setErr("");
    api<Zone[]>("GET", `/api/dns/${server}/zones`).then((zs) => {
      setZones(zs);
      const forward = zs.find((z) => !z.name.endsWith(".arpa."));
      setZone((cur) => (zs.some((z) => z.name === cur) ? cur : forward?.name ?? zs[0]?.name ?? ""));
    }).catch((e) => setErr(e.message));
  }, [server]);

  const load = () => {
    if (server === null || !zone) return;
    api<RRSet[]>("GET", `/api/dns/${server}/zones/${encodeURIComponent(zone)}/records`).then(setRecords).catch((e) => setErr(e.message));
  };
  useEffect(load, [server, zone]);

  const shown = useMemo(() => {
    const f = filter.toLowerCase();
    return records.filter((r) => !f || r.name.includes(f) || r.records.some((v) => v.toLowerCase().includes(f)) || r.type.toLowerCase() === f);
  }, [records, filter]);

  const submit = async (changes: Change[], ptr: boolean, dryRun: boolean) => {
    setErr("");
    setMsg("");
    try {
      const res = await api<{ applied: boolean; plan: ZonePlan[]; warnings: string[] | null }>(
        "POST", `/api/dns/${server}/zones/${encodeURIComponent(zone)}/changes`, { changes, ptr, dry_run: dryRun });
      if (dryRun) setPlan({ ...res, changes });
      else {
        setPlan(null);
        setMsg(`Applied ${res.plan.reduce((n, p) => n + p.changes.length, 0)} change(s).${res.warnings?.length ? " " + res.warnings.join(" ") : ""}`);
        load();
      }
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const preview = (e: React.FormEvent) => {
    e.preventDefault();
    const values = form.value.split("\n").map((v) => v.trim()).filter(Boolean);
    submit([{ op: "REPLACE", rrset: { name: form.name || "@", type: form.type, ttl: Number(form.ttl), records: values } }], form.ptr && (form.type === "A" || form.type === "AAAA"), true);
  };

  const remove = (r: RRSet) => {
    submit([{ op: "DELETE", rrset: { name: r.name, type: r.type, ttl: 0, records: [] } }], r.type === "A" || r.type === "AAAA", true);
  };

  const edit = (r: RRSet) => setForm({ name: relative(r.name, zone), type: r.type, ttl: r.ttl, value: r.records.join("\n"), ptr: true });

  if (servers.length === 0) {
    return (
      <>
        <h1>DNS</h1>
        <p className="muted">No DNS servers yet. Add your PowerDNS server in <a href="#/settings">Settings</a>.</p>
        {err && <div className="error">{err}</div>}
      </>
    );
  }

  return (
    <>
      <h1>DNS</h1>
      <div className="toolbar">
        <select value={server ?? ""} onChange={(e) => setServer(Number(e.target.value))}>
          {servers.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.kind})</option>)}
        </select>
        <select value={zone} onChange={(e) => setZone(e.target.value)}>
          {zones.map((z) => <option key={z.name} value={z.name}>{z.name}</option>)}
        </select>
        <input placeholder="Filter records" value={filter} onChange={(e) => setFilter(e.target.value)} />
      </div>
      {err && <div className="error block">{err}</div>}
      {msg && <div className="ok block">{msg}</div>}

      <div className="split">
        <div className="card flush">
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Value</th>{canWrite && <th />}</tr></thead>
            <tbody>
              {shown.map((r) => (
                <tr key={r.name + r.type}>
                  <td className="mono">{relative(r.name, zone)}</td>
                  <td><span className="pill">{r.type}</span></td>
                  <td>{r.ttl}</td>
                  <td className="mono wrap">{r.records.map((v) => <div key={v}>{v}</div>)}</td>
                  {canWrite && (
                    <td className="actions">
                      {r.type !== "SOA" && <button className="link" onClick={() => edit(r)}>Edit</button>}
                      {r.type !== "SOA" && r.type !== "NS" && <button className="link danger" onClick={() => remove(r)}>Delete</button>}
                    </td>
                  )}
                </tr>
              ))}
              {shown.length === 0 && <tr><td colSpan={5} className="muted">No records.</td></tr>}
            </tbody>
          </table>
        </div>

        {canWrite && (
          <div>
            <form className="card" onSubmit={preview}>
              <h2>Add or replace a record</h2>
              <label>Name<div className="suffix"><input value={form.name} placeholder="nas" onChange={(e) => setForm({ ...form, name: e.target.value })} /><span className="muted">.{zone}</span></div></label>
              <div className="row">
                <label>Type<select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>{TYPES.map((t) => <option key={t}>{t}</option>)}</select></label>
                <label>TTL (s)<input type="number" min={0} value={form.ttl} onChange={(e) => setForm({ ...form, ttl: Number(e.target.value) })} /></label>
              </div>
              <label>Value (one per line)<textarea rows={3} value={form.value} placeholder={form.type === "A" ? "192.168.1.50" : ""} onChange={(e) => setForm({ ...form, value: e.target.value })} /></label>
              {(form.type === "A" || form.type === "AAAA") && (
                <label className="check"><input type="checkbox" checked={form.ptr} onChange={(e) => setForm({ ...form, ptr: e.target.checked })} /> Also create the reverse (PTR) record</label>
              )}
              <button className="primary">Preview change</button>
            </form>

            {plan && (
              <div className="card plan">
                <h2>Review before applying</h2>
                {plan.plan.map((p) => (
                  <div key={p.zone}>
                    <div className="muted small">Zone {p.zone}</div>
                    <ul className="plain mono small">
                      {p.changes.map((c, i) => (
                        <li key={i}>
                          <span className={c.op === "DELETE" ? "danger" : "good"}>{c.op === "DELETE" ? "− delete" : "+ set"}</span>{" "}
                          {c.rrset.name} {c.rrset.type}{c.op !== "DELETE" && <> {c.rrset.ttl} {c.rrset.records.join(", ")}</>}
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
                {plan.warnings?.map((w) => <div key={w} className="warn-text small">{w}</div>)}
                <div className="row">
                  <button className="primary" onClick={() => submit(plan.changes, plan.plan.length > 1, false)}>Apply</button>
                  <button onClick={() => setPlan(null)}>Cancel</button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </>
  );
}
