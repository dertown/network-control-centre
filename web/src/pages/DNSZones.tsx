// DNS page, "Zones & VLANs" tab: which DNS zone each router network (VLAN) uses, what is wrong
// with it (no zone, the zone missing from the DNS server, a zone named for another VLAN, the
// router handing out another search domain, no reverse zone), the zones on each DNS server as
// a tree of subdomains, and a form that creates zones and subdomains and assigns them to VLANs
// through a preview of every step.
import { useEffect, useMemo, useState } from "react";
import { api, User, ZoneMap, ZonePlanRequest, ZonePlanResponse, ZoneRow, ZoneStatus, ZoneUse } from "../api";
import { Modal } from "../ui";

const tone: Record<ZoneStatus, string> = { pass: "good", skip: "", unknown: "", warn: "warn", fail: "bad" };
const label: Record<ZoneStatus, string> = { pass: "OK", skip: "Not checked", unknown: "Can't tell", warn: "Warning", fail: "Problem" };
const stepIcon: Record<string, string> = { create_zone: "+ zone", create_reverse: "+ reverse", delegate: "+ NS", assign: "→ VLAN", dhcp_domain: "router" };

const vlanTag = (r: { vlan: number }) => (r.vlan ? `VLAN ${r.vlan}` : "untagged");
const rowKey = (r: { router_id: number; network_id: string }) => `${r.router_id}/${r.network_id}`;
const has = (r: ZoneRow, code: string) => r.issues.some((i) => i.code === code);
const fq = (z: string) => (z.trim().toLowerCase().replace(/\.+$/, "") + ".");

/** Depth of a zone below its farthest ancestor on the same server, for the tree. */
function depth(z: ZoneUse, all: ZoneUse[]): number {
  let d = 0;
  let p = z.parent;
  while (p) {
    d++;
    p = all.find((o) => o.server_id === z.server_id && o.zone === p)?.parent;
  }
  return d;
}

type Mode = "subdomain" | "zone" | "existing";

interface FormState {
  server: number;
  mode: Mode;
  label: string;
  parent: string;
  name: string;
  existing: string;
  nameservers: string;
  delegate: boolean;
  target: string; // rowKey, "" = don't assign
  dhcp: boolean;
  reverse: boolean;
}

/** ZoneForm creates a zone or subdomain and/or assigns one to a VLAN, through a preview. */
function ZoneForm({ map, init, onClose, onDone }: { map: ZoneMap; init: Partial<FormState>; onClose: () => void; onDone: (msg: string) => void }) {
  const servers = map.servers.filter((s) => !s.error);
  const [f, setF] = useState<FormState>(() => {
    const server = init.server ?? servers.find((s) => s.can_create)?.id ?? servers[0]?.id ?? 0;
    return {
      server, mode: "subdomain", label: "", parent: map.domain ?? "", name: "", existing: "", nameservers: "",
      delegate: true, target: "", dhcp: true, reverse: true, ...init,
    };
  });
  const [plan, setPlan] = useState<ZonePlanResponse["plan"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const set = (p: Partial<FormState>) => { setF((o) => ({ ...o, ...p })); setPlan(null); setErr(""); };

  const srv = servers.find((s) => s.id === f.server);
  const forward = (srv?.zones ?? []).filter((z) => !z.name.endsWith(".arpa.")).map((z) => z.name);
  const row = map.rows.find((r) => rowKey(r) === f.target);
  const zoneName = f.mode === "subdomain" ? (f.label.trim() && f.parent ? fq(`${f.label}.${f.parent}`) : "")
    : f.mode === "zone" ? (f.name.trim() ? fq(f.name) : "") : f.existing;

  const request = (): ZonePlanRequest => {
    const req: ZonePlanRequest = { server_id: f.server, zones: [], assign: [] };
    if (f.mode !== "existing" && zoneName) {
      const ns = f.nameservers.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
      req.zones.push({ name: zoneName, nameservers: ns.length ? ns : undefined, delegate: f.mode === "subdomain" && f.delegate });
    }
    if (row && zoneName) {
      req.assign.push({ zone: zoneName, router_id: row.router_id, network_id: row.network_id, set_dhcp_domain: f.dhcp, reverse: f.reverse });
    }
    return req;
  };

  const send = async (dryRun: boolean) => {
    setBusy(true);
    setErr("");
    try {
      const res = await api<ZonePlanResponse>("POST", "/api/dns/zoneplan", { ...request(), dry_run: dryRun });
      if (dryRun) setPlan(res.plan);
      else onDone(`Done: ${res.results?.length ?? 0} step(s) applied.${res.plan.warnings.length ? " " + res.plan.warnings.join(" ") : ""}`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const assignable = map.rows.filter((r) => r.purpose !== "wan");
  const canPreview = !!zoneName && !!f.server && (f.mode !== "existing" || !!row);

  return (
    <Modal title="DNS zone for a VLAN" onClose={onClose} wide>
      <form className="zone-form" onSubmit={(e) => { e.preventDefault(); send(true); }}>
        <div className="row">
          <label className="grow">DNS server
            <select value={f.server} onChange={(e) => set({ server: Number(e.target.value) })}>
              {servers.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.kind}){s.can_create ? "" : " – can't create zones"}</option>)}
            </select>
          </label>
        </div>
        <div className="seg" role="radiogroup" aria-label="Zone">
          {(["subdomain", "zone", "existing"] as Mode[]).map((m) => (
            <button type="button" key={m} role="radio" aria-checked={f.mode === m} className={f.mode === m ? "on" : ""} onClick={() => set({ mode: m })}>
              {m === "subdomain" ? "New subdomain" : m === "zone" ? "New zone" : "Existing zone"}
            </button>
          ))}
        </div>

        {f.mode === "subdomain" && (
          <>
            <label>Subdomain
              <div className="suffix">
                <input value={f.label} placeholder="iot" autoFocus onChange={(e) => set({ label: e.target.value })} />
                <select value={f.parent} onChange={(e) => set({ parent: e.target.value })} aria-label="Parent zone">
                  {forward.map((z) => <option key={z} value={z}>.{z}</option>)}
                </select>
              </div>
            </label>
            <label className="check"><input type="checkbox" checked={f.delegate} onChange={(e) => set({ delegate: e.target.checked })} /> Delegate it from {f.parent || "the parent zone"} (adds NS records there)</label>
          </>
        )}
        {f.mode === "zone" && (
          <label>Zone name<input value={f.name} placeholder="corp.lan" autoFocus onChange={(e) => set({ name: e.target.value })} /></label>
        )}
        {f.mode === "existing" && (
          <label>Zone
            <select value={f.existing} onChange={(e) => set({ existing: e.target.value })}>
              <option value="">Choose a zone…</option>
              {forward.map((z) => <option key={z} value={z}>{z}</option>)}
            </select>
          </label>
        )}
        {f.mode !== "existing" && (
          <label>Name servers <span className="muted small">(optional; blank copies the parent zone's)</span>
            <input value={f.nameservers} placeholder="ns1.home.lan, ns2.home.lan" onChange={(e) => set({ nameservers: e.target.value })} />
          </label>
        )}

        <label>Assign to VLAN
          <select value={f.target} onChange={(e) => set({ target: e.target.value })}>
            <option value="">Don't assign</option>
            {assignable.map((r) => (
              <option key={rowKey(r)} value={rowKey(r)}>
                {r.network} ({vlanTag(r)}{r.subnet ? `, ${r.subnet}` : ""}){map.routers.length > 1 ? ` on ${r.router}` : ""}{r.zone ? ` – now ${r.zone}` : ""}
              </option>
            ))}
          </select>
        </label>
        {row && (
          <>
            <label className="check">
              <input type="checkbox" checked={f.dhcp} disabled={!row.can_set_domain} onChange={(e) => set({ dhcp: e.target.checked })} />
              Hand out {zoneName ? zoneName.replace(/\.$/, "") : "the zone"} as the network's domain name on {row.router}
              {row.dhcp_domain ? <span className="muted"> (now {row.dhcp_domain})</span> : null}
            </label>
            {row.reverse_zone && (
              <label className="check">
                <input type="checkbox" checked={f.reverse} onChange={(e) => set({ reverse: e.target.checked })} />
                Create the reverse zone <span className="mono">{row.reverse_zone}</span> if missing, so PTR records work
              </label>
            )}
          </>
        )}

        {err && <div className="error block">{err}</div>}
        {plan && (
          <div className="subcard plan">
            <h3>Review before applying</h3>
            {plan.steps.length === 0 ? <p className="muted">Nothing to change.</p> : (
              <ol className="plain zone-steps">
                {plan.steps.map((s, i) => (
                  <li key={i}><span className={`pill ${s.kind === "dhcp_domain" ? "warn" : ""}`}>{stepIcon[s.kind]}</span> {s.title}</li>
                ))}
              </ol>
            )}
            {plan.warnings.map((w) => <div key={w} className="warn-text small">{w}</div>)}
          </div>
        )}
        <div className="modal-actions">
          <button type="button" onClick={onClose}>Cancel</button>
          {plan && plan.steps.length > 0
            ? <button type="button" className="primary" disabled={busy} onClick={() => send(false)}>{busy ? "Applying…" : `Apply ${plan.steps.length} step${plan.steps.length > 1 ? "s" : ""}`}</button>
            : <button className="primary" disabled={!canPreview || busy}>{busy ? "Checking…" : "Preview"}</button>}
        </div>
      </form>
    </Modal>
  );
}

/** SuggestAll plans the suggested zone for every VLAN that has none, in one preview. */
function SuggestAll({ map, rows, onClose, onDone }: { map: ZoneMap; rows: ZoneRow[]; onClose: () => void; onDone: (msg: string) => void }) {
  const server = map.servers.find((s) => s.can_create && !s.error)?.id ?? 0;
  const have = new Set(map.zones.filter((z) => z.server_id === server).map((z) => z.zone));
  const req: ZonePlanRequest = {
    server_id: server,
    zones: [...new Set(rows.map((r) => r.suggested_zone!).filter((z) => !have.has(z)))].map((name) => ({ name, delegate: true })),
    assign: rows.map((r) => ({ zone: r.suggested_zone!, router_id: r.router_id, network_id: r.network_id, set_dhcp_domain: r.can_set_domain, reverse: true })),
  };
  const [plan, setPlan] = useState<ZonePlanResponse["plan"] | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    api<ZonePlanResponse>("POST", "/api/dns/zoneplan", { ...req, dry_run: true }).then((r) => setPlan(r.plan)).catch((e) => setErr(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const apply = async () => {
    setBusy(true);
    try {
      const res = await api<ZonePlanResponse>("POST", "/api/dns/zoneplan", { ...req, dry_run: false });
      onDone(`Done: ${res.results?.length ?? 0} step(s) applied.`);
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  };
  return (
    <Modal title={`Zones for ${rows.length} VLAN${rows.length > 1 ? "s" : ""}`} onClose={onClose} wide>
      <p className="muted small">Each VLAN gets its own subdomain of {map.domain}, delegated from it, with a reverse zone for its subnet,
        and the router hands it out as the network's domain name.</p>
      {!plan && !err && <p className="muted">Planning…</p>}
      {plan && (
        <ol className="plain zone-steps">
          {plan.steps.map((s, i) => <li key={i}><span className={`pill ${s.kind === "dhcp_domain" ? "warn" : ""}`}>{stepIcon[s.kind]}</span> {s.title}</li>)}
        </ol>
      )}
      {plan?.warnings.map((w) => <div key={w} className="warn-text small">{w}</div>)}
      {err && <div className="error block">{err}</div>}
      <div className="modal-actions">
        <button onClick={onClose}>Cancel</button>
        <button className="primary" disabled={!plan || plan.steps.length === 0 || busy} onClick={apply}>{busy ? "Applying…" : `Apply ${plan?.steps.length ?? ""} steps`}</button>
      </div>
    </Modal>
  );
}

export function DNSZones({ user, tick }: { user: User; tick: number }) {
  const admin = user.role === "admin";
  const [map, setMap] = useState<ZoneMap | null>(null);
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [form, setForm] = useState<Partial<FormState> | null>(null);
  const [bulk, setBulk] = useState(false);
  const [confirm, setConfirm] = useState("");
  const load = () => api<ZoneMap>("GET", "/api/dns/zonemap").then((m) => { setMap(m); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [tick]);

  const suggestable = useMemo(() => (map?.rows ?? []).filter((r) => !r.zone && r.suggested_zone && r.status !== "skip"), [map]);

  if (!map) return err ? <div className="error block">{err}</div> : <p className="muted">Loading…</p>;

  const done = (m: string) => { setForm(null); setBulk(false); setMsg(m); load(); };
  const openFor = (r: ZoneRow) => {
    const z = r.zone ?? r.suggested_zone ?? "";
    const exists = map.zones.some((u) => u.zone === z);
    const parent = map.domain && z.endsWith("." + map.domain) ? map.domain : "";
    setForm(exists || !z ? { mode: "existing", existing: z, target: rowKey(r), server: r.server_id }
      : parent ? { mode: "subdomain", label: z.slice(0, -(parent.length + 1)), parent, target: rowKey(r) }
        : { mode: "zone", name: z, target: rowKey(r) });
  };
  const unassign = async (id: number) => {
    try {
      await api("DELETE", `/api/dns/zonemap/${id}`);
      setMsg("Unassigned. The zone itself is untouched.");
      load();
    } catch (e) { setErr((e as Error).message); }
  };
  const deleteZone = async (z: ZoneUse) => {
    try {
      await api("DELETE", `/api/dns/${z.server_id}/zones/${encodeURIComponent(z.zone)}`);
      setMsg(`Deleted ${z.zone} from ${z.server}.`);
      setConfirm("");
      load();
    } catch (e) { setErr((e as Error).message); }
  };

  const canCreate = map.servers.some((s) => s.can_create && !s.error);
  const issues = (r: ZoneRow) => r.issues.filter((i) => i.code !== "no_zone");

  return (
    <>
      <section className="card zone-map">
        <div className="card-head">
          <h2>Zones and VLANs {map.status && <span className={`pill ${tone[map.status]}`}>{label[map.status]}</span>}</h2>
          {admin && (
            <div className="row" style={{ margin: 0 }}>
              {suggestable.length > 0 && canCreate && <button onClick={() => setBulk(true)}>Create suggested zones ({suggestable.length})</button>}
              <button className="primary" disabled={map.servers.length === 0} onClick={() => setForm({})}>New zone or subdomain</button>
            </div>
          )}
        </div>
        <p className="lede">{map.summary}</p>
        {map.domain && <p className="muted small" style={{ marginTop: -6 }}>New VLAN zones are suggested under <span className="mono">{map.domain.replace(/\.$/, "")}</span>.</p>}
        {err && <div className="error block">{err}</div>}
        {msg && <div className="ok block">{msg}</div>}

        {map.rows.length > 0 && (
          <div className="scroll-x">
            <table className="zone-table">
              <thead><tr><th>Network</th><th>DNS zone</th><th>Reverse</th><th>DHCP domain</th><th>Status</th>{admin && <th />}</tr></thead>
              <tbody>
                {map.rows.map((r) => (
                  <tr key={rowKey(r)} className={`zone-row zone-${r.status}`}>
                    <td>
                      <div className="zone-net"><strong>{r.network}</strong> <span className="pill">{vlanTag(r)}</span></div>
                      <div className="muted small">{[r.subnet, r.firewall_zone, map.routers.length > 1 ? r.router : ""].filter(Boolean).join(" · ")}</div>
                    </td>
                    <td>
                      {r.zone ? (
                        <><div className="mono">{r.zone}</div><div className="muted small">{r.server}{has(r, "zone_missing") && " · not found"}</div></>
                      ) : r.suggested_zone ? (
                        <span className="muted">none <span className="small">· suggest <span className="mono">{r.suggested_zone}</span></span></span>
                      ) : <span className="muted">none</span>}
                    </td>
                    <td className="small" data-label="Reverse">
                      {r.zone && r.reverse_zone ? (
                        r.reverse_found ? <span className="good">✓</span> : has(r, "no_reverse") ? <span className="warn-text">missing</span> : <span className="muted">?</span>
                      ) : <span className="muted">–</span>}
                    </td>
                    <td className="mono small" data-label="DHCP domain">{r.dhcp_domain || <span className="muted">–</span>}</td>
                    <td>
                      <span className={`pill ${tone[r.status]}`}>{r.status === "warn" && !r.zone ? "No zone" : label[r.status]}</span>
                      {issues(r).length > 0 && (
                        <ul className="plain zone-issues small">
                          {issues(r).map((i) => <li key={i.code} className={i.severity === "fail" ? "danger" : ""}>{i.message}{i.fix && <span className="muted"> {i.fix.endsWith(".") ? i.fix : i.fix + "."}</span>}</li>)}
                        </ul>
                      )}
                    </td>
                    {admin && (
                      <td className="actions">
                        {r.status !== "skip" || r.zone ? (
                          <>
                            <button className="link" onClick={() => openFor(r)}>{r.zone ? (r.status === "pass" ? "Change" : "Fix") : "Assign"}</button>
                            {r.assignment_id && <button className="link danger" onClick={() => unassign(r.assignment_id!)}>Unassign</button>}
                          </>
                        ) : <button className="link" onClick={() => openFor(r)}>Assign</button>}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {map.orphans.length > 0 && (
          <div className="dns-check bad zone-orphans">
            <strong>Assignments to networks that no longer exist</strong>
            <ul className="plain small">
              {map.orphans.map((o) => (
                <li key={o.id} className="row-between">
                  <span><span className="mono">{o.zone}</span> → {o.network} (VLAN {o.vlan || "untagged"})</span>
                  {admin && <button className="link danger" onClick={() => unassign(o.id)}>Remove</button>}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>

      <section className="card">
        <h2>Zones on your DNS servers</h2>
        {map.servers.map((s) => s.error && <div key={s.id} className="error block">{s.name}: {s.error}</div>)}
        {map.zones.length === 0 ? <p className="muted">No zones yet.</p> : (
          <ul className="plain zone-tree">
            {map.zones.map((z) => {
              const d = depth(z, map.zones);
              const k = `${z.server_id}/${z.zone}`;
              return (
                <li key={k} style={{ paddingLeft: d * 22 }}>
                  <span className="mono">{d > 0 && <span className="muted">└ </span>}{z.zone}</span>
                  {z.reverse && <span className="pill">reverse</span>}
                  {map.servers.length > 1 && <span className="muted small">{z.server}</span>}
                  <span className="grow" />
                  {z.networks.map((n) => <span key={n} className="pill good">{n}</span>)}
                  {admin && z.networks.length === 0 && map.servers.find((s) => s.id === z.server_id)?.can_create && (
                    confirm === k
                      ? <span className="small">Delete {z.zone} and all its records? <button className="link danger" onClick={() => deleteZone(z)}>Delete</button> <button className="link" onClick={() => setConfirm("")}>Keep</button></span>
                      : <button className="link danger small" onClick={() => setConfirm(k)}>Delete</button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </section>

      {form && <ZoneForm map={map} init={form} onClose={() => setForm(null)} onDone={done} />}
      {bulk && <SuggestAll map={map} rows={suggestable} onClose={() => setBulk(false)} onDone={done} />}
    </>
  );
}
