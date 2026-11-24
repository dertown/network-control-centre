// IoT devices page: the company's IoT inventory (cameras, printers, phones, room systems,
// signage, door controllers, building controllers, UPSs, sensors...) found among the
// network's clients, with where each one is, who owns it and whether it sits on an IoT
// network. The second tab is the smart home controls from Home Assistant.
import { ReactNode, useEffect, useMemo, useState } from "react";
import { api, IoTCandidate, IoTDevice, IoTNetwork, IoTPatch, IoTView, Target, User } from "../api";
import { ago } from "../format";
import { Icon, IconName } from "../icons";
import { Modal, PageHeader, PageLoading, Tile } from "../ui";
import { pollNow } from "../connections";
import { SmartHome } from "./SmartHome";

const TITLE = "IoT Devices";

export const typeInfo: Record<string, { label: string; one: string; icon: IconName }> = {
  camera: { label: "Cameras", one: "Camera", icon: "camera" },
  access: { label: "Doors and access", one: "Door or access", icon: "door" },
  printer: { label: "Printers and scanners", one: "Printer", icon: "printer" },
  phone: { label: "Phones", one: "Phone", icon: "deskphone" },
  conference: { label: "Meeting rooms", one: "Meeting room", icon: "users" },
  display: { label: "Displays and signage", one: "Display", icon: "tv" },
  building: { label: "Building systems", one: "Building system", icon: "building" },
  sensor: { label: "Sensors", one: "Sensor", icon: "gauge" },
  power: { label: "Power (UPS, PDU, plugs)", one: "Power", icon: "power" },
  lighting: { label: "Lighting", one: "Lighting", icon: "bulb" },
  speaker: { label: "Speakers", one: "Speaker", icon: "speaker" },
  other: { label: "Other IoT", one: "Other", icon: "plug" },
};
const tinfo = (t: string) => typeInfo[t] ?? typeInfo.other;

type Tab = "inventory" | "controls";
type Group = "location" | "type" | "network";
type Show = "all" | "attention" | "unassigned" | "ignored";

function loadPref<T extends string>(key: string, ok: readonly T[], def: T): T {
  try { const v = localStorage.getItem(key) as T; return ok.includes(v) ? v : def; } catch { return def; }
}
function savePref(key: string, v: string) { try { localStorage.setItem(key, v); } catch { /* storage blocked */ } }

/** IoT is the page: a tab bar over the inventory and the smart home controls. */
export function IoT({ tick, user }: { tick: number; user: User }) {
  const [tab, setTab] = useState<Tab>(() => {
    const q = new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("tab");
    return q === "controls" || q === "inventory" ? q : loadPref("ncc-iot-tab", ["inventory", "controls"] as const, "inventory");
  });
  useEffect(() => savePref("ncc-iot-tab", tab), [tab]);
  const nav = (
    <div className="seg iot-tabs" role="tablist" aria-label="IoT view">
      <button role="tab" aria-selected={tab === "inventory"} className={tab === "inventory" ? "on" : ""} onClick={() => setTab("inventory")}>Inventory</button>
      <button role="tab" aria-selected={tab === "controls"} className={tab === "controls" ? "on" : ""} onClick={() => setTab("controls")}>Smart home controls</button>
    </div>
  );
  return tab === "controls" ? <SmartHome tick={tick} user={user} title={TITLE} nav={nav} /> : <Inventory tick={tick} user={user} nav={nav} />;
}

const floorText = (f: string) => (/^\d+$/.test(f) ? `Floor ${f}` : f);
const floorRoom = (d: IoTDevice) => [d.floor && floorText(d.floor), d.room].filter(Boolean).join(" · ");
const locationText = (d: IoTDevice) => [d.building, floorRoom(d)].filter(Boolean).join(" · ");

function Inventory({ tick, user, nav }: { tick: number; user: User; nav: ReactNode }) {
  const [view, setView] = useState<IoTView | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [show, setShow] = useState<Show>("all");
  const [group, setGroup] = useState<Group>(() => loadPref("ncc-iot-inv-group", ["location", "type", "network"] as const, "location"));
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<IoTDevice | null>(null);
  const [bulk, setBulk] = useState(false);
  const [adding, setAdding] = useState(false);
  const [nets, setNets] = useState(false);
  const [flash, setFlash] = useState("");
  const canEdit = user.role !== "viewer";
  const isAdmin = user.role === "admin";
  useEffect(() => savePref("ncc-iot-inv-group", group), [group]);

  const refetch = () => api<IoTView>("GET", "/api/iot").then((v) => { setView(v); setErr(""); }).catch((e) => setErr((e as Error).message));
  useEffect(() => { refetch(); }, [tick]);

  const devices = view?.devices ?? [];
  const active = devices.filter((d) => !d.ignored);
  const shown = useMemo(() => {
    const s = q.trim().toLowerCase();
    return devices.filter((d) =>
      (show === "ignored" ? d.ignored : !d.ignored) &&
      (show !== "attention" || d.issues.includes("wrong_network") || d.issues.includes("offline")) &&
      (show !== "unassigned" || d.issues.includes("no_location") || d.issues.includes("no_owner")) &&
      (!type || d.type === type) &&
      (!s || [d.name, d.hostname, d.ip, d.mac, d.vendor, d.model, d.owner, d.site, d.building, d.floor, d.room, d.network, d.notes]
        .some((x) => x?.toLowerCase().includes(s))));
  }, [devices, q, type, show]);

  const groups = useMemo(() => {
    const by = new Map<string, IoTDevice[]>();
    const keyOf = (d: IoTDevice) => group === "type" ? tinfo(d.type).label
      : group === "network" ? (d.network ? `${d.network}${d.vlan ? ` · VLAN ${d.vlan}` : ""}` : "Unknown network")
      : [d.site, d.building].filter(Boolean).join(" · ");
    for (const d of shown) {
      const k = keyOf(d);
      by.set(k, [...(by.get(k) ?? []), d]);
    }
    const order = group === "type" ? Object.values(typeInfo).map((t) => t.label) : null;
    return [...by.entries()].sort(([a], [b]) => {
      if (a === "") return 1;
      if (b === "") return -1;
      return order ? order.indexOf(a) - order.indexOf(b) : a.localeCompare(b);
    });
  }, [shown, group]);

  // keep the selection to devices still on screen
  useEffect(() => {
    const vis = new Set(shown.map((d) => d.mac));
    setSel((s) => { const n = new Set([...s].filter((m) => vis.has(m))); return n.size === s.size ? s : n; });
  }, [shown]);

  if (!view) return <PageLoading title={TITLE} err={err} />;

  const online = active.filter((d) => d.online).length;
  const wrong = active.filter((d) => d.issues.includes("wrong_network"));
  const offline = active.filter((d) => d.issues.includes("offline"));
  const unassigned = active.filter((d) => d.issues.includes("no_location") || d.issues.includes("no_owner"));
  const iotNets = view.networks.filter((n) => n.iot);
  const sites = new Set(active.map((d) => d.site).filter(Boolean));

  const patch = async (macs: string[], p: IoTPatch, msg: string) => {
    try {
      await api("PUT", "/api/iot/devices", { macs, ...p });
      setFlash(msg);
      setSel(new Set());
      await refetch();
    } catch (e) { setErr((e as Error).message); }
  };

  const refresh = async () => {
    setBusy(true);
    try {
      const ts = await api<(Target & { enabled: boolean; id: number; name: string })[]>("GET", "/api/targets?category=device");
      setErr(await pollNow(ts));
    } catch (e) { setErr((e as Error).message); }
    setBusy(false);
    refetch();
  };

  const toggle = (mac: string) => setSel((s) => { const n = new Set(s); n.has(mac) ? n.delete(mac) : n.add(mac); return n; });
  const selDevs = devices.filter((d) => sel.has(d.mac));
  const selWrong = selDevs.filter((d) => d.issues.includes("wrong_network"));

  return (
    <>
      <PageHeader title={TITLE}>
        {canEdit && <button onClick={() => setAdding(true)}><Icon name="plus" size={15} />Add device</button>}
        <button onClick={() => setNets(true)}><Icon name="vlan" size={15} />IoT networks</button>
        <button onClick={() => exportCSV(shown)} disabled={shown.length === 0}><Icon name="download" size={15} />Export CSV</button>
        {canEdit && <button onClick={refresh} disabled={busy}>{busy ? "Refreshing…" : "Refresh now"}</button>}
      </PageHeader>
      {nav}
      <p className="muted lede">
        {active.length} device{active.length === 1 ? "" : "s"}{sites.size > 0 && <> across {sites.size} site{sites.size === 1 ? "" : "s"}</>}
        {" · "}found among your network's clients by vendor and name{canEdit && ", add any NCC missed"}
        {" · "}IoT networks: {iotNets.length ? iotNets.map((n) => n.vlan ? `${n.name} (VLAN ${n.vlan})` : n.name).join(", ") : "none yet"}
        {!view.networks_chosen && iotNets.length > 0 && " (guessed from their names)"}
      </p>
      {err && <div className="error block">{err}</div>}
      {flash && <div className="banner good" role="status"><Icon name="check" size={16} /><span>{flash}</span><button className="link" onClick={() => setFlash("")}>Dismiss</button></div>}
      {view.sources === 0 && (
        <div className="banner warn"><Icon name="alert" size={16} /><span>NCC finds IoT devices among your router's clients. Connect your UniFi console under <a href="#/settings">Settings</a> first.</span></div>
      )}
      {view.sources > 0 && iotNets.length === 0 && (
        <div className="banner warn"><Icon name="alert" size={16} /><span>No network is marked as an IoT network yet, so NCC can't tell which devices are in the wrong place.</span>
          <button onClick={() => setNets(true)}>Choose IoT networks</button></div>
      )}

      <div className="tiles">
        <Tile label="Online" icon={online === active.length ? "check" : "alert"} tone={active.length && online === active.length ? "good" : undefined}
          value={<>{online}<small> / {active.length}</small></>} sub={`${new Set(active.map((d) => d.type)).size} kinds of device`} />
        <IssueTile label="Not on an IoT network" icon="vlan" n={wrong.length} tone="bad" on={show === "attention" && wrong.length > 0} onClick={() => setShow(show === "attention" ? "all" : "attention")}
          sub={wrong.length ? wrong.slice(0, 3).map((d) => d.name).join(", ") : "every device is where it should be"} />
        <IssueTile label="Offline" icon="power" n={offline.length} tone="warn" on={show === "attention" && offline.length > 0} onClick={() => setShow(show === "attention" ? "all" : "attention")}
          sub={offline.length ? offline.slice(0, 3).map((d) => `${d.name} (${ago(d.last_seen)})`).join(", ") : "all answering"} />
        <IssueTile label="No location or owner" icon="building" n={unassigned.length} tone="warn" on={show === "unassigned"} onClick={() => setShow(show === "unassigned" ? "all" : "unassigned")}
          sub={unassigned.length ? "select them and set where they are" : "every device has a home"} />
      </div>

      <div className="toolbar">
        <input type="search" placeholder="Search name, IP, MAC, vendor, owner, room" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search devices" />
        <select value={type} onChange={(e) => setType(e.target.value)} aria-label="Type">
          <option value="">All types</option>
          {view.types.map((t) => <option key={t} value={t}>{tinfo(t).label}</option>)}
        </select>
        <select value={show} onChange={(e) => setShow(e.target.value as Show)} aria-label="Show">
          <option value="all">All devices</option>
          <option value="attention">Needs attention</option>
          <option value="unassigned">No location or owner</option>
          <option value="ignored">Marked not IoT</option>
        </select>
        <div className="seg" role="group" aria-label="Group by">
          {(["location", "type", "network"] as const).map((g) => (
            <button key={g} className={group === g ? "on" : ""} onClick={() => setGroup(g)}>{g === "location" ? "Location" : g === "type" ? "Type" : "Network"}</button>
          ))}
        </div>
        <span className="muted">{shown.length} of {show === "ignored" ? devices.length - active.length : active.length}</span>
      </div>

      {canEdit && sel.size > 0 && (
        <div className="iot-bulk" role="region" aria-label="Selected devices">
          <strong>{sel.size} selected</strong>
          <button onClick={() => setBulk(true)}><Icon name="edit" size={15} />Set location, owner or type</button>
          {selWrong.length > 0 && <a className="button" href={`#/vlans?select=${selWrong.map((d) => d.mac).join(",")}`}>Move {selWrong.length} to an IoT network →</a>}
          {selWrong.length > 0 && <button onClick={() => patch(selWrong.map((d) => d.mac), { network_ok: true, network_ok_reason: "allowed in bulk" }, `${selWrong.length} device${selWrong.length === 1 ? "" : "s"} allowed on ${selWrong.length === 1 ? "its" : "their"} current network.`)}>Allow where they are</button>}
          {show === "ignored"
            ? <button onClick={() => patch([...sel], { ignored: false }, `${sel.size} back in the inventory.`)}>Back in inventory</button>
            : <button onClick={() => patch([...sel], { ignored: true }, `${sel.size} marked not IoT. Find them under "Marked not IoT".`)}>Not IoT</button>}
          <button className="link" onClick={() => setSel(new Set())}>Clear</button>
        </div>
      )}

      {shown.length === 0 && (
        <section className="card"><div className="empty">
          <Icon name={devices.length ? "search" : "plug"} size={22} />
          <span>{devices.length ? "No device matches." : view.sources ? "No IoT devices found among the network's clients yet. Add one by hand." : "Nothing here yet."}</span>
        </div></section>
      )}

      {groups.map(([g, list]) => (
        <section key={g} className="card flush iot-group">
          <div className="iot-group-head">
            <h2>{group === "location" && <Icon name="building" size={16} />}{g || "No location yet"}</h2>
            <span className="muted small">{list.length} device{list.length === 1 ? "" : "s"}{list.some((d) => d.issues.includes("wrong_network")) && <> · <span className="pill bad">{list.filter((d) => d.issues.includes("wrong_network")).length} not on an IoT network</span></>}</span>
          </div>
          <div>
            <table className="compact iot-table">
              <thead><tr>
                {canEdit && <th style={{ width: 28 }}><input type="checkbox" aria-label={`Select all in ${g || "no location"}`}
                  checked={list.every((d) => sel.has(d.mac))}
                  onChange={(e) => setSel((s) => { const n = new Set(s); list.forEach((d) => e.target.checked ? n.add(d.mac) : n.delete(d.mac)); return n; })} /></th>}
                <th>Device</th>{group !== "type" && <th>Type</th>}<th>{group === "location" ? "Floor and room" : "Location"}</th><th>Owner</th><th>Network</th><th>Connected to</th><th>IP</th><th>Status</th>
              </tr></thead>
              <tbody>
                {list.map((d) => (
                  <tr key={d.mac} className={`clickable ${sel.has(d.mac) ? "sel" : ""}`} onClick={() => setEditing(d)}>
                    {canEdit && <td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={sel.has(d.mac)} onChange={() => toggle(d.mac)} aria-label={`Select ${d.name}`} /></td>}
                    <td>
                      <span className="devname">
                        <span className={`kind-chip iot-${d.type}`}><Icon name={tinfo(d.type).icon} size={16} /></span>
                        <span className="iot-name"><strong>{d.name}</strong><span className="muted small">{[d.model || d.vendor, d.label && d.hostname && d.hostname !== d.label ? d.hostname : ""].filter(Boolean).join(" · ")}</span></span>
                      </span>
                    </td>
                    {group !== "type" && <td>{tinfo(d.type).one}</td>}
                    <td>{(group === "location" ? floorRoom(d) : [d.site, locationText(d)].filter(Boolean).join(" · ")) || <span className="muted">—</span>}</td>
                    <td>{d.owner || <span className="muted">—</span>}</td>
                    <td>
                      {d.network ? <span className={`pill ${d.issues.includes("wrong_network") ? "bad" : ""}`} title={d.network_ok ? `Allowed here: ${d.network_ok_reason || "exception"}` : undefined}>
                        {d.network}{d.vlan ? ` · ${d.vlan}` : ""}{d.network_ok && " ✓"}
                      </span> : <span className="muted">—</span>}
                    </td>
                    <td className="small">{d.uplink || <span className="muted">—</span>}</td>
                    <td className="mono small">{d.ip}</td>
                    <td>{d.online ? <span className="pill good">online</span> : <span className="pill warn" title={d.last_seen}>seen {ago(d.last_seen)}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}

      {editing && <EditDevice d={devices.find((x) => x.mac === editing.mac) ?? editing} all={devices} types={view.types} canEdit={canEdit} isAdmin={isAdmin}
        onClose={() => setEditing(null)} onSaved={(msg) => { setEditing(null); setFlash(msg); refetch(); }} />}
      {bulk && <BulkEdit devs={selDevs} all={devices} types={view.types}
        onClose={() => setBulk(false)} onSave={async (p) => { setBulk(false); await patch([...sel], p, `Updated ${sel.size} device${sel.size === 1 ? "" : "s"}.`); }} />}
      {adding && <AddDevice candidates={view.candidates} types={view.types} onClose={() => setAdding(false)}
        onAdded={(name) => { setAdding(false); setFlash(`${name} added to the inventory.`); refetch(); }} />}
      {nets && <Networks networks={view.networks} chosen={view.networks_chosen} isAdmin={isAdmin}
        onClose={() => setNets(false)} onSaved={() => { setNets(false); setFlash("IoT networks saved."); refetch(); }} />}
    </>
  );
}

function IssueTile({ label, icon, n, tone, sub, on, onClick }: {
  label: string; icon: IconName; n: number; tone: "warn" | "bad"; sub: string; on: boolean; onClick: () => void;
}) {
  return (
    <button className={`tile tile-btn ${n ? tone : ""} ${on ? "on" : ""}`} onClick={onClick} disabled={n === 0} aria-pressed={on}>
      <div className="tile-top"><span className="tile-label">{label}</span><span className={`tile-icon ${n ? tone : "good"}`}><Icon name={n ? icon : "check"} size={17} /></span></div>
      <div className="tile-value">{n}</div>
      <div className="muted small sh-tile-sub">{sub}</div>
    </button>
  );
}

// values people already typed, for the location and owner suggestions
function suggestions(all: IoTDevice[]) {
  const uniq = (f: (d: IoTDevice) => string) => [...new Set(all.map(f).filter(Boolean))].sort();
  return { site: uniq((d) => d.site), building: uniq((d) => d.building), floor: uniq((d) => d.floor), room: uniq((d) => d.room), owner: uniq((d) => d.owner) };
}

function Lists({ all }: { all: IoTDevice[] }) {
  const s = suggestions(all);
  return <>{(Object.keys(s) as (keyof typeof s)[]).map((k) => <datalist key={k} id={`iot-${k}`}>{s[k].map((v) => <option key={v} value={v} />)}</datalist>)}</>;
}

const locFields = [["site", "Site"], ["building", "Building"], ["floor", "Floor"], ["room", "Room or area"]] as const;

function EditDevice({ d, all, types, canEdit, isAdmin, onClose, onSaved }: {
  d: IoTDevice; all: IoTDevice[]; types: string[]; canEdit: boolean; isAdmin: boolean; onClose: () => void; onSaved: (msg: string) => void;
}) {
  const [f, setF] = useState({ label: d.label, type: d.type, site: d.site, building: d.building, floor: d.floor, room: d.room, owner: d.owner,
    notes: d.notes, network_ok: d.network_ok, network_ok_reason: d.network_ok_reason ?? "", ignored: d.ignored });
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const offIoT = d.issues.includes("wrong_network") || d.network_ok;

  const save = async () => {
    setSaving(true);
    try {
      await api("PUT", "/api/iot/devices", { macs: [d.mac], ...f, type: f.type === d.auto_type && !d.type ? "" : f.type });
      onSaved(`${f.label || d.hostname || d.mac} saved.`);
    } catch (e) { setErr((e as Error).message); setSaving(false); }
  };
  const forget = async () => {
    try { await api("DELETE", `/api/iot/devices/${d.mac}`); onSaved(`${d.name} removed. It comes back on the next read if it still looks like IoT; use "Not an IoT device" to keep it out.`); }
    catch (e) { setErr((e as Error).message); }
  };

  return (
    <Modal title={d.name} onClose={onClose} wide>
      <Lists all={all} />
      <dl className="kv iot-kv">
        <dt>MAC</dt><dd className="mono">{d.mac}</dd>
        {d.vendor && <><dt>Vendor</dt><dd>{d.vendor}</dd></>}
        {d.model && <><dt>Model</dt><dd>{d.model}</dd></>}
        {d.firmware && <><dt>Firmware</dt><dd className="mono">{d.firmware}</dd></>}
        {d.hostname && <><dt>Network name</dt><dd>{d.hostname}</dd></>}
        <dt>IP</dt><dd className="mono">{d.ip || "—"}</dd>
        <dt>Network</dt><dd>{d.network || "—"}{d.vlan ? ` (VLAN ${d.vlan})` : ""}{d.issues.includes("wrong_network") && <> <span className="pill bad">not an IoT network</span></>}</dd>
        <dt>Connected to</dt><dd>{d.uplink || "—"}{d.target && <span className="muted"> · {d.target}</span>}</dd>
        <dt>Seen</dt><dd>{d.online ? "online now" : `last ${ago(d.last_seen)}`} · first {ago(d.first_seen)}</dd>
        {d.updated_by && <><dt>Edited</dt><dd>{d.updated_by}, {ago(d.updated_at)}</dd></>}
      </dl>
      <fieldset disabled={!canEdit} className="iot-form">
        <div className="row">
          <label>Name in NCC<input value={f.label} onChange={set("label")} placeholder={d.hostname || d.mac} /></label>
          <label>Type
            <select value={f.type} onChange={set("type")}>
              {types.map((t) => <option key={t} value={t}>{tinfo(t).one}{t === d.auto_type ? " (NCC's guess)" : ""}</option>)}
            </select>
          </label>
          <label>Owner<input value={f.owner} onChange={set("owner")} list="iot-owner" placeholder="Team or person" /></label>
        </div>
        <div className="row">
          {locFields.map(([k, label]) => <label key={k}>{label}<input value={f[k]} onChange={set(k)} list={`iot-${k}`} /></label>)}
        </div>
        <label>Notes<textarea rows={2} value={f.notes} onChange={set("notes")} placeholder="Asset tag, support contract, admin page…" /></label>
        {offIoT && (
          <div className="iot-exception">
            <label className="check"><input type="checkbox" checked={f.network_ok} onChange={(e) => setF({ ...f, network_ok: e.target.checked })} />
              Allowed on {d.network || "this network"} (don't flag it)</label>
            {f.network_ok && <input value={f.network_ok_reason} onChange={set("network_ok_reason")} placeholder="Why, e.g. needs the management LAN" aria-label="Reason" />}
            {!f.network_ok && <a className="small" href={`#/vlans?select=${d.mac}`}>Move it to an IoT network on the VLANs page →</a>}
          </div>
        )}
        <label className="check"><input type="checkbox" checked={f.ignored} onChange={(e) => setF({ ...f, ignored: e.target.checked })} />Not an IoT device (hide it and don't add it again)</label>
      </fieldset>
      {err && <div className="error block">{err}</div>}
      <div className="modal-actions">
        {isAdmin && <button className="danger" onClick={forget} style={{ marginRight: "auto" }}><Icon name="trash" size={15} />Remove</button>}
        <button onClick={onClose}>{canEdit ? "Cancel" : "Close"}</button>
        {canEdit && <button className="primary" onClick={save} disabled={saving}>{saving ? "Saving…" : "Save"}</button>}
      </div>
    </Modal>
  );
}

function BulkEdit({ devs, all, types, onClose, onSave }: {
  devs: IoTDevice[]; all: IoTDevice[]; types: string[]; onClose: () => void; onSave: (p: IoTPatch) => void;
}) {
  const [f, setF] = useState<Record<string, string>>({});
  const set = (k: string) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const p: IoTPatch = {};
  for (const [k, v] of Object.entries(f)) if (v.trim()) (p as Record<string, string>)[k] = v.trim();
  const n = Object.keys(p).length;
  return (
    <Modal title={`Set details for ${devs.length} device${devs.length === 1 ? "" : "s"}`} onClose={onClose}>
      <Lists all={all} />
      <p className="muted small" style={{ marginTop: 0 }}>Fill in only what should change; empty fields stay as they are on each device.</p>
      <div className="row">
        {locFields.slice(0, 2).map(([k, label]) => <label key={k}>{label}<input value={f[k] ?? ""} onChange={set(k)} list={`iot-${k}`} /></label>)}
      </div>
      <div className="row">
        {locFields.slice(2).map(([k, label]) => <label key={k}>{label}<input value={f[k] ?? ""} onChange={set(k)} list={`iot-${k}`} /></label>)}
      </div>
      <div className="row">
        <label>Owner<input value={f.owner ?? ""} onChange={set("owner")} list="iot-owner" /></label>
        <label>Type
          <select value={f.type ?? ""} onChange={set("type")}>
            <option value="">Leave as is</option>
            {types.map((t) => <option key={t} value={t}>{tinfo(t).one}</option>)}
          </select>
        </label>
      </div>
      <p className="muted small">{devs.slice(0, 6).map((d) => d.name).join(", ")}{devs.length > 6 && ` and ${devs.length - 6} more`}</p>
      <div className="modal-actions">
        <button onClick={onClose}>Cancel</button>
        <button className="primary" disabled={n === 0} onClick={() => onSave(p)}>Apply to {devs.length}</button>
      </div>
    </Modal>
  );
}

function AddDevice({ candidates, types, onClose, onAdded }: {
  candidates: IoTCandidate[]; types: string[]; onClose: () => void; onAdded: (name: string) => void;
}) {
  const [q, setQ] = useState("");
  const [pick, setPick] = useState<IoTCandidate | null>(null);
  const [type, setType] = useState("");
  const [err, setErr] = useState("");
  const s = q.trim().toLowerCase();
  const list = candidates.filter((c) => !s || [c.name, c.ip, c.mac, c.vendor, c.network].some((x) => x?.toLowerCase().includes(s))).slice(0, 50);
  const add = async () => {
    if (!pick) return;
    try { await api("POST", "/api/iot/devices", { mac: pick.mac, type }); onAdded(pick.name); }
    catch (e) { setErr((e as Error).message); }
  };
  return (
    <Modal title="Add a device" onClose={onClose} wide>
      <p className="muted small" style={{ marginTop: 0 }}>Pick a client your network sees now. NCC keeps it in the inventory from then on, even when it's offline.</p>
      <input type="search" placeholder="Search name, IP, MAC or vendor" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: "100%" }} autoFocus aria-label="Search clients" />
      <ul className="list iot-pick">
        {list.length === 0 && <li className="muted">No client matches.</li>}
        {list.map((c) => (
          <li key={c.mac} className={pick?.mac === c.mac ? "on" : ""}>
            <label className="check grow-col">
              <input type="radio" name="iot-pick" checked={pick?.mac === c.mac} onChange={() => { setPick(c); setType(c.guess || "other"); }} />
              <span className="grow-col"><strong>{c.name}</strong> <span className="muted small">{[c.vendor, c.ip, c.network].filter(Boolean).join(" · ")}</span></span>
              {c.ignored && <span className="pill">marked not IoT</span>}
              {c.guess && !c.ignored && <span className="pill">{tinfo(c.guess).one}?</span>}
            </label>
          </li>
        ))}
      </ul>
      {pick && (
        <div className="row">
          <label>Type
            <select value={type} onChange={(e) => setType(e.target.value)}>{types.map((t) => <option key={t} value={t}>{tinfo(t).one}</option>)}</select>
          </label>
        </div>
      )}
      {err && <div className="error block">{err}</div>}
      <div className="modal-actions">
        <button onClick={onClose}>Cancel</button>
        <button className="primary" disabled={!pick} onClick={add}>Add {pick ? pick.name : "device"}</button>
      </div>
    </Modal>
  );
}

function Networks({ networks, chosen, isAdmin, onClose, onSaved }: {
  networks: IoTNetwork[]; chosen: boolean; isAdmin: boolean; onClose: () => void; onSaved: () => void;
}) {
  const [on, setOn] = useState<Set<string>>(new Set(networks.filter((n) => n.iot).map((n) => n.id)));
  const [err, setErr] = useState("");
  const save = async (guess: boolean) => {
    try { await api("PUT", "/api/iot/networks", guess ? { guess: true } : { ids: [...on] }); onSaved(); }
    catch (e) { setErr((e as Error).message); }
  };
  return (
    <Modal title="IoT networks" onClose={onClose}>
      <p className="muted small" style={{ marginTop: 0 }}>
        IoT devices should sit on networks of their own, away from laptops and servers. NCC flags any device on a network that isn't ticked here.
        {!chosen && " Until an admin chooses, NCC guesses from the network names (IoT, Cameras, BMS, OT…)."}
      </p>
      <ul className="list">
        {networks.map((n) => (
          <li key={n.id}>
            <label className="check grow-col">
              <input type="checkbox" disabled={!isAdmin} checked={on.has(n.id)}
                onChange={(e) => setOn((s) => { const x = new Set(s); e.target.checked ? x.add(n.id) : x.delete(n.id); return x; })} />
              <span className="grow-col"><strong>{n.name}</strong> <span className="muted small">{[n.vlan ? `VLAN ${n.vlan}` : "untagged", n.subnet, n.zone && `${n.zone} zone`].filter(Boolean).join(" · ")}</span></span>
            </label>
            <span className="muted small">{n.devices} IoT device{n.devices === 1 ? "" : "s"}{n.suggested && " · looks like IoT"}</span>
          </li>
        ))}
        {networks.length === 0 && <li className="muted">No networks read yet.</li>}
      </ul>
      {err && <div className="error block">{err}</div>}
      <div className="modal-actions">
        {isAdmin && chosen && <button onClick={() => save(true)} style={{ marginRight: "auto" }}>Guess from names</button>}
        <button onClick={onClose}>{isAdmin ? "Cancel" : "Close"}</button>
        {isAdmin && <button className="primary" onClick={() => save(false)}>Save</button>}
      </div>
      {!isAdmin && <p className="muted small">Only an admin can change these.</p>}
    </Modal>
  );
}

function exportCSV(devs: IoTDevice[]) {
  const cols: [string, (d: IoTDevice) => string | number | undefined][] = [
    ["Name", (d) => d.name], ["Type", (d) => tinfo(d.type).one], ["Site", (d) => d.site], ["Building", (d) => d.building], ["Floor", (d) => d.floor],
    ["Room", (d) => d.room], ["Owner", (d) => d.owner], ["Vendor", (d) => d.vendor], ["Model", (d) => d.model], ["Firmware", (d) => d.firmware],
    ["MAC", (d) => d.mac], ["IP", (d) => d.ip], ["Network", (d) => d.network], ["VLAN", (d) => d.vlan || ""], ["Connected to", (d) => d.uplink],
    ["Online", (d) => (d.online ? "yes" : "no")], ["Last seen", (d) => d.last_seen], ["On an IoT network", (d) => (d.issues.includes("wrong_network") ? "no" : "yes")],
    ["Notes", (d) => d.notes],
  ];
  const esc = (v: string | number | undefined) => {
    let s = String(v ?? "");
    if (/^[=+\-@]/.test(s)) s = "'" + s; // keep spreadsheets from running it as a formula
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const csv = [cols.map((c) => c[0]).join(","), ...devs.map((d) => cols.map((c) => esc(c[1](d))).join(","))].join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
  a.download = `iot-devices-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
