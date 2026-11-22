// VLANs page: the router's networks as columns of clients. Drag clients (or a selection)
// between networks to move them, always through a preview; create networks; reconnect stale clients.
import { useEffect, useMemo, useState } from "react";
import { api, MovePlan, MoveResult, NetClient, Network, NetworkSpec, User, VLANTarget } from "../api";
import { ago } from "../format";
import { Icon } from "../icons";
import { Modal } from "../ui";
import { networkColors, zonePill, zoneText } from "./topoVlan";

// Vendors whose devices are almost always "smart home" gear. Used by "Select likely IoT".
const iotVendors = [
  "espressif", "tuya", "shelly", "sonoff", "itead", "nest", "google", "amazon", "ring", "wyze", "eufy", "anker", "arlo",
  "philips", "signify", "lifx", "sonos", "roku", "ecobee", "honeywell", "resideo", "irobot", "ezviz", "hikvision",
  "dahua", "reolink", "tp-link", "tplink", "kasa", "meross", "xiaomi", "yeelight", "aqara", "lumi", "broadlink",
  "tado", "netatmo", "withings", "august", "yale", "chamberlain", "myq", "rachio", "wemo", "belkin", "govee",
  "nanoleaf", "smartthings", "emporia", "midea", "silicon labs", "nordic semi",
];
const iotNames = ["iot", "plug", "bulb", "light", "lamp", "cam", "camera", "doorbell", "thermostat", "sensor", "switch-", "echo",
  "alexa", "nest", "hue", "sonos", "speaker", "tv", "chromecast", "roomba", "vacuum", "lock", "garage", "sprinkler", "printer"];

export function looksIoT(c: NetClient): boolean {
  const v = (c.vendor ?? "").toLowerCase();
  const n = c.name.toLowerCase();
  return iotVendors.some((x) => v.includes(x)) || iotNames.some((x) => n.includes(x));
}

const UNKNOWN = "__unknown";

function vlanTag(n?: { vlan?: number }) {
  return n?.vlan ? `VLAN ${n.vlan}` : "untagged";
}

export function VLANs({ tick, user }: { tick: number; user: User }) {
  const [targets, setTargets] = useState<VLANTarget[] | null>(null);
  const [err, setErr] = useState("");
  const [tid, setTid] = useState<number | null>(null);
  const [q, setQ] = useState("");
  const [medium, setMedium] = useState<"" | "wired" | "wifi">("");
  // the IoT page links here with ?select=mac,mac to move those devices
  const [sel, setSel] = useState<Set<string>>(() => new Set(new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("select")?.split(",").filter(Boolean) ?? []));
  const [over, setOver] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [move, setMove] = useState<{ network: Network; macs: string[] } | null>(null);
  const [creating, setCreating] = useState(false);
  const [renew, setRenew] = useState<NetClient[] | null>(null);
  const [flash, setFlash] = useState("");
  const isAdmin = user.role === "admin";

  const refetch = () =>
    api<{ targets: VLANTarget[] }>("GET", "/api/vlans").then((v) => { setTargets(v.targets); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { refetch(); }, [tick]);

  const t = targets?.find((x) => x.id === tid) ?? targets?.[0];
  const lan = useMemo(() => (t?.networks ?? []).filter((n) => n.purpose !== "wan" && !(n.purpose ?? "").includes("vpn")), [t]);
  const colors = useMemo(() => networkColors(t?.networks as never, "var(--muted)"), [t]);
  const devName = useMemo(() => new Map((t?.devices ?? []).map((d) => [d.id, d.name])), [t]);

  const shown = useMemo(() => {
    const s = q.toLowerCase();
    return (t?.clients ?? []).filter((c) =>
      (!medium || (medium === "wired") === c.wired) &&
      (!s || [c.name, c.ip, c.vendor, c.mac, c.ssid, c.network].some((x) => x?.toLowerCase().includes(s))));
  }, [t, q, medium]);

  const columns = useMemo(() => {
    const ids = new Set(lan.map((n) => n.id));
    const by = new Map<string, NetClient[]>();
    for (const c of shown) {
      const k = c.network_id && ids.has(c.network_id) ? c.network_id : UNKNOWN;
      by.set(k, [...(by.get(k) ?? []), c]);
    }
    return by;
  }, [shown, lan]);

  // drop selection entries that are no longer visible
  useEffect(() => {
    if (!t) return; // not loaded yet: keep a selection the IoT page passed in
    const vis = new Set(t.clients.map((c) => c.mac));
    setSel((s) => { const n = new Set([...s].filter((m) => vis.has(m))); return n.size === s.size ? s : n; });
  }, [t]);

  if (!targets) return <><h1>VLANs</h1>{err ? <div className="error block">{err}</div> : <p className="muted">Loading…</p>}</>;
  if (!t) {
    return (
      <>
        <h1>VLANs</h1>
        <section className="card"><p className="muted" style={{ margin: 0 }}>Connect your router under <a href="#/settings">Settings</a> first. NCC lists its networks and clients here.</p></section>
      </>
    );
  }

  const toggle = (mac: string) => setSel((s) => { const n = new Set(s); n.has(mac) ? n.delete(mac) : n.add(mac); return n; });
  // only clients on ordinary internal networks: servers in a DMZ or guests are left alone
  const zoneOf = new Map(lan.map((n) => [n.id, n.zone]));
  const selectIoT = () => setSel(new Set(shown.filter((c) => looksIoT(c) && !["dmz", "hotspot"].includes(zoneOf.get(c.network_id ?? "") ?? ""))
    .map((c) => c.mac)));

  const onDragStart = (e: React.DragEvent, c: NetClient) => {
    const macs = sel.has(c.mac) ? [...sel] : [c.mac];
    e.dataTransfer.setData("application/x-ncc-macs", JSON.stringify(macs));
    e.dataTransfer.setData("text/plain", macs.join(","));
    e.dataTransfer.effectAllowed = "move";
    setDragging(true);
  };
  const onDrop = (e: React.DragEvent, n: Network) => {
    e.preventDefault();
    setOver(null);
    setDragging(false);
    let macs: string[] = [];
    try { macs = JSON.parse(e.dataTransfer.getData("application/x-ncc-macs") || "[]"); } catch { /* not ours */ }
    if (macs.length) setMove({ network: n, macs });
  };

  const unknown = columns.get(UNKNOWN) ?? [];
  const stale = t.clients.filter((c) => c.stale);

  return (
    <>
      <div className="card-head" style={{ marginBottom: 4 }}>
        <h1 style={{ margin: 0 }}>VLANs</h1>
        <div className="row" style={{ alignItems: "center" }}>
          {targets.length > 1 && (
            <select value={t.id} onChange={(e) => { setTid(Number(e.target.value)); setSel(new Set()); }} aria-label="Router">
              {targets.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
            </select>
          )}
          {isAdmin && t.writable && <button className="primary" onClick={() => setCreating(true)}><Icon name="plus" size={15} />New VLAN</button>}
        </div>
      </div>
      <p className="muted lede">
        {lan.length} networks and {t.clients.length} clients on {t.name}{t.taken_at && <> · updated {ago(t.taken_at)}</>}.
        {" "}Drag clients onto a network to move them; select several first to move them together. You see what will change before anything is sent.
      </p>
      {err && <div className="error block">{err}</div>}
      {t.last_error && <div className="banner bad" role="alert"><Icon name="alert" size={16} /><strong>{t.name}</strong><span>{t.last_error}</span></div>}
      {flash && <div className="banner good" role="status"><Icon name="check" size={16} /><span>{flash}</span><button className="link" onClick={() => setFlash("")}>Dismiss</button></div>}
      {stale.length > 0 && (
        <div className="banner warn" role="status">
          <Icon name="alert" size={16} />
          <span><strong>{stale.length} device{stale.length === 1 ? " still has an address" : "s still have addresses"}</strong> from {stale.length === 1 ? "its" : "their"} old network: {stale.slice(0, 6).map((c) => c.name).join(", ")}{stale.length > 6 ? "…" : ""}.</span>
          {isAdmin && t.writable && <button onClick={() => setRenew(stale)}>Reconnect {stale.length === 1 ? "it" : "them"}</button>}
        </div>
      )}
      {!t.writable && <div className="banner warn"><Icon name="alert" size={16} /><span>NCC cannot change networks on {t.kind} connections yet. You can still see them here.</span></div>}

      <div className="toolbar">
        <input placeholder="Search name, IP, vendor or MAC" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={medium} onChange={(e) => setMedium(e.target.value as never)} aria-label="Connection">
          <option value="">Wired and Wi-Fi</option>
          <option value="wired">Wired only</option>
          <option value="wifi">Wi-Fi only</option>
        </select>
        <button onClick={selectIoT} title="Select clients whose vendor or name looks like smart home gear (cameras, plugs, speakers, TVs…)">Select likely IoT</button>
        {sel.size > 0 && (
          <span className="vlan-selbar">
            <strong>{sel.size} selected</strong>
            <select value="" onChange={(e) => { const n = lan.find((x) => x.id === e.target.value); if (n) setMove({ network: n, macs: [...sel] }); }} aria-label="Move selected to">
              <option value="">Move to…</option>
              {lan.map((n) => <option key={n.id} value={n.id}>{n.name} ({vlanTag(n)})</option>)}
            </select>
            <button className="link" onClick={() => setSel(new Set())}>Clear</button>
          </span>
        )}
      </div>

      <div className={`vlan-board ${dragging ? "dragging" : ""}`}>
        {lan.map((n) => {
          const list = columns.get(n.id) ?? [];
          const zone = zoneText(n);
          return (
            <section key={n.id} className={`vlan-col ${over === n.id ? "over" : ""}`} style={{ ["--net" as string]: colors.get(n.id) }}
              onDragOver={(e) => { e.preventDefault(); e.dataTransfer.dropEffect = "move"; setOver(n.id); }}
              onDragLeave={(e) => { if (!e.currentTarget.contains(e.relatedTarget as Node)) setOver((o) => (o === n.id ? null : o)); }}
              onDrop={(e) => onDrop(e, n)} aria-label={`${n.name} network`}>
              <header className="vlan-col-head">
                <div className="vlan-col-title">
                  <strong>{n.name}</strong>
                  <span className="vlan-tag">{vlanTag(n)}</span>
                  <span className="grow" />
                  <span className="muted small">{list.length}</span>
                </div>
                <div className="muted small">{n.subnet ?? (n.purpose === "vlan-only" ? "VLAN only, no router address" : "")}</div>
                <div className="vlan-pills">
                  {zone && <span className={`pill ${zonePill[n.zone ?? ""] ?? ""}`}>{zone}</span>}
                  {n.isolated && <span className="pill">Isolated</span>}
                  {!n.internet_access && <span className="pill warn">No internet</span>}
                  {(n.ssids ?? []).map((s) => <span key={s} className="pill" title="Wi-Fi network that drops clients here"><Icon name="wifi" size={11} />{s}</span>)}
                </div>
              </header>
              <div className="vlan-cards">
                {list.map((c) => <ClientCard key={c.mac} c={c} t={t} devName={devName} selected={sel.has(c.mac)} onToggle={() => toggle(c.mac)}
                  onDragStart={(e) => onDragStart(e, c)} onDragEnd={() => { setDragging(false); setOver(null); }} />)}
                {list.length === 0 && <div className="vlan-empty muted small">Drop clients here</div>}
              </div>
            </section>
          );
        })}
        {unknown.length > 0 && (
          <section className="vlan-col unknown">
            <header className="vlan-col-head">
              <div className="vlan-col-title"><strong>Network not known</strong><span className="grow" /><span className="muted small">{unknown.length}</span></div>
              <div className="muted small">The router did not say which network these are in.</div>
            </header>
            <div className="vlan-cards">
              {unknown.map((c) => <ClientCard key={c.mac} c={c} t={t} devName={devName} selected={sel.has(c.mac)} onToggle={() => toggle(c.mac)}
                onDragStart={(e) => onDragStart(e, c)} onDragEnd={() => { setDragging(false); setOver(null); }} />)}
            </div>
          </section>
        )}
      </div>

      <section className="card vlan-howto">
        <h2><Icon name="vlan" size={16} /> How clients are moved</h2>
        <ul className="small">
          <li><strong>Wi-Fi clients</strong> keep their Wi-Fi name and password. The router puts just that device in the new VLAN (UniFi's per-client network override), so nothing needs setting up again. They are disconnected so they rejoin straight away and get an address in the new network.</li>
          <li><strong>Wired clients</strong> move by changing the untagged VLAN of the switch port they are plugged into. Everything on that port moves together, so if a small unmanaged switch sits there you see the other devices listed first. Ports that lead to other switches or access points are never changed. To make the devices ask for a new address, NCC turns the port off for about 10 seconds and back on, or power-cycles it if it is a PoE port.</li>
          <li>A <strong>fixed IP</strong> reserved for a device moves with it, keeping the same last number in the new subnet (192.168.1.50 becomes 192.168.30.50) when that number is free. If it isn't, the reservation is removed and the device gets an address from DHCP.</li>
          <li>Every change is shown for confirmation first and written to the audit log. Changes need the router account NCC uses to have a role that can change settings: a View Only account can see this page, but the router refuses changes.</li>
        </ul>
      </section>

      {move && <MoveDialog target={t} network={move.network} macs={move.macs} canApply={isAdmin && t.writable}
        onClose={(msg) => { setMove(null); if (msg) { setFlash(msg); setSel(new Set()); refetch(); } }} />}
      {renew && <ReconnectDialog target={t} clients={renew} onClose={(msg) => { setRenew(null); if (msg) { setFlash(msg); refetch(); } }} />}
      {creating && <CreateDialog target={t} onClose={(msg) => { setCreating(false); if (msg) { setFlash(msg); refetch(); } }} />}
    </>
  );
}

function ClientCard({ c, t, devName, selected, onToggle, onDragStart, onDragEnd }: {
  c: NetClient; t: VLANTarget; devName: Map<string, string>; selected: boolean; onToggle: () => void;
  onDragStart: (e: React.DragEvent) => void; onDragEnd: () => void;
}) {
  const port = c.switch_mac ? t.ports[`${c.switch_mac}#${c.switch_port}`] : undefined;
  const via = c.wired
    ? c.switch_mac ? `${devName.get(c.switch_mac) ?? "switch"} · ${port?.name || `Port ${c.switch_port}`}` : "wired"
    : `Wi-Fi ${c.ssid ?? ""}`.trim();
  const shared = c.wired && port && port.clients > 1;
  const behind = c.wired && port?.infra;
  return (
    <div className={`vlan-card ${selected ? "sel" : ""}`} draggable onDragStart={onDragStart} onDragEnd={onDragEnd}
      onClick={(e) => { if (!(e.target as HTMLElement).closest("input")) onToggle(); }} title="Drag onto a network, or click to select">
      <input type="checkbox" checked={selected} onChange={onToggle} aria-label={`Select ${c.name}`} />
      <span className="vlan-card-icon"><Icon name={c.wired ? "cable" : "wifi"} size={15} /></span>
      <span className="vlan-card-body">
        <span className="vlan-card-name">{c.name}</span>
        <span className="muted small">{[c.ip, c.vendor].filter(Boolean).join(" · ")}</span>
        <span className="muted small vlan-via">{via}
          {c.stale && <span className="pill bad" title="It is in this network but still has an address from its old one. Reconnect it to get a new address.">old address</span>}
          {shared && <span className="pill warn" title={`${port!.clients} devices share this port; they move together`}>shared port</span>}
          {behind && <span className="pill" title="Behind another switch: set the VLAN on that switch">behind a switch</span>}
        </span>
      </span>
    </div>
  );
}

const methodText = { port: "switch port VLAN", client: "per-client override" } as const;

function MoveDialog({ target, network, macs, canApply, onClose }: {
  target: VLANTarget; network: Network; macs: string[]; canApply: boolean; onClose: (msg?: string) => void;
}) {
  const [plan, setPlan] = useState<MovePlan | null>(null);
  const [err, setErr] = useState("");
  const [reconnect, setReconnect] = useState(true);
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<MoveResult[] | null>(null);

  useEffect(() => {
    api<MovePlan>("POST", "/api/vlans/plan", { target_id: target.id, network_id: network.id, macs }).then(setPlan).catch((e) => setErr(e.message));
  }, [target.id, network.id, macs]);

  const moving = plan?.steps.filter((s) => s.method) ?? [];
  const blocked = plan?.steps.filter((s) => s.blocked) ?? [];
  const already = plan?.steps.filter((s) => !s.method && s.already) ?? [];
  const wifi = moving.filter((s) => s.method === "client").length;
  const wired = moving.length - wifi;

  const apply = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await api<{ results: MoveResult[] }>("POST", "/api/vlans/move", { target_id: target.id, network_id: network.id, macs, reconnect });
      setResults(r.results);
    } catch (e) {
      setErr((e as Error).message);
    }
    setBusy(false);
  };

  const title = `Move ${macs.length === 1 ? plan?.steps[0]?.name ?? "1 client" : `${macs.length} clients`} to ${network.name} (${vlanTag(network)})`;
  if (results) {
    const ok = results.filter((r) => r.ok).length;
    return (
      <Modal title={title} onClose={() => onClose(`${ok} of ${results.length} clients moved to ${network.name}. The map updates after the next refresh.`)}>
        <ul className="vlan-steps">
          {results.map((r) => (
            <li key={r.mac}>
              <span className={`dot ${r.ok ? "good" : "bad"}`} /><strong>{r.name}</strong>
              {r.ok ? <span className="muted"> moved</span> : <span className="error"> {r.error}</span>}
              {(r.notes ?? []).map((n) => <div key={n} className="muted small">{n}</div>)}
            </li>
          ))}
        </ul>
        <p className="muted small">Devices show their new addresses after the next refresh. Any still on an old address are marked "old address" on the board, with a button to reconnect them.</p>
        <div className="row"><button className="primary" onClick={() => onClose(`${ok} of ${results.length} clients moved to ${network.name}.`)}>Done</button></div>
      </Modal>
    );
  }
  return (
    <Modal title={title} onClose={() => onClose()} wide>
      {!plan && !err && <p className="muted">Working out what changes…</p>}
      {err && <div className="error block">{err}</div>}
      {plan && (
        <>
          {plan.ports.length > 0 && (
            <>
              <h3>Switch ports that change</h3>
              <table className="vlan-plan">
                <thead><tr><th>Port</th><th>Untagged network now</th><th>Becomes</th><th>Devices on it</th></tr></thead>
                <tbody>
                  {plan.ports.map((p) => (
                    <tr key={p.switch_mac + p.port}>
                      <td><strong>{p.switch_name}</strong> {p.port_name}{p.profile && <div className="muted small">profile {p.profile}</div>}</td>
                      <td>{p.from_name ?? "—"}</td>
                      <td><strong>{network.name}</strong></td>
                      <td>{p.clients.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
          {moving.length > 0 && (
            <>
              <h3>Clients that move ({moving.length})</h3>
              <ul className="vlan-steps">
                {moving.map((s) => (
                  <li key={s.mac}>
                    <Icon name={s.wired ? "cable" : "wifi"} size={14} /> <strong>{s.name}</strong>
                    <span className="muted"> {s.from_name ?? "unknown"} → {network.name} · {methodText[s.method!]} · {s.via}</span>
                    {s.note && <div className={`small ${s.requested ? "muted" : "warn-text"}`}>{s.note}</div>}
                  </li>
                ))}
              </ul>
            </>
          )}
          {blocked.length > 0 && (
            <>
              <h3>Can't be moved from here ({blocked.length})</h3>
              <ul className="vlan-steps">
                {blocked.map((s) => <li key={s.mac}><span className="dot bad" /><strong>{s.name}</strong> <span className="muted small">{s.blocked}</span></li>)}
              </ul>
            </>
          )}
          {already.length > 0 && <p className="muted small">Already in {network.name}: {already.map((s) => s.name).join(", ")}.</p>}
          {(plan.warnings ?? []).map((w) => <div key={w} className="banner warn"><Icon name="alert" size={16} /><span>{w}</span></div>)}
          {moving.length > 0 && (
            <label className="check vlan-reconnect">
              <input type="checkbox" checked={reconnect} onChange={(e) => setReconnect(e.target.checked)} />
              <span>
                <strong>Give them addresses in {network.name} now</strong>
                <span className="muted small">
                  {wifi > 0 && <>Wi-Fi devices are disconnected and rejoin. </>}
                  {wired > 0 && <>Wired devices have their switch port turned off for about 10 seconds; PoE ports are power-cycled instead, which restarts the device. </>}
                  Without this, each device moves when it next renews its address, which can take hours.
                </span>
              </span>
            </label>
          )}
          <div className="row" style={{ marginTop: 12 }}>
            <button className="primary" disabled={!canApply || busy || moving.length === 0} onClick={apply}>
              {busy ? "Applying…" : `Apply to ${target.name}`}
            </button>
            <button onClick={() => onClose()}>Cancel</button>
            {!canApply && <span className="muted small">Only admins can apply network changes.</span>}
          </div>
        </>
      )}
    </Modal>
  );
}

function ReconnectDialog({ target, clients, onClose }: { target: VLANTarget; clients: NetClient[]; onClose: (msg?: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [results, setResults] = useState<MoveResult[] | null>(null);
  const run = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await api<{ results: MoveResult[] }>("POST", "/api/vlans/reconnect", { target_id: target.id, macs: clients.map((c) => c.mac) });
      setResults(r.results);
    } catch (e) {
      setErr((e as Error).message);
    }
    setBusy(false);
  };
  const title = `Reconnect ${clients.length === 1 ? clients[0].name : `${clients.length} devices`}`;
  const done = () => onClose(`Reconnected ${results?.filter((r) => r.ok).length ?? 0} of ${results?.length ?? 0}. New addresses show after the next refresh.`);
  if (results) {
    return (
      <Modal title={title} onClose={done}>
        <ul className="vlan-steps">
          {results.map((r) => (
            <li key={r.mac}>
              <span className={`dot ${r.ok ? "good" : "bad"}`} /><strong>{r.name}</strong>
              {r.ok ? (r.notes ?? []).map((n) => <div key={n} className="muted small">{n}</div>) : <div className="error small">{r.error}</div>}
            </li>
          ))}
        </ul>
        <div className="row"><button className="primary" onClick={done}>Done</button></div>
      </Modal>
    );
  }
  return (
    <Modal title={title} onClose={() => onClose()}>
      <p className="small" style={{ marginTop: 0 }}>
        These devices are in their new network but still have an address from the old one. NCC makes them ask for a new address:
        Wi-Fi devices are disconnected and rejoin; wired devices have their switch port turned off for about 10 seconds (PoE ports are power-cycled, which restarts the device).
        Anything else on the same port reconnects too.
      </p>
      <ul className="vlan-steps">
        {clients.map((c) => <li key={c.mac}><Icon name={c.wired ? "cable" : "wifi"} size={14} /> <strong>{c.name}</strong> <span className="muted">{c.ip} · now in {c.network}</span></li>)}
      </ul>
      {err && <div className="error block">{err}</div>}
      <div className="row" style={{ marginTop: 12 }}>
        <button className="primary" disabled={busy} onClick={run}>{busy ? "Reconnecting…" : "Reconnect"}</button>
        <button onClick={() => onClose()}>Cancel</button>
      </div>
    </Modal>
  );
}

function CreateDialog({ target, onClose }: { target: VLANTarget; onClose: (msg?: string) => void }) {
  const s = target.suggestion;
  const [f, setF] = useState<NetworkSpec>({
    name: "", vlan: s.vlan || 10, mode: "gateway", gateway: s.gateway ?? "", dhcp: true, dhcp_start: "", dhcp_stop: "",
    isolated: false, internet_access: true,
  });
  const [review, setReview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const set = (p: Partial<NetworkSpec>) => { setF({ ...f, ...p }); setReview(false); };

  const create = async () => {
    setBusy(true);
    setErr("");
    try {
      const r = await api<{ spec: NetworkSpec }>("POST", "/api/vlans/networks", { target_id: target.id, ...f, vlan: Number(f.vlan) });
      onClose(`${r.spec.name} (VLAN ${r.spec.vlan}) was created on ${target.name}. Drag clients into it when it appears.`);
    } catch (e) {
      setErr((e as Error).message);
      setReview(false);
    }
    setBusy(false);
  };

  return (
    <Modal title={`New VLAN on ${target.name}`} onClose={() => onClose()}>
      <form onSubmit={(e) => { e.preventDefault(); setReview(true); }}>
        <div className="row">
          <label>Name<input value={f.name} onChange={(e) => set({ name: e.target.value })} required maxLength={32} placeholder="IoT" autoFocus /></label>
          <label style={{ maxWidth: 120 }}>VLAN ID<input type="number" min={2} max={4009} value={f.vlan} onChange={(e) => set({ vlan: Number(e.target.value) })} required /></label>
        </div>
        <label>Type
          <select value={f.mode} onChange={(e) => set({ mode: e.target.value as NetworkSpec["mode"] })}>
            <option value="gateway">Routed by {target.name}, with its own subnet</option>
            <option value="vlan-only">VLAN only (another router handles addresses)</option>
          </select>
        </label>
        {f.mode === "gateway" && (
          <>
            <label>Router address and subnet<input value={f.gateway} onChange={(e) => set({ gateway: e.target.value })} required placeholder="192.168.30.1/24" /></label>
            <label className="check"><input type="checkbox" checked={f.dhcp} onChange={(e) => set({ dhcp: e.target.checked })} /> Hand out addresses (DHCP)</label>
            {f.dhcp && (
              <div className="row" style={{ marginTop: 10 }}>
                <label>First address<input value={f.dhcp_start} onChange={(e) => set({ dhcp_start: e.target.value })} placeholder="automatic" /></label>
                <label>Last address<input value={f.dhcp_stop} onChange={(e) => set({ dhcp_stop: e.target.value })} placeholder="automatic" /></label>
              </div>
            )}
            <label className="check"><input type="checkbox" checked={f.isolated} onChange={(e) => set({ isolated: e.target.checked })} /> Isolate: block it from reaching your other networks (good for IoT)</label>
            <label className="check" style={{ marginTop: 8 }}><input type="checkbox" checked={f.internet_access} onChange={(e) => set({ internet_access: e.target.checked })} /> Allow internet access</label>
          </>
        )}
        {err && <div className="error block" style={{ marginTop: 12 }}>{err}</div>}
        {review ? (
          <div className="subcard">
            <p className="small" style={{ marginTop: 0 }}>
              Create <strong>{f.name}</strong> as <strong>VLAN {f.vlan}</strong> on {target.name}
              {f.mode === "gateway"
                ? <>, router address {f.gateway}{f.dhcp ? `, DHCP ${f.dhcp_start || "automatic range"}${f.dhcp_stop ? ` to ${f.dhcp_stop}` : ""}` : ", no DHCP"}{f.isolated ? ", isolated" : ""}{f.internet_access ? "" : ", no internet"}</>
                : ", VLAN only"}.
              {" "}Nothing moves into it until you drag clients there. Switch ports set to carry all VLANs pick it up automatically.
            </p>
            <div className="row">
              <button type="button" className="primary" disabled={busy} onClick={create}>{busy ? "Creating…" : "Create network"}</button>
              <button type="button" onClick={() => setReview(false)}>Back</button>
            </div>
          </div>
        ) : (
          <div className="row" style={{ marginTop: 14 }}>
            <button className="primary">Review</button>
            <button type="button" onClick={() => onClose()}>Cancel</button>
          </div>
        )}
      </form>
    </Modal>
  );
}
