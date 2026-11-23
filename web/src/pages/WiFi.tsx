// Wi-Fi page: each router's Wi-Fi networks (SSIDs), its access points' radios and how well
// wireless clients hear them, the weak settings NCC flags, and SSID changes (name, on/off,
// network/VLAN, security, passphrase), always through a preview. Passphrases are kept in the vault.
import { useEffect, useMemo, useState } from "react";
import { api, Radio, SSID, User, WiFiChange, WiFiClient, WiFiFinding, WiFiPlan, WiFiTarget } from "../api";
import { ago } from "../format";
import { Icon } from "../icons";
import { Modal, PageHeader, Tile, Tone } from "../ui";

export const securityLabel: Record<string, string> = {
  open: "Open", wep: "WEP", wpa1: "WPA", "wpa1-wpa2": "WPA/WPA2", wpa2: "WPA2", "wpa2-wpa3": "WPA2/WPA3", wpa3: "WPA3",
  enterprise: "Enterprise", owe: "Enhanced Open",
};
const securityTone: Record<string, Tone | undefined> = {
  open: "bad", wep: "bad", wpa1: "bad", "wpa1-wpa2": "warn", wpa2: undefined, "wpa2-wpa3": "good", wpa3: "good", enterprise: "good", owe: "warn",
};
const personal = new Set(["wpa1", "wpa1-wpa2", "wpa2", "wpa2-wpa3", "wpa3"]);

/** Signal quality from dBm, as people read it. */
function signalTone(dbm?: number): { tone: Tone; label: string; bars: number } {
  if (!dbm) return { tone: "warn", label: "unknown", bars: 0 };
  if (dbm >= -60) return { tone: "good", label: "strong", bars: 4 };
  if (dbm >= -67) return { tone: "good", label: "good", bars: 3 };
  if (dbm >= -75) return { tone: "warn", label: "weak", bars: 2 };
  return { tone: "bad", label: "poor", bars: 1 };
}

function Signal({ dbm }: { dbm?: number }) {
  const s = signalTone(dbm);
  return (
    <span className={`wifi-signal ${s.tone}`} title={dbm ? `${dbm} dBm, ${s.label}` : "signal unknown"}>
      <span className="wifi-bars" aria-hidden>{[1, 2, 3, 4].map((b) => <i key={b} className={b <= s.bars ? "on" : ""} style={{ height: 3 + b * 3 }} />)}</span>
      {dbm ? <span className="mono">{dbm} dBm</span> : <span className="muted">—</span>}
    </span>
  );
}

const bandText = (b: string) => `${b} GHz`;
const vlanText = (v?: number) => (v ? `VLAN ${v}` : "untagged");

export function WiFi({ tick, user }: { tick: number; user: User }) {
  const [targets, setTargets] = useState<WiFiTarget[] | null>(null);
  const [err, setErr] = useState("");
  const [tid, setTid] = useState<number | null>(null);
  const [edit, setEdit] = useState<SSID | null>(null);
  const [allClients, setAllClients] = useState(false);
  const [flash, setFlash] = useState("");
  const isAdmin = user.role === "admin";

  const refetch = () =>
    api<{ targets: WiFiTarget[] }>("GET", "/api/wifi").then((v) => { setTargets(v.targets); setErr(""); }).catch((e) => setErr((e as Error).message));
  useEffect(() => { refetch(); }, [tick]);

  const t = targets?.find((x) => x.id === tid) ?? targets?.[0];
  const aps = useMemo(() => {
    const by = new Map<string, { id: string; name: string; online: boolean; radios: Radio[]; clients: WiFiClient[] }>();
    for (const r of t?.radios ?? []) {
      const a = by.get(r.device_id) ?? { id: r.device_id, name: r.device_name, online: r.online, radios: [], clients: [] };
      a.radios.push(r);
      by.set(r.device_id, a);
    }
    for (const c of t?.clients ?? []) by.get(c.ap_id ?? "")?.clients.push(c);
    const order = { "2.4": 0, "5": 1, "6": 2 } as Record<string, number>;
    for (const a of by.values()) a.radios.sort((x, y) => (order[x.band] ?? 9) - (order[y.band] ?? 9));
    return [...by.values()];
  }, [t]);

  if (!targets) return <><h1>Wi-Fi</h1>{err ? <div className="error block">{err}</div> : <p className="muted">Loading…</p>}</>;
  if (!t) {
    return (
      <>
        <h1>Wi-Fi</h1>
        <section className="card"><p className="muted" style={{ margin: 0 }}>Connect your UniFi router under <a href="#/settings">Settings</a> first. NCC lists its Wi-Fi networks and access points here.</p></section>
      </>
    );
  }

  const canEdit = isAdmin && t.writable;
  const on = t.ssids.filter((s) => s.enabled);
  const weak = t.clients.filter((c) => c.signal && c.signal < -67).sort((a, b) => (a.signal ?? 0) - (b.signal ?? 0));
  const shownClients = allClients ? [...t.clients].sort((a, b) => (a.signal ?? 0) - (b.signal ?? 0)) : weak;
  const problems = t.findings.filter((f) => f.severity !== "info");
  const critical = t.findings.filter((f) => f.severity === "critical").length;
  const apOnline = aps.filter((a) => a.online).length;
  const ssidOf = (id?: string) => t.ssids.find((s) => s.id === id);
  const flagged = (s: SSID) => t.findings.filter((f) => f.ssid_id === s.id && f.severity !== "info");

  return (
    <>
      <PageHeader title="Wi-Fi">
        {targets.length > 1 && (
          <select value={t.id} onChange={(e) => setTid(Number(e.target.value))} aria-label="Router">
            {targets.map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}
          </select>
        )}
      </PageHeader>
      <p className="muted lede">
        {t.ssids.length} Wi-Fi networks and {aps.length} access points on {t.name}{t.taken_at && <> · updated {ago(t.taken_at)}</>}.
        {" "}Changes are shown for confirmation before anything is sent, and passphrases NCC sets or reads are kept in the vault.
      </p>
      {err && <div className="error block">{err}</div>}
      {t.last_error && <div className="banner bad" role="alert"><Icon name="alert" size={16} /><strong>{t.name}</strong><span>{t.last_error}</span></div>}
      {flash && <div className="banner good" role="status"><Icon name="check" size={16} /><span>{flash}</span><button className="link" onClick={() => setFlash("")}>Dismiss</button></div>}

      <div className="tiles">
        <Tile label="Wi-Fi networks on" icon="wifi" value={<>{on.length}<small> / {t.ssids.length}</small></>}
          sub={on.filter((s) => s.guest).length ? `${on.filter((s) => s.guest).length} for guests` : "no guest network"} />
        <Tile label="Wireless clients" icon="client" value={t.clients.length}
          tone={weak.filter((c) => (c.signal ?? 0) < -75).length ? "warn" : undefined}
          sub={weak.length ? `${weak.length} with a weak signal` : "all with a good signal"} />
        <Tile label="Access points online" icon="ap" value={<>{apOnline}<small> / {aps.length}</small></>}
          tone={apOnline < aps.length ? "warn" : undefined} sub={`${t.radios.filter((r) => r.online).length} radios on air`} />
        <Tile label="Settings to fix" icon="shield" value={problems.length} tone={critical ? "bad" : problems.length ? "warn" : "good"}
          sub={critical ? `${critical} critical` : problems.length ? "warnings" : "nothing weak found"} />
      </div>

      {t.findings.length > 0 && (
        <section className="card">
          <h2><Icon name="alert" size={16} /> Needs attention</h2>
          <ul className="list wifi-findings">
            {t.findings.map((f, i) => {
              const s = ssidOf(f.ssid_id);
              return (
                <li key={i}>
                  <span className={`dot ${f.severity === "critical" ? "bad" : f.severity === "warning" ? "warn" : ""}`} />
                  <span className="grow-col">
                    <span>{f.summary}</span>
                    {f.fix && <div className="muted small">{f.fix}</div>}
                  </span>
                  {s && canEdit && <button onClick={() => setEdit(s)}><Icon name="edit" size={14} />Fix</button>}
                </li>
              );
            })}
          </ul>
        </section>
      )}

      <div className="card flush">
        <div className="card-head fw-head"><h2>Wi-Fi networks</h2><span className="muted small">{t.ssids.length} SSIDs</span></div>
        <table className="wifi-table">
          <thead><tr><th>Name</th><th>Status</th><th>Security</th><th>Bands</th><th>Network</th><th>Clients</th><th></th></tr></thead>
          <tbody>
            {t.ssids.map((s) => {
              const f = flagged(s);
              return (
                <tr key={s.id} className={s.enabled ? "" : "fw-off"}>
                  <td>
                    <strong>{s.name}</strong>
                    {s.guest && <span className="pill fw-tag">guest</span>}
                    {s.hidden && <span className="pill fw-tag">hidden</span>}
                    {f.length > 0 && <div className={`small ${f.some((x) => x.severity === "critical") ? "bad-text" : "warn-text"}`}>{f.map((x) => kindText[x.kind] ?? x.kind).join(" · ")}</div>}
                  </td>
                  <td>{s.enabled ? <span className="pill good">on</span> : <span className="pill">off</span>}</td>
                  <td>
                    <span className={`pill ${securityTone[s.security] ?? ""}`}>{securityLabel[s.security] ?? s.security}</span>
                    {s.tkip && <span className="pill warn fw-tag">TKIP</span>}
                  </td>
                  <td className="nowrap">{(s.bands ?? []).map(bandText).join(", ")}</td>
                  <td>{s.network ?? "—"} <span className="muted small">{vlanText(s.vlan)}</span></td>
                  <td>{s.clients}</td>
                  <td className="actions">
                    {canEdit && <button onClick={() => setEdit(s)}><Icon name="edit" size={14} />Edit</button>}
                    {t.saved.includes(s.id) && <span className="muted small" title="NCC has a copy of the passphrase in the vault"><Icon name="lock" size={12} /> in vault</span>}
                  </td>
                </tr>
              );
            })}
            {t.ssids.length === 0 && <tr><td colSpan={7} className="muted">The router reported no Wi-Fi networks.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card flush">
        <div className="card-head fw-head"><h2>Access points and radios</h2><span className="muted small">channel, width and power as the radios report them</span></div>
        <table className="wifi-table">
          <thead><tr><th>Access point</th><th>Band</th><th>Channel</th><th>Width</th><th>Transmit power</th><th>Clients</th><th>Channel use</th></tr></thead>
          <tbody>
            {aps.map((a) => a.radios.map((r, i) => (
              <tr key={a.id + r.band} className={a.online ? "" : "fw-off"}>
                {i === 0 && (
                  <td rowSpan={a.radios.length} className="wifi-ap">
                    <span className={`dot ${a.online ? "good" : "bad"}`} /><strong>{a.name}</strong>
                    <div className="muted small">{a.online ? `${a.clients.length} clients` : "offline"}</div>
                  </td>
                )}
                <td className="nowrap">{bandText(r.band)}</td>
                <td>{r.channel ?? "—"}{r.channel_auto && <span className="muted small"> auto</span>}</td>
                <td>{r.width_mhz ? `${r.width_mhz} MHz` : "—"}</td>
                <td>{r.tx_power ? `${r.tx_power} dBm` : "—"}{r.tx_power_mode && <span className="muted small"> {r.tx_power_mode}</span>}</td>
                <td>{a.online ? r.clients : "—"}</td>
                <td className="wifi-cu">
                  {a.online && r.utilization !== undefined ? (
                    <><div className={`meter ${r.utilization >= 70 ? "bad" : r.utilization >= 50 ? "warn" : "good"}`}><span style={{ width: `${r.utilization}%` }} /></div><span className="muted small">{r.utilization}%</span></>
                  ) : <span className="muted">—</span>}
                </td>
              </tr>
            )))}
            {aps.length === 0 && <tr><td colSpan={7} className="muted">No access points reported radio details.</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card flush">
        <div className="card-head fw-head">
          <h2>{allClients ? "Wireless clients" : "Weakest connections"}</h2>
          <label className="check small"><input type="checkbox" checked={allClients} onChange={(e) => setAllClients(e.target.checked)} /> Show all {t.clients.length}</label>
        </div>
        <table className="wifi-table">
          <thead><tr><th>Client</th><th>Signal</th><th>Access point</th><th>Band</th><th>Wi-Fi</th></tr></thead>
          <tbody>
            {shownClients.map((c) => (
              <tr key={c.mac}>
                <td><strong>{c.name}</strong><div className="muted small mono">{c.ip ?? c.mac}</div></td>
                <td><Signal dbm={c.signal} /></td>
                <td>{c.ap ?? "—"}</td>
                <td className="nowrap">{c.band ? `${bandText(c.band)}${c.channel ? ` · ch ${c.channel}` : ""}` : "—"}</td>
                <td>{c.ssid ?? "—"}{c.network && <div className="muted small">{c.network}</div>}</td>
              </tr>
            ))}
            {shownClients.length === 0 && (
              <tr><td colSpan={5} className="muted">{t.clients.length ? "Every wireless client has a good signal (−67 dBm or better)." : "No wireless clients right now."}</td></tr>
            )}
          </tbody>
        </table>
        {!allClients && weak.length > 0 && (
          <p className="muted small wifi-note">Below −67 dBm calls and video start to stutter; below −75 dBm devices drop off. Move the device or access point closer, or add an access point.</p>
        )}
      </div>

      {!canEdit && (
        <p className="muted small">{isAdmin ? `${t.kind} connections cannot change Wi-Fi from NCC yet.` : "Only admins can change Wi-Fi settings."}</p>
      )}

      {edit && <SSIDDialog key={edit.id} target={t} ssid={edit} onClose={(msg) => { setEdit(null); if (msg) { setFlash(msg); refetch(); } }} />}
    </>
  );
}

const kindText: Record<string, string> = {
  open: "open network", wep: "WEP", wpa1: "WPA1", "mixed-wpa1": "allows WPA1", tkip: "TKIP", "short-passphrase": "short passphrase",
  "iot-vlan": "IoT Wi-Fi not on the IoT VLAN", "guest-lan": "guests on your LAN",
};

/** A strong random passphrase of 20 characters, easy to type (no look-alike characters). */
function generatePassphrase(): string {
  const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const buf = new Uint32Array(20);
  crypto.getRandomValues(buf);
  const s = [...buf].map((n) => chars[n % chars.length]).join("");
  return `${s.slice(0, 5)}-${s.slice(5, 10)}-${s.slice(10, 15)}-${s.slice(15)}`;
}

function SSIDDialog({ target, ssid, onClose }: { target: WiFiTarget; ssid: SSID; onClose: (msg?: string) => void }) {
  const enterprise = ssid.security === "enterprise";
  const weakNow = !personal.has(ssid.security) || ["wpa1", "wpa1-wpa2"].includes(ssid.security) || !!ssid.tkip;
  const [name, setName] = useState(ssid.name);
  const [enabled, setEnabled] = useState(ssid.enabled);
  const [hidden, setHidden] = useState(!!ssid.hidden);
  const [network, setNetwork] = useState(ssid.network_id ?? "");
  const [security, setSecurity] = useState<string>(weakNow && !enterprise ? "wpa2-wpa3" : ssid.security);
  const [pass, setPass] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [current, setCurrent] = useState<{ passphrase: string; source: string; vault_path?: string } | null>(null);
  const [plan, setPlan] = useState<WiFiPlan | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [done, setDone] = useState<{ vault_path?: string; warning?: string } | null>(null);
  const reset = () => { setPlan(null); setErr(""); };

  const change = (): WiFiChange => {
    const c: WiFiChange = {};
    if (name.trim() !== ssid.name) c.name = name.trim();
    if (enabled !== ssid.enabled) c.enabled = enabled;
    if (hidden !== !!ssid.hidden) c.hidden = hidden;
    if (network && network !== ssid.network_id) c.network_id = network;
    if (!enterprise && security !== ssid.security && ["wpa2", "wpa2-wpa3", "wpa3"].includes(security)) c.security = security as WiFiChange["security"];
    if (pass) c.passphrase = pass;
    return c;
  };
  const body = () => ({ target_id: target.id, ssid_id: ssid.id, ...change() });

  const review = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try { setPlan(await api<WiFiPlan>("POST", "/api/wifi/plan", body())); } catch (e) { setErr((e as Error).message); }
    setBusy(false);
  };
  const apply = async () => {
    setBusy(true);
    setErr("");
    try { setDone(await api<{ vault_path?: string; warning?: string }>("POST", "/api/wifi/apply", body())); setPass(""); } catch (e) { setErr((e as Error).message); }
    setBusy(false);
  };
  const reveal = async (fromRouter = false) => {
    setErr("");
    try { setCurrent(await api("POST", "/api/wifi/passphrase", { target_id: target.id, ssid_id: ssid.id, from_router: fromRouter })); } catch (e) { setErr((e as Error).message); }
  };

  const title = `Edit ${ssid.name}`;
  if (done) {
    const msg = `${plan?.ssid.name ?? ssid.name} was updated on ${target.name}. The table updates after the next refresh.`;
    return (
      <Modal title={title} onClose={() => onClose(msg)}>
        <p style={{ marginTop: 0 }}><Icon name="check" size={15} /> {target.name} accepted the change. Its access points re-apply Wi-Fi settings within a minute.</p>
        {done.vault_path && <p className="small">The new passphrase is saved in the vault at <span className="mono">{done.vault_path}</span>. Admins can see it again from this dialog or the Vault page.</p>}
        {done.warning && <div className="banner warn"><Icon name="alert" size={16} /><span>{done.warning}</span></div>}
        <div className="row"><button className="primary" onClick={() => onClose(msg)}>Done</button></div>
      </Modal>
    );
  }

  return (
    <Modal title={title} onClose={() => onClose()} wide>
      <form onSubmit={review} className="wifi-form">
        <div className="row">
          <label>Name<input value={name} onChange={(e) => { setName(e.target.value); reset(); }} maxLength={32} required /></label>
          <label>Network
            <select value={network} onChange={(e) => { setNetwork(e.target.value); reset(); }}>
              {target.networks.map((n) => <option key={n.id} value={n.id}>{n.name} ({vlanText(n.vlan)}){n.purpose === "guest" ? " · guest" : n.isolated ? " · isolated" : ""}</option>)}
            </select>
          </label>
        </div>
        <div className="row">
          <label>Security
            <select value={security} disabled={enterprise} onChange={(e) => { setSecurity(e.target.value); reset(); }}>
              {!["wpa2", "wpa2-wpa3", "wpa3"].includes(ssid.security) && <option value={ssid.security} disabled>{securityLabel[ssid.security]} (now)</option>}
              <option value="wpa2">WPA2</option>
              <option value="wpa2-wpa3">WPA2/WPA3 (recommended)</option>
              <option value="wpa3">WPA3 only</option>
            </select>
            {enterprise && <span className="muted small">Uses RADIUS; change it in UniFi Network.</span>}
          </label>
          <label>{personal.has(ssid.security) ? "New passphrase" : "Passphrase"}
            <span className="wifi-pass">
              <input type={showPass ? "text" : "password"} value={pass} autoComplete="new-password" disabled={enterprise}
                placeholder={personal.has(ssid.security) ? "leave empty to keep the current one" : "8 to 63 characters"}
                onChange={(e) => { setPass(e.target.value); reset(); }} />
              <button type="button" className="iconbtn" onClick={() => setShowPass(!showPass)} title={showPass ? "Hide" : "Show"} aria-label={showPass ? "Hide passphrase" : "Show passphrase"}>
                <Icon name={showPass ? "unlock" : "lock"} size={15} />
              </button>
              <button type="button" disabled={enterprise} onClick={() => { setPass(generatePassphrase()); setShowPass(true); reset(); }}>Generate</button>
            </span>
          </label>
        </div>
        <div className="row wifi-checks">
          <label className="check"><input type="checkbox" checked={enabled} onChange={(e) => { setEnabled(e.target.checked); reset(); }} /> Broadcasting (on)</label>
          <label className="check"><input type="checkbox" checked={hidden} onChange={(e) => { setHidden(e.target.checked); reset(); }} /> Hide the name</label>
        </div>
        {personal.has(ssid.security) && (
          <div className="wifi-current small">
            {current ? (
              <>
                Current passphrase: <span className="mono wifi-secret">{current.passphrase}</span>
                <span className="muted"> · {current.source === "vault" ? "from the vault" : `read from ${target.name}`}{current.vault_path ? `, saved at ${current.vault_path}` : ""}</span>
                {current.source === "vault" && <button type="button" className="link" onClick={() => reveal(true)}>Read from router</button>}
              </>
            ) : (
              <button type="button" className="link" onClick={() => reveal(false)}><Icon name="vault" size={13} /> Show current passphrase</button>
            )}
          </div>
        )}
        {err && <div className="error block" style={{ marginTop: 12 }}>{err}</div>}
        {plan ? (
          <div className="subcard">
            <h3 style={{ marginTop: 0 }}>What changes on {target.name}</h3>
            <table className="vlan-plan">
              <thead><tr><th>Setting</th><th>Now</th><th>Becomes</th></tr></thead>
              <tbody>{plan.changes.map((c) => <tr key={c.setting}><td>{c.setting}</td><td>{c.from}</td><td><strong>{c.to}</strong></td></tr>)}</tbody>
            </table>
            {plan.resolves.length > 0 && (
              <ul className="vlan-steps">{plan.resolves.map((f) => <li key={f.kind}><Icon name="check" size={14} /> <span className="good-text">Fixes:</span> {f.summary}</li>)}</ul>
            )}
            {plan.remaining.length > 0 && (
              <ul className="vlan-steps">{plan.remaining.map((f: WiFiFinding) => <li key={f.kind}><span className={`dot ${f.severity === "critical" ? "bad" : "warn"}`} /><span className="warn-text">Still flagged:</span> {f.summary}</li>)}</ul>
            )}
            {plan.warnings.map((w) => <div key={w} className="banner warn"><Icon name="alert" size={16} /><span>{w}</span></div>)}
            {change().passphrase && <p className="muted small">The passphrase is sent to {target.name} and saved in the vault. It is not shown in the audit log.</p>}
            <div className="row">
              <button type="button" className="primary" disabled={busy} onClick={apply}>{busy ? "Applying…" : `Apply to ${target.name}`}</button>
              <button type="button" onClick={() => setPlan(null)}>Back</button>
            </div>
          </div>
        ) : (
          <div className="row" style={{ marginTop: 14 }}>
            <button className="primary" disabled={busy}>{busy ? "Checking…" : "Review changes"}</button>
            <button type="button" onClick={() => onClose()}>Cancel</button>
          </div>
        )}
      </form>
    </Modal>
  );
}
