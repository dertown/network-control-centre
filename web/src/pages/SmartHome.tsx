import { useEffect, useMemo, useState } from "react";
import { api, MatterCheck, SmartDevice, SmartEntity, SmartInventory, SmartPlan, SmartSource, User } from "../api";
import { ago } from "../live";
import { Icon, IconName } from "../icons";
import { AddTarget } from "./Settings";

// Controls people use; sensors are shown as readings.
const controlDomains = new Set(["light", "switch", "fan", "input_boolean", "humidifier", "media_player", "cover", "valve", "lock",
  "climate", "water_heater", "vacuum", "lawn_mower", "alarm_control_panel", "camera"]);
const sceneDomains = new Set(["scene", "script", "button"]);
const readingDomains = new Set(["sensor", "binary_sensor"]);

const typeLabel: Record<string, string> = {
  light: "Lights", switch: "Plugs and switches", input_boolean: "Plugs and switches", fan: "Fans", humidifier: "Fans", media_player: "Speakers and TVs",
  cover: "Doors, blinds and garage", valve: "Doors, blinds and garage", lock: "Locks", climate: "Heating and cooling", water_heater: "Heating and cooling",
  vacuum: "Robots", lawn_mower: "Robots", alarm_control_panel: "Security", camera: "Cameras",
};

function entityIcon(e: SmartEntity): IconName {
  switch (e.domain) {
    case "light": return "bulb";
    case "switch": case "input_boolean": return "plug";
    case "fan": case "humidifier": return "fan";
    case "cover": return e.device_class === "garage" || e.device_class === "gate" ? "garage" : e.device_class === "door" ? "door" : "blinds";
    case "valve": return "droplet";
    case "lock": return e.state === "locked" ? "lock" : "unlock";
    case "climate": case "water_heater": return "thermo";
    case "media_player": return /\btv\b|television|chromecast/i.test(e.name) || e.device_class === "tv" ? "tv" : "speaker";
    case "vacuum": case "lawn_mower": return "vacuum";
    case "scene": case "script": case "button": return "sparkle";
    case "camera": return "camera";
    case "alarm_control_panel": return "shield";
    case "binary_sensor": return e.device_class === "motion" || e.device_class === "occupancy" ? "motion" : e.device_class === "door" || e.device_class === "window" ? "door" : "gauge";
    case "sensor":
      if (e.device_class === "temperature") return "thermo";
      if (e.device_class === "humidity" || e.device_class === "moisture") return "droplet";
      if (e.device_class === "battery") return "battery";
      return "gauge";
  }
  return "unknown";
}

// isActive: the entity is "on" in the everyday sense, for highlighting.
function isActive(e: SmartEntity): boolean {
  if (["on", "open", "opening", "unlocked", "playing", "cleaning", "mowing", "heat", "cool", "heat_cool", "auto"].includes(e.state)) return true;
  return e.domain === "climate" && (e.hvac_action === "heating" || e.hvac_action === "cooling");
}

const words: Record<string, string> = {
  on: "On", off: "Off", open: "Open", closed: "Closed", opening: "Opening…", closing: "Closing…", locked: "Locked", unlocked: "Unlocked",
  locking: "Locking…", unlocking: "Unlocking…", jammed: "Jammed", playing: "Playing", paused: "Paused", idle: "Idle", standby: "Standby",
  docked: "Docked", cleaning: "Cleaning", returning: "Going home", mowing: "Mowing", unavailable: "Offline", unknown: "Unknown",
  heat: "Heat", cool: "Cool", heat_cool: "Heat and cool", auto: "Auto", dry: "Dry", fan_only: "Fan", streaming: "Streaming", recording: "Recording",
  disarmed: "Disarmed", armed_home: "Armed (home)", armed_away: "Armed (away)", armed_night: "Armed (night)", triggered: "Triggered",
};

function stateText(e: SmartEntity, unit?: string): string {
  if (e.state === "unavailable") return "Offline";
  switch (e.domain) {
    case "light": return e.state === "on" && e.brightness !== undefined ? `On · ${e.brightness}%` : words[e.state] ?? e.state;
    case "climate": {
      const mode = words[e.state] ?? e.state;
      const act = e.hvac_action && e.hvac_action !== "off" && e.hvac_action !== "idle" ? ` · ${e.hvac_action}` : "";
      return e.current_temp !== undefined ? `${e.current_temp}${unit ?? "°"} now · ${mode}${act}` : mode;
    }
    case "media_player": return e.media_title && e.state === "playing" ? `Playing · ${e.media_title}` : words[e.state] ?? e.state;
    case "scene": case "script": case "button": return e.state && !isNaN(Date.parse(e.state)) ? `Last run ${ago(e.state)}` : "Ready";
    case "binary_sensor": {
      const on = e.state === "on";
      const dc = e.device_class;
      if (dc === "motion" || dc === "occupancy") return on ? "Motion" : "Clear";
      if (dc === "door" || dc === "window" || dc === "opening" || dc === "garage_door") return on ? "Open" : "Closed";
      if (dc === "moisture") return on ? "Wet" : "Dry";
      return on ? "Detected" : "Clear";
    }
    case "sensor": return `${e.state}${e.unit ? (e.unit === "%" || e.unit.startsWith("°") ? "" : " ") + e.unit : ""}`;
  }
  return words[e.state] ?? e.state.replace(/_/g, " ");
}

type Busy = Record<string, boolean>;

export function SmartHome({ tick, user }: { tick: number; user: User }) {
  const [sources, setSources] = useState<SmartSource[] | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState(false);
  const [group, setGroup] = useState<"rooms" | "types">(() => {
    try { return localStorage.getItem("ncc-iot-group") === "types" ? "types" : "rooms"; } catch { return "rooms"; }
  });
  const [q, setQ] = useState("");
  const [pairing, setPairing] = useState(false);
  const isAdmin = user.role === "admin";

  const refetch = () => api<{ sources: SmartSource[] }>("GET", "/api/smarthome").then((v) => { setSources(v.sources); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { refetch(); }, [tick]);
  useEffect(() => { try { localStorage.setItem("ncc-iot-group", group); } catch { /* storage blocked */ } }, [group]);

  const refresh = async () => {
    if (!sources) return;
    setBusy(true);
    const fails: string[] = [];
    await Promise.all(sources.filter((s) => s.enabled).map((s) => api("POST", `/api/targets/${s.id}/poll`).catch((e) => fails.push(`${s.name}: ${(e as Error).message}`))));
    setErr(fails.join(" · "));
    setBusy(false);
    refetch();
  };

  const live = useMemo(() => (sources ?? []).filter((s) => s.enabled && s.inventory), [sources]);

  if (!sources) return <><h1>Smart home</h1>{err ? <div className="error block">{err}</div> : <p className="muted">Loading…</p>}</>;

  if (sources.length === 0) {
    return (
      <>
        <h1>Smart home</h1>
        <p className="muted lede">Lights, plugs, thermostats, locks, speakers and sensors from Google Home, Alexa, Matter and more, in one place.</p>
        <section className="card">
          <div className="empty" style={{ alignItems: "flex-start", textAlign: "left", padding: 0 }}>
            <span className="tile-icon"><Icon name="home" size={17} /></span>
            <div style={{ margin: "4px 0 10px", lineHeight: 1.55 }}>
              <p style={{ margin: "0 0 8px" }}>
                Google Home and Alexa don't let other apps control their devices directly, so NCC works through <strong>Home Assistant</strong>,
                a free smart home server you run next to NCC. Home Assistant controls Matter devices (which can stay in Google Home or Alexa at
                the same time), Google Nest and Cast devices, Alexa devices, Hue, TP-Link, Zigbee and hundreds more.
              </p>
              <ol className="sh-steps">
                <li>Run Home Assistant and its Matter server (NCC's <code>deploy/homeassistant</code> folder has a ready Docker Compose file and the steps).</li>
                <li>In Home Assistant add the <strong>Matter</strong> integration, then make a long-lived access token in your profile.</li>
                <li>Connect it here, then share your Google Home devices with NCC using their pairing codes.</li>
              </ol>
            </div>
          </div>
          {isAdmin
            ? (adding ? <AddTarget kind="homeassistant" onDone={() => { setAdding(false); refetch(); }} /> : <button className="primary" onClick={() => setAdding(true)}>Connect Home Assistant</button>)
            : <p className="muted small">Ask an admin to connect Home Assistant.</p>}
        </section>
      </>
    );
  }

  const invs = live.map((s) => s.inventory!);
  const ents = invs.flatMap((i) => i.entities);
  const devices = invs.flatMap((i) => i.devices);
  const online = devices.filter((d) => d.online).length;
  const lights = ents.filter((e) => e.domain === "light" && e.state !== "unavailable");
  const lightsOn = lights.filter((e) => e.state === "on").length;
  const locks = ents.filter((e) => e.domain === "lock" && e.state !== "unavailable");
  const garages = ents.filter((e) => e.domain === "cover" && (e.device_class === "garage" || e.device_class === "gate") && e.state !== "unavailable");
  const insecure = [...locks.filter((e) => e.state !== "locked"), ...garages.filter((e) => e.state !== "closed")];
  const climate = ents.find((e) => e.domain === "climate" && e.state !== "unavailable");
  const alerts = live.flatMap((s) => s.inventory!.alerts.map((a) => ({ ...a, source: s })));
  const crit = alerts.filter((a) => a.level === "critical").length;
  const hubs = invs.map((i) => i.hub);
  const srcs = [...new Set(hubs.flatMap((h) => h.sources))];
  const unit = hubs[0]?.unit;

  return (
    <>
      <div className="card-head" style={{ marginBottom: 4 }}>
        <h1 style={{ margin: 0 }}>Smart home</h1>
        <div className="row" style={{ margin: 0 }}>
          {isAdmin && live.length > 0 && <button onClick={() => setPairing(true)}><Icon name="plus" size={15} />Add Matter device</button>}
          {user.role !== "viewer" && <button onClick={refresh} disabled={busy}>{busy ? "Refreshing…" : "Refresh now"}</button>}
        </div>
      </div>
      <p className="muted lede">
        {devices.length} device{devices.length === 1 ? "" : "s"} in {new Set(invs.flatMap((i) => i.areas.map((a) => a.id))).size} rooms
        {srcs.length > 0 && <> · from {srcs.join(", ")}</>}
        {hubs[0] && <> · Home Assistant {hubs[0].version}</>}
        {live[0]?.taken_at && <> · updated {ago(live[0].taken_at)}</>}
      </p>
      {err && <div className="error block">{err}</div>}
      {sources.filter((s) => s.enabled && s.last_error).map((s) => (
        <div key={s.id} className="banner bad" role="alert">
          <Icon name="alert" size={16} /><strong>{s.name}</strong><span>{s.last_error}</span>
          {s.taken_at && <span className="muted small">Showing the read from {ago(s.taken_at)}.</span>}
        </div>
      ))}
      {live.flatMap((s) => (s.inventory!.warnings ?? []).map((w) => (
        <div key={s.id + w} className="banner warn"><Icon name="alert" size={16} /><strong>{s.name}</strong><span>{w}</span></div>
      )))}
      {live.some((s) => !s.inventory!.hub.matter) && isAdmin && (
        <div className="banner warn"><Icon name="alert" size={16} /><span>Matter isn't set up in Home Assistant yet, so devices can't be shared from Google Home. In Home Assistant open <strong>Settings → Devices &amp; services → Add integration → Matter</strong>.</span></div>
      )}

      {live.length > 0 && (
        <div className="tiles">
          <Tile label="Devices online" icon={online === devices.length ? "check" : "alert"} tone={online === devices.length ? "good" : "warn"}
            value={<>{online}<small> / {devices.length}</small></>}
            sub={alerts.length ? `${alerts.length} need${alerts.length === 1 ? "s" : ""} attention${crit ? `, ${crit} urgent` : ""}` : "everything is answering"} />
          <Tile label="Lights on" icon="bulb" iconTone="c4" value={<>{lightsOn}<small> of {lights.length}</small></>}
            sub={lightsOn ? lights.filter((e) => e.state === "on").map((e) => e.name).slice(0, 3).join(", ") : "all off"} />
          <Tile label="Doors and locks" icon={insecure.length ? "unlock" : "lock"} tone={insecure.length ? "warn" : locks.length + garages.length ? "good" : undefined}
            valueClass="small-value" value={locks.length + garages.length === 0 ? "–" : insecure.length ? `${insecure.length} open` : "All secure"}
            sub={insecure.length ? insecure.map((e) => `${e.name} ${stateText(e).toLowerCase()}`).join(", ") : `${locks.length} lock${locks.length === 1 ? "" : "s"}, ${garages.length} garage`} />
          <Tile label="Climate" icon="thermo" iconTone="c2" valueClass="small-value"
            value={climate?.current_temp !== undefined ? <>{climate.current_temp}{unit ?? "°"}{climate.target_temp !== undefined && <small> → {climate.target_temp}{unit ?? "°"}</small>}</> : "–"}
            sub={climate ? `${climate.name} · ${stateText(climate, unit).split(" · ").slice(1).join(" · ") || words[climate.state]}` : "no thermostat"} />
        </div>
      )}

      {alerts.length > 0 && (
        <section className="card">
          <h2><Icon name="alert" size={16} /> Needs attention</h2>
          <ul className="list st-alerts">
            {alerts.map((a, i) => (
              <li key={i}>
                <span className={`dot ${a.level === "critical" ? "bad" : "warn"}`} />
                <span className="grow-col"><strong>{a.subject}</strong> <span>{a.message}</span></span>
                {live.length > 1 && <span className="muted small">{a.source.name}</span>}
              </li>
            ))}
          </ul>
        </section>
      )}

      {live.length > 0 && (
        <div className="toolbar">
          <div className="seg" role="group" aria-label="Group by">
            <button className={group === "rooms" ? "on" : ""} onClick={() => setGroup("rooms")}>By room</button>
            <button className={group === "types" ? "on" : ""} onClick={() => setGroup("types")}>By type</button>
          </div>
          <input type="search" placeholder="Find a device…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Find a device" />
        </div>
      )}

      {live.map((s) => <Home key={s.id} src={s} user={user} group={group} q={q} onChanged={refetch} />)}

      <Ecosystems hubs={hubs} />

      {isAdmin && (
        <section className="card" style={{ marginTop: 18 }}>
          <div className="card-head"><h2><Icon name="link" size={16} /> Connections</h2><a href="#/settings">Manage in Settings →</a></div>
          <ul className="list">
            {sources.map((s) => (
              <li key={s.id}>
                <span className={`dot ${!s.enabled ? "" : s.last_error ? "bad" : s.taken_at ? "good" : "warn"}`} />
                <span className="grow-col"><strong>{s.name}</strong> <span className="muted small">Home Assistant{s.inventory ? ` ${s.inventory.hub.version} · ${s.inventory.hub.name}` : ""}</span></span>
                <span className="mono small muted">{s.address}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {pairing && <MatterPair sources={live} onClose={() => setPairing(false)} onPaired={refetch} />}
    </>
  );
}

function Home({ src, user, group, q, onChanged }: { src: SmartSource; user: User; group: "rooms" | "types"; q: string; onChanged: () => void }) {
  const inv = src.inventory!;
  const [busy, setBusy] = useState<Busy>({});
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [confirm, setConfirm] = useState<{ plan: SmartPlan; body: Record<string, unknown> } | null>(null);
  const canOperate = user.role !== "viewer";
  const devBy = useMemo(() => Object.fromEntries(inv.devices.map((d) => [d.id, d])), [inv.devices]);
  const unit = inv.hub.unit;

  const needle = q.trim().toLowerCase();
  const match = (e: SmartEntity) => {
    if (!needle) return true;
    const d = e.device ? devBy[e.device] : undefined;
    return [e.name, e.id, d?.name, d?.manufacturer, d?.model, e.source].some((x) => x?.toLowerCase().includes(needle));
  };
  const shown = inv.entities.filter(match);

  const run = async (e: SmartEntity, action: string, extra: Record<string, unknown> = {}) => {
    const body = { id: src.id, entity: e.id, action, ...extra };
    setNote(null);
    setBusy((b) => ({ ...b, [e.id]: true }));
    try {
      if (["unlock", "disarm"].includes(action) || (action === "open" && e.domain === "cover" && ["garage", "gate", "door"].includes(e.device_class ?? ""))) {
        const plan = await api<SmartPlan>("POST", "/api/smarthome/plan", body);
        if (plan.sensitive) {
          setConfirm({ plan, body });
          return;
        }
      }
      await api("POST", "/api/smarthome/control", body);
      onChanged();
    } catch (err) {
      setNote({ ok: false, text: `${e.name}: ${(err as Error).message}` });
    } finally {
      setBusy((b) => ({ ...b, [e.id]: false }));
    }
  };

  const confirmRun = async () => {
    if (!confirm) return;
    const { plan, body } = confirm;
    setBusy((b) => ({ ...b, [plan.entity]: true }));
    try {
      await api("POST", "/api/smarthome/control", { ...body, confirm: true });
      setNote({ ok: true, text: `${plan.description}: done.` });
      setConfirm(null);
      onChanged();
    } catch (err) {
      setNote({ ok: false, text: (err as Error).message });
      setConfirm(null);
    } finally {
      setBusy((b) => ({ ...b, [plan.entity]: false }));
    }
  };

  // sections: rooms (with "Other" for entities without one) or device types
  type Section = { key: string; title: string; icon: IconName; controls: SmartEntity[]; readings: SmartEntity[]; scenes: SmartEntity[] };
  const sections: Section[] = [];
  const add = (key: string, title: string, icon: IconName, e: SmartEntity) => {
    let s = sections.find((x) => x.key === key);
    if (!s) { s = { key, title, icon, controls: [], readings: [], scenes: [] }; sections.push(s); }
    if (controlDomains.has(e.domain)) s.controls.push(e);
    else if (readingDomains.has(e.domain)) s.readings.push(e);
    else if (sceneDomains.has(e.domain)) s.scenes.push(e);
  };
  if (group === "rooms") {
    for (const a of inv.areas) for (const e of shown.filter((x) => x.area === a.id)) add(a.id, a.name, "home", e);
    for (const e of shown.filter((x) => !x.area || !inv.areas.some((a) => a.id === x.area))) add("_none", sceneDomains.has(e.domain) ? "Scenes" : "No room", sceneDomains.has(e.domain) ? "sparkle" : "home", e);
  } else {
    const order = ["light", "switch", "fan", "climate", "lock", "cover", "media_player", "vacuum", "camera", "alarm_control_panel"];
    const sorted = [...shown].sort((a, b) => (order.indexOf(a.domain) + 99) % 99 - (order.indexOf(b.domain) + 99) % 99);
    for (const e of sorted) {
      if (controlDomains.has(e.domain)) add(typeLabel[e.domain] ?? e.domain, typeLabel[e.domain] ?? e.domain, entityIcon(e), e);
      else if (sceneDomains.has(e.domain)) add("Scenes", "Scenes", "sparkle", e);
      else add("Sensors", "Sensors", "gauge", e);
    }
  }
  const nonEmpty = sections.filter((s) => s.controls.length + s.readings.length + s.scenes.length > 0);
  if (group === "types") nonEmpty.sort((a, b) => (a.key === "Sensors" ? 1 : 0) - (b.key === "Sensors" ? 1 : 0) || (a.key === "Scenes" ? 1 : 0) - (b.key === "Scenes" ? 1 : 0));

  return (
    <>
      {note && <div className={`banner ${note.ok ? "good" : "bad"}`} role="status"><Icon name={note.ok ? "check" : "alert"} size={16} /><span>{note.text}</span>
        <button className="link" onClick={() => setNote(null)} style={{ marginLeft: "auto" }}>Dismiss</button></div>}
      {nonEmpty.length === 0 && <p className="muted">{needle ? "No devices match." : "Home Assistant has no devices NCC can show yet."}</p>}
      <div className="sh-rooms">
        {nonEmpty.map((s) => (
          <section key={s.key} className="card sh-room">
            <div className="sh-room-head">
              <h2><Icon name={s.icon} size={16} /> {s.title}</h2>
              {s.readings.length > 0 && (
                <div className="sh-readings">
                  {s.readings.filter((r) => group === "rooms" ? r.device_class === "temperature" || r.device_class === "humidity" || r.device_class === "carbon_dioxide" : true)
                    .slice(0, group === "rooms" ? 3 : 99).map((r) => (
                      <span key={r.id} className={`sh-reading ${r.state === "unavailable" ? "off" : ""}`} title={r.name}>
                        <Icon name={entityIcon(r)} size={13} />{stateText(r)}
                      </span>
                    ))}
                </div>
              )}
            </div>
            <div className="sh-grid">
              {s.controls.map((e) => (
                <EntityCard key={e.id} e={e} dev={e.device ? devBy[e.device] : undefined} unit={unit} busy={!!busy[e.id]} canOperate={canOperate}
                  isAdmin={user.role === "admin"} run={run} />
              ))}
              {group === "types" && s.key === "Sensors" && s.readings.map((r) => <ReadingCard key={r.id} e={r} dev={r.device ? devBy[r.device] : undefined} />)}
              {group === "rooms" && s.readings.some((r) => r.domain === "binary_sensor" || r.device_class === "power" || (r.device_class === "battery" && !s.controls.some((c) => c.device && c.device === r.device))) && (
                <div className="sh-mini">
                  {s.readings.filter((r) => !(r.device_class === "temperature" || r.device_class === "humidity" || r.device_class === "carbon_dioxide")
                    && !(r.device_class === "battery" && s.controls.some((c) => c.device && c.device === r.device))).map((r) => (
                    <div key={r.id} className={`sh-mini-row ${r.device_class === "battery" && Number(r.state) <= 20 ? "warn" : ""}`}>
                      <Icon name={entityIcon(r)} size={14} /><span className="grow-col">{r.name}</span><strong>{stateText(r)}</strong>
                    </div>
                  ))}
                </div>
              )}
            </div>
            {s.scenes.length > 0 && (
              <div className="sh-scenes">
                {s.scenes.map((e) => (
                  <button key={e.id} disabled={!canOperate || busy[e.id]} onClick={() => run(e, e.domain === "button" ? "press" : "activate")} title={stateText(e)}>
                    <Icon name="sparkle" size={14} />{e.name}
                  </button>
                ))}
              </div>
            )}
          </section>
        ))}
      </div>
      {confirm && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="sh-confirm-title" onClick={(ev) => ev.target === ev.currentTarget && setConfirm(null)}>
          <div className="modal">
            <div className="modal-head"><h2 id="sh-confirm-title">{confirm.plan.description}?</h2></div>
            <p>This can let someone into your home, so NCC asks first. It runs <code>{confirm.plan.call.domain}.{confirm.plan.call.service}</code> on{" "}
              <code>{confirm.plan.entity}</code> in Home Assistant and is written to the audit log.</p>
            <div className="row">
              <button className="primary" onClick={confirmRun} disabled={busy[confirm.plan.entity]}>{busy[confirm.plan.entity] ? "Working…" : confirm.plan.description}</button>
              <button onClick={() => setConfirm(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function EntityCard({ e, dev, unit, busy, canOperate, isAdmin, run }: {
  e: SmartEntity; dev?: SmartDevice; unit?: string; busy: boolean; canOperate: boolean; isAdmin: boolean;
  run: (e: SmartEntity, action: string, extra?: Record<string, unknown>) => void;
}) {
  const can = (a: string) => canOperate && !!e.actions?.includes(a);
  const off = e.state === "unavailable";
  const active = isActive(e);
  const [bri, setBri] = useState(e.brightness ?? 100);
  useEffect(() => { if (e.brightness !== undefined) setBri(e.brightness); }, [e.brightness]);
  const toggleable = e.actions?.includes("toggle");
  const step = e.temp_step || 0.5;
  const sub = [dev?.manufacturer && dev.model ? `${dev.manufacturer} ${dev.model}` : dev?.model, e.source].filter(Boolean).join(" · ");
  const sensitive = (a: string) => (a === "unlock" || a === "disarm" || (a === "open" && ["garage", "gate", "door"].includes(e.device_class ?? "")));
  const adminOnly = (a: string) => sensitive(a) && !isAdmin;

  return (
    <div className={`sh-card ${active ? "active" : ""} ${off ? "off" : ""} ${e.domain}`}>
      <div className="sh-card-top">
        <span className="sh-icon"><Icon name={entityIcon(e)} size={18} /></span>
        <div className="grow-col sh-name">
          <strong title={e.id}>{e.name}</strong>
          <span className="muted small">{stateText(e, unit)}</span>
        </div>
        {toggleable && (
          <button role="switch" aria-checked={e.state === "on"} aria-label={`${e.name} ${e.state === "on" ? "on" : "off"}`}
            className={`sh-toggle ${e.state === "on" ? "on" : ""}`} disabled={!can("toggle") || busy} onClick={() => run(e, "toggle")}><span /></button>
        )}
      </div>
      {e.domain === "light" && e.dimmable && !off && (
        <label className="sh-range">
          <span className="sr-only">Brightness</span>
          <input type="range" min={1} max={100} value={e.state === "on" ? bri : 0} disabled={!can("brightness") || busy}
            onChange={(ev) => setBri(Number(ev.target.value))}
            onPointerUp={(ev) => run(e, "brightness", { value: Number((ev.target as HTMLInputElement).value) })}
            onKeyUp={(ev) => ["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown", "Home", "End"].includes(ev.key) && run(e, "brightness", { value: Number((ev.target as HTMLInputElement).value) })} />
          <span className="small muted sh-pct">{e.state === "on" ? `${bri}%` : "off"}</span>
        </label>
      )}
      {(e.domain === "climate" || e.domain === "water_heater") && !off && (
        <div className="sh-climate">
          <button className="iconbtn" aria-label="Lower" disabled={!can("set_temperature") || busy || e.target_temp === undefined}
            onClick={() => run(e, "set_temperature", { value: Math.round(((e.target_temp ?? 20) - step) * 10) / 10 })}><Icon name="minus" size={15} /></button>
          <span className="sh-target">{e.target_temp !== undefined ? `${e.target_temp}${unit ?? "°"}` : "–"}</span>
          <button className="iconbtn" aria-label="Raise" disabled={!can("set_temperature") || busy || e.target_temp === undefined}
            onClick={() => run(e, "set_temperature", { value: Math.round(((e.target_temp ?? 20) + step) * 10) / 10 })}><Icon name="plus" size={15} /></button>
          {e.hvac_modes && e.hvac_modes.length > 0 && (
            <select aria-label="Mode" value={e.state} disabled={!can("set_hvac_mode") || busy} onChange={(ev) => run(e, "set_hvac_mode", { mode: ev.target.value })}>
              {e.hvac_modes.map((m) => <option key={m} value={m}>{words[m] ?? m}</option>)}
            </select>
          )}
          {e.humidity !== undefined && <span className="muted small"><Icon name="droplet" size={12} /> {e.humidity}%</span>}
        </div>
      )}
      {!toggleable && !["climate", "water_heater", "camera"].includes(e.domain) && (e.actions?.length ?? 0) > 0 && (
        <div className="sh-actions">
          {(e.actions ?? []).filter((a) => a !== "brightness").map((a) => (
            <button key={a} disabled={!can(a) || busy || adminOnly(a) || (a === "lock" && e.state === "locked") || (a === "unlock" && e.state === "unlocked")
              || (a === "open" && e.state === "open") || (a === "close" && e.state === "closed") || (a === "turn_off" && e.state === "off")}
              title={adminOnly(a) ? "Needs an admin" : undefined} onClick={() => run(e, a)}>
              {sensitive(a) && <Icon name="shield" size={13} />}{actionLabel(e, a)}
            </button>
          ))}
        </div>
      )}
      {e.battery !== undefined && e.domain !== "vacuum" && (
        <div className={`small sh-batt ${e.battery <= 20 ? "warn-text" : "muted"}`}><Icon name="battery" size={12} /> {e.battery}%</div>
      )}
      {e.domain === "vacuum" && e.battery !== undefined && <div className="small muted sh-batt"><Icon name="battery" size={12} /> {e.battery}%</div>}
      {sub && <div className="muted small sh-sub">{sub}</div>}
    </div>
  );
}

function actionLabel(e: SmartEntity, a: string): string {
  const m: Record<string, string> = {
    turn_on: "On", turn_off: "Off", open: "Open", close: "Close", stop: "Stop", lock: "Lock", unlock: "Unlock", play_pause: e.state === "playing" ? "Pause" : "Play",
    start: "Start", pause: "Pause", dock: "Dock", arm_home: "Arm home", arm_away: "Arm away", disarm: "Disarm", press: "Press", activate: "Run",
  };
  return m[a] ?? a;
}

function ReadingCard({ e, dev }: { e: SmartEntity; dev?: SmartDevice }) {
  return (
    <div className={`sh-card reading ${e.state === "unavailable" ? "off" : ""}`}>
      <div className="sh-card-top">
        <span className="sh-icon"><Icon name={entityIcon(e)} size={18} /></span>
        <div className="grow-col sh-name"><strong title={e.id}>{e.name}</strong><span className="muted small">{dev?.name && dev.name !== e.name ? dev.name : e.source}</span></div>
        <span className="sh-value">{stateText(e)}</span>
      </div>
    </div>
  );
}

const ecosystems: { key: keyof Pick<SmartInventory["hub"], "matter" | "nest" | "cast" | "alexa">; name: string; how: React.ReactNode }[] = [
  { key: "matter", name: "Matter (Google Home, Alexa, Apple Home)", how: <>Devices with the Matter logo. Share each one from the app it's in with a pairing code (<strong>Add Matter device</strong> above); it stays in that app too.</> },
  { key: "nest", name: "Google Nest thermostats, cameras and doorbells", how: <>Older Nest devices don't speak Matter. Add Home Assistant's <strong>Google Nest</strong> integration; Google charges a one-time US$5 for Device Access.</> },
  { key: "cast", name: "Nest speakers, displays and Chromecast", how: <>Found on your network by Home Assistant's <strong>Google Cast</strong> integration: play, pause and power.</> },
  { key: "alexa", name: "Amazon Echo devices", how: <>Add Home Assistant's <strong>Alexa Devices</strong> integration with your Amazon login. Alexa's Matter devices can be shared like Google's.</> },
];

function Ecosystems({ hubs }: { hubs: SmartInventory["hub"][] }) {
  if (hubs.length === 0) return null;
  return (
    <section className="card" style={{ marginTop: 18 }}>
      <h2><Icon name="link" size={16} /> Google Home, Alexa and others</h2>
      <ul className="list sh-eco">
        {ecosystems.map((x) => {
          const on = hubs.some((h) => h[x.key]);
          return (
            <li key={x.key}>
              <span className={`dot ${on ? "good" : ""}`} />
              <span className="grow-col"><strong>{x.name}</strong><span className="muted small">{x.how}</span></span>
              <span className={`pill ${on ? "good" : ""}`}>{on ? "Set up" : "Not set up"}</span>
            </li>
          );
        })}
      </ul>
      <p className="muted small" style={{ marginBottom: 0 }}>Hue, TP-Link Kasa and Tapo, Zigbee, Z-Wave, Shelly, Sonos, Ring and hundreds more appear here once they're added in Home Assistant. Google Home routines and Alexa routines stay in their own apps.</p>
    </section>
  );
}

const pairApps: { id: string; name: string; steps: React.ReactNode }[] = [
  { id: "google", name: "Google Home", steps: <ol className="sh-steps"><li>Open the Google Home app and tap the device.</li><li>Tap <strong>Settings</strong> (the gear) → <strong>Linked Matter apps &amp; services</strong> → <strong>Link apps &amp; services</strong>.</li><li>Choose <strong>Share with QR code</strong> or copy the 11-digit pairing code, and paste it below within a few minutes.</li></ol> },
  { id: "alexa", name: "Alexa", steps: <ol className="sh-steps"><li>Open the Alexa app → <strong>Devices</strong> and tap the device.</li><li>Tap the gear → <strong>Other assistants and apps</strong> → <strong>Add another</strong>.</li><li>Paste the pairing code it shows below.</li></ol> },
  { id: "apple", name: "Apple Home", steps: <ol className="sh-steps"><li>In the Home app, long-press the device → <strong>Settings</strong>.</li><li>Tap <strong>Turn On Pairing Mode</strong> and copy the setup code.</li><li>Paste it below.</li></ol> },
  { id: "new", name: "New device", steps: <ol className="sh-steps"><li>Type the 11-digit code printed next to the Matter QR code on the device or its box.</li><li>Brand-new devices are usually set up over Bluetooth; that works best from the Home Assistant phone app. Tick "on the network already" off below only for Wi-Fi or Ethernet devices that are already connected.</li></ol> },
];

function MatterPair({ sources, onClose, onPaired }: { sources: SmartSource[]; onClose: () => void; onPaired: () => void }) {
  const [hub, setHub] = useState(sources[0]?.id ?? 0);
  const [app, setApp] = useState("google");
  const [code, setCode] = useState("");
  const [check, setCheck] = useState<MatterCheck | null>(null);
  const [onNet, setOnNet] = useState(true);
  const [state, setState] = useState<"idle" | "checking" | "pairing" | "done">("idle");
  const [err, setErr] = useState("");
  const [added, setAdded] = useState<string[]>([]);

  useEffect(() => { setOnNet(app !== "new"); }, [app]);

  const doCheck = async (ev: React.FormEvent) => {
    ev.preventDefault();
    setErr(""); setCheck(null); setState("checking");
    try {
      setCheck(await api<MatterCheck>("POST", "/api/smarthome/matter/check", { id: hub, code }));
    } catch (e) {
      setErr((e as Error).message);
    }
    setState("idle");
  };
  const pair = async () => {
    setErr(""); setState("pairing");
    try {
      const r = await api<{ new_devices?: string[] }>("POST", "/api/smarthome/matter/pair", { id: hub, code, network_only: onNet });
      setAdded(r.new_devices ?? []);
      setState("done");
      onPaired();
    } catch (e) {
      setErr((e as Error).message);
      setState("idle");
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="matter-title" onClick={(ev) => ev.target === ev.currentTarget && state !== "pairing" && onClose()}>
      <div className="modal wide">
        <div className="modal-head">
          <h2 id="matter-title"><Icon name="qr" size={16} /> Add a Matter device</h2>
          <button className="iconbtn" onClick={onClose} disabled={state === "pairing"} aria-label="Close">✕</button>
        </div>
        {state === "done" ? (
          <>
            <div className="banner good"><Icon name="check" size={16} /><span>
              {added.length ? <>Added <strong>{added.join(", ")}</strong>. </> : "Paired. "}
              It stays in {pairApps.find((a) => a.id === app)?.name ?? "its app"} as well. Give it a room in Home Assistant so it shows up in the right place here.
            </span></div>
            <div className="row"><button className="primary" onClick={onClose}>Done</button><button onClick={() => { setState("idle"); setCode(""); setCheck(null); }}>Add another</button></div>
          </>
        ) : (
          <>
            <p className="muted" style={{ marginTop: 0 }}>Matter devices can be controlled from several apps at once. Share one from the app it's in and NCC (through Home Assistant) gets control too.</p>
            <div className="seg" role="tablist" aria-label="Where the device is now">
              {pairApps.map((a) => <button key={a.id} role="tab" aria-selected={app === a.id} className={app === a.id ? "on" : ""} onClick={() => setApp(a.id)}>{a.name}</button>)}
            </div>
            {pairApps.find((a) => a.id === app)?.steps}
            <form onSubmit={doCheck}>
              <div className="row">
                {sources.length > 1 && <label>Home Assistant<select value={hub} onChange={(e) => setHub(Number(e.target.value))}>{sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}</select></label>}
                <label style={{ flex: 1 }}>Pairing code or QR text<input value={code} onChange={(e) => { setCode(e.target.value); setCheck(null); }} placeholder="1234-567-8901 or MT:…" autoComplete="off" spellCheck={false} className="mono" /></label>
                <button disabled={!code.trim() || state !== "idle"}>{state === "checking" ? "Checking…" : "Check code"}</button>
              </div>
              <label className="check block"><input type="checkbox" checked={onNet} onChange={(e) => setOnNet(e.target.checked)} /> The device is on the network already (shared from another app, or a Wi-Fi or Ethernet device)</label>
            </form>
            {err && <div className="error block">{err}</div>}
            {check && (
              <div className="subcard sh-preview">
                <h3>Ready to pair</h3>
                <dl className="kv">
                  <dt>Code</dt><dd className="mono">{check.code.formatted} <span className="muted small">({check.code.kind === "qr" ? "QR payload" : check.code.vendor_present ? "21-digit code" : "11-digit code"}, check digit OK)</span></dd>
                  <dt>Paired by</dt><dd>{check.hub} (Home Assistant's Matter server)</dd>
                  <dt>Then</dt><dd>The device appears here and in Home Assistant, and stays in {pairApps.find((a) => a.id === app)?.name ?? "its app"}.</dd>
                </dl>
                {!check.matter_ready ? (
                  <div className="banner warn"><Icon name="alert" size={16} /><span>Matter isn't set up in Home Assistant yet: add the Matter integration there first, then refresh.</span></div>
                ) : (
                  <div className="row">
                    <button className="primary" onClick={pair} disabled={state === "pairing"}>{state === "pairing" ? "Pairing… this can take a minute" : "Pair device"}</button>
                    <button onClick={() => setCheck(null)} disabled={state === "pairing"}>Cancel</button>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

function Tile({ label, value, sub, tone, icon, iconTone, valueClass }: {
  label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: "good" | "warn" | "bad"; icon: IconName; iconTone?: string; valueClass?: string;
}) {
  return (
    <div className={`tile ${tone ?? ""}`}>
      <div className="tile-top">
        <span className="tile-label">{label}</span>
        <span className={`tile-icon ${iconTone ?? tone ?? ""}`}><Icon name={icon} size={17} /></span>
      </div>
      <div className={`tile-value ${valueClass ?? ""}`}>{value}</div>
      {sub && <div className="muted small sh-tile-sub">{sub}</div>}
    </div>
  );
}
