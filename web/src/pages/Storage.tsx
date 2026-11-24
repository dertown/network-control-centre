// Storage page: NAS and file servers (QNAP, Synology, SMB, NFS, SNMP) with health, volumes,
// disks, shares and snapshots, plus the management actions each kind supports.
import { Fragment, useEffect, useMemo, useState } from "react";
import {
  api, CapacityHistory, StorageDisk, StorageInventory, StorageShare, StorageSnapshot, StorageSource, StorageVolume, User,
} from "../api";
import { ago, bytes, pct, uptime } from "../format";
import { Icon, IconName } from "../icons";
import { Meter, Sparkline } from "../charts";
import { AlertList, PageHeader, PageLoading, SourceBanners, Tile } from "../ui";
import { ConnectionPicker, RefreshButton, useConnectionAdder, useSourceData } from "../connections";

const healthTone: Record<string, "good" | "warn" | "bad" | ""> = { good: "good", warning: "warn", critical: "bad", unknown: "" };
const healthWord: Record<string, string> = { good: "Healthy", warning: "Warning", critical: "Critical", unknown: "Unknown" };

// fill grades how full a volume is: amber from 85%, red from 95% (same thresholds as the server's alerts).
function fill(n: number): "good" | "warn" | "bad" {
  return n >= 0.95 ? "bad" : n >= 0.85 ? "warn" : "good";
}

// tempTone grades a temperature in °C; SSDs run hotter than hard disks before it matters.
function tempTone(c: number | undefined, ssd?: boolean): "good" | "warn" | "bad" | "" {
  if (!c) return "";
  const [w, b] = ssd ? [65, 75] : [50, 60];
  return c >= b ? "bad" : c >= w ? "warn" : "good";
}

const addGroup = "storage";

export function Storage({ tick, user }: { tick: number; user: User }) {
  const { data: sources, err, busy, refetch, refresh } = useSourceData<{ sources: StorageSource[] }, StorageSource[]>(
    "/api/storage", tick, (d) => d, (r) => r.sources);
  const [pick, setPick] = useState<number | null>(null);
  const isAdmin = user.role === "admin";
  const adder = useConnectionAdder(addGroup, user, refetch);

  const live = useMemo(() => (sources ?? []).filter((s) => s.enabled && s.inventory), [sources]);
  const invs = live.map((s) => s.inventory!);
  const disks = invs.flatMap((i) => i.disks);
  const vols = invs.flatMap((i) => i.volumes);
  const total = vols.reduce((s, v) => s + v.total, 0);
  const used = vols.reduce((s, v) => s + v.used, 0);
  const alerts = live.flatMap((s) => s.inventory!.alerts.map((a) => ({ ...a, source: s })));
  const crit = alerts.filter((a) => a.level === "critical").length;
  const hottest = disks.reduce((m, d) => Math.max(m, d.temp_c ?? 0), 0);
  const shares = invs.reduce((s, i) => s + i.shares.filter((x) => !x.hidden).length, 0);
  const snaps = invs.reduce((s, i) => s + i.snapshots.length, 0);
  const badDisks = disks.filter((d) => d.health === "critical" || d.health === "warning").length;

  if (!sources) return <PageLoading title="Storage" err={err} />;

  if (sources.length === 0) {
    return (
      <>
        <h1>Storage</h1>
        <p className="muted lede">Watch your NAS, file servers and other network storage: health, volumes, disks, temperatures, shares and snapshots.</p>
        <section className="card">
          <div className="empty" style={{ alignItems: "flex-start", textAlign: "left", padding: 0 }}>
            <span className="tile-icon"><Icon name="nas" size={17} /></span>
            <p style={{ margin: "4px 0 10px" }}>
              Nothing connected yet. QNAP (QTS and QuTS hero) and Synology DSM are read through their own API and can be managed from here; any
              SMB or NFS server shows its shares; anything else that speaks SNMP shows its disks and file systems. Logins are kept in the vault.
            </p>
          </div>
          {isAdmin ? <ConnectionPicker group={addGroup} onDone={refetch} primary /> : <p className="muted small">Ask an admin to add your NAS.</p>}
        </section>
      </>
    );
  }

  const shown = pick === null ? live : live.filter((s) => s.id === pick);

  return (
    <>
      <PageHeader title="Storage">
        {adder.button}
        <RefreshButton user={user} busy={busy} onClick={refresh} />
      </PageHeader>
      {adder.panel}
      <p className="muted lede">
        {live.length} device{live.length === 1 ? "" : "s"}{disks.length ? ` · ${disks.length} disks` : ""}
        {total > 0 && <> · {bytes(used)} of {bytes(total)} used</>}
        {live[0]?.taken_at && <> · updated {ago(live[0].taken_at)}</>}
      </p>
      {err && <div className="error block">{err}</div>}
      <SourceBanners sources={sources} warnings={(s) => (s.enabled ? s.inventory?.warnings : undefined)} />

      <div className="tiles">
        <Tile label="Health" icon={crit ? "alert" : "check"} tone={crit ? "bad" : alerts.length ? "warn" : "good"}
          value={crit ? <>{crit}<small> critical</small></> : alerts.length ? <>{alerts.length}<small> warning{alerts.length === 1 ? "" : "s"}</small></> : "All good"}
          sub={alerts.length ? `${alerts.length} alert${alerts.length === 1 ? "" : "s"} across ${new Set(alerts.map((a) => a.source.id)).size} device(s)` : `${live.length} device${live.length === 1 ? "" : "s"} healthy`} />
        <Tile label="Capacity used" icon="dashboard" iconTone="c3" valueClass="small-value" tone={total ? (fill(used / total) === "good" ? undefined : fill(used / total)) : undefined}
          value={total ? <>{pct(used / total)}<small> of {bytes(total)}</small></> : "–"} sub={total ? `${bytes(total - used)} free on ${vols.length} volume${vols.length === 1 ? "" : "s"}` : "no volumes read"} />
        <Tile label="Disks" icon="disk" iconTone="c2" tone={badDisks ? "warn" : undefined}
          value={<>{disks.length - badDisks}<small> / {disks.length} healthy</small></>}
          sub={hottest ? <span className={tempTone(hottest) === "good" ? "" : "warn-text"}>hottest {hottest} °C</span> : "no disk data"} />
        <Tile label="Shares" icon="share" value={shares} sub={snaps ? `${snaps} snapshot${snaps === 1 ? "" : "s"}` : "no snapshots read"} />
      </div>

      <AlertList title="Alerts" alerts={alerts} />

      {live.length > 1 && (
        <div className="toolbar">
          <div className="seg" role="group" aria-label="Device">
            <button className={pick === null ? "on" : ""} onClick={() => setPick(null)}>All devices</button>
            {live.map((s) => <button key={s.id} className={pick === s.id ? "on" : ""} onClick={() => setPick(s.id)}>{s.name}</button>)}
          </div>
        </div>
      )}

      {shown.map((s) => <Device key={s.id} src={s} user={user} onChanged={refetch} />)}

    </>
  );
}

function Device({ src, user, onChanged }: { src: StorageSource; user: User; onChanged: () => void }) {
  const inv = src.inventory!;
  const s = inv.system;
  const isAdmin = user.role === "admin";
  const canOperate = user.role !== "viewer";
  const can = (c: string) => inv.capabilities.includes(c);
  const [history, setHistory] = useState<Record<string, CapacityHistory>>({});
  const [power, setPower] = useState<"" | "restart" | "shutdown">("");
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const icon: IconName = src.kind === "smb" || src.kind === "nfs" ? "server" : "nas";

  useEffect(() => {
    api<{ volumes: CapacityHistory[] }>("GET", `/api/storage/${src.id}/history?days=30`)
      .then((h) => setHistory(Object.fromEntries(h.volumes.map((v) => [v.volume, v])))).catch(() => {});
  }, [src.id, src.taken_at]);

  const mem = s.mem_bytes ? (s.mem_used ?? 0) / s.mem_bytes : 0;
  const facts = [s.model, s.os && s.firmware ? `${s.os} ${s.firmware.replace(/^DSM\s*/, "")}` : s.os || s.firmware, s.uptime_s ? `up ${uptime(s.uptime_s)}` : ""].filter(Boolean);

  return (
    <section className="card st-device">
      <div className="st-head">
        <span className={`kind-chip st-chip ${healthTone[s.health]}`}><Icon name={icon} size={18} /></span>
        <div className="grow-col">
          <div className="st-title"><strong>{s.name || src.name}</strong>{s.name && s.name !== src.name && <span className="muted small">{src.name}</span>}
            <span className={`pill ${healthTone[s.health]}`}>{healthWord[s.health]}</span></div>
          <div className="muted small">{s.vendor}{facts.length ? ` · ${facts.join(" · ")}` : ""}</div>
        </div>
        {isAdmin && (can("restart") || can("shutdown")) && (
          <div className="row st-power">
            {can("restart") && <button onClick={() => setPower(power === "restart" ? "" : "restart")} aria-expanded={power === "restart"}><Icon name="restart" size={15} />Restart</button>}
            {can("shutdown") && <button className="danger-outline" onClick={() => setPower(power === "shutdown" ? "" : "shutdown")} aria-expanded={power === "shutdown"}><Icon name="power" size={15} />Shut down</button>}
          </div>
        )}
      </div>
      {power && <PowerConfirm src={src} action={power} onClose={() => setPower("")} onDone={(t) => { setPower(""); setNote({ ok: true, text: t }); }} />}
      {note && <div className={note.ok ? "ok block" : "error block"}>{note.text}</div>}

      {(s.cpu_usage >= 0 || s.mem_bytes || s.temp_c || s.fans?.length || s.nics?.length) && (
        <div className="st-stats">
          {s.cpu_usage >= 0 && <Stat label="CPU" value={pct(s.cpu_usage)}><Meter value={s.cpu_usage} tone={s.cpu_usage > 0.9 ? "bad" : s.cpu_usage > 0.75 ? "warn" : "good"} /></Stat>}
          {!!s.mem_bytes && <Stat label={`Memory · ${bytes(s.mem_bytes)}`} value={pct(mem)}><Meter value={mem} tone={mem > 0.9 ? "bad" : mem > 0.8 ? "warn" : "good"} /></Stat>}
          {(!!s.temp_c || !!s.cpu_temp_c) && (
            <Stat label="Temperature" value={<span className={`st-temp ${tempTone(s.temp_c, true)}`}><Icon name="thermo" size={14} />{s.temp_c ? `${s.temp_c} °C` : "–"}</span>}>
              <span className="muted small">{s.cpu_temp_c ? `CPU ${s.cpu_temp_c} °C` : "system"}</span>
            </Stat>
          )}
          {!!s.fans?.length && (
            <Stat label="Fans" value={s.fans.every((f) => f.ok) ? "OK" : <span className="warn-text">Fault</span>}>
              <span className="muted small">{s.fans.map((f) => (f.rpm ? `${f.rpm} rpm` : f.name)).join(" · ")}</span>
            </Stat>
          )}
          {!!s.nics?.length && (
            <Stat label="Network" value={`${s.nics.filter((n) => n.up).length} / ${s.nics.length} up`}>
              <span className="muted small mono">{s.nics.filter((n) => n.up).map((n) => n.ip || n.name).join(", ")}{s.nics.find((n) => n.up && n.speed_mbps) ? ` · ${(s.nics.find((n) => n.up && n.speed_mbps)!.speed_mbps! / 1000).toString()} GbE` : ""}</span>
            </Stat>
          )}
        </div>
      )}

      {(inv.pools.length > 0 || inv.volumes.length > 0) && (
        <>
          <h3 className="st-sub"><Icon name="dashboard" size={15} /> {inv.pools.length ? "Pools and volumes" : "Volumes"}</h3>
          <div className="st-vols">
            {inv.pools.map((p) => (
              <div key={"p" + p.id} className="st-vol pool">
                <div className="usage-top"><span><strong>{p.name}</strong> <span className="muted">{[p.raid, p.disks?.length ? `${p.disks.length} disks` : ""].filter(Boolean).join(" · ")}</span></span>
                  <span className={`pill ${healthTone[p.health]}`}>{p.status || healthWord[p.health]}</span></div>
                {p.total > 0 && <><Meter value={p.used / p.total} tone="good" /><div className="muted small">{bytes(p.used)} of {bytes(p.total)} allocated</div></>}
              </div>
            ))}
            {inv.volumes.map((v) => <VolumeRow key={v.id} v={v} h={history[v.id]} />)}
          </div>
        </>
      )}

      {inv.disks.length > 0 && (
        <>
          <h3 className="st-sub"><Icon name="disk" size={15} /> Disks</h3>
          <div className="st-disks">{inv.disks.map((d) => <DiskCard key={d.id} d={d} />)}</div>
        </>
      )}

      <Shares src={src} canOperate={canOperate} isAdmin={isAdmin} onChanged={onChanged} />
    </section>
  );
}

function Stat({ label, value, children }: { label: string; value: React.ReactNode; children?: React.ReactNode }) {
  return (
    <div className="st-stat">
      <div className="usage-top"><span className="muted">{label}</span><strong>{value}</strong></div>
      {children}
    </div>
  );
}

function VolumeRow({ v, h }: { v: StorageVolume; h?: CapacityHistory }) {
  const f = v.total ? v.used / v.total : 0;
  // the sparkline's baseline is zero, so draw the change from the lowest point to show growth
  const raw = h && h.points.length > 1 ? h.points.map((p) => p.used) : [];
  const low = Math.min(...raw);
  const trend = raw.map((x) => x - low);
  return (
    <div className="st-vol">
      <div className="usage-top">
        <span><strong>{v.name}</strong> <span className="muted">{[v.pool, v.fs?.toUpperCase()].filter(Boolean).join(" · ")}</span></span>
        {v.status || v.health !== "unknown" ? <span className={`pill ${healthTone[v.health]}`}>{v.status || healthWord[v.health]}</span> : <span className="muted small" title="QNAP's API doesn't report volume state; add SNMP to the connection to see it">state not reported</span>}
      </div>
      {v.total > 0 && <Meter value={f} tone={fill(f)} />}
      <div className="st-vol-foot">
        <span className="small">{v.total > 0 ? <><strong>{pct(f)}</strong> <span className="muted">· {bytes(v.used)} of {bytes(v.total)} · {bytes(v.total - v.used)} free</span></> : <span className="muted">size not reported</span>}</span>
        {h && (
          <span className="muted small st-trend" title="Growth over the last 30 days">
            {h.per_day !== 0 && <>{h.per_day > 0 ? "+" : "−"}{bytes(Math.abs(h.per_day))}/day</>}
            {h.full_in_days !== undefined && <> · <span className={h.full_in_days < 30 ? "warn-text" : ""}>full in ~{h.full_in_days < 60 ? `${h.full_in_days} days` : `${Math.round(h.full_in_days / 30)} months`}</span></>}
          </span>
        )}
      </div>
      {trend.length > 1 && <div className="st-spark"><Sparkline values={trend} color="var(--c3)" height={26} /></div>}
    </div>
  );
}

function DiskCard({ d }: { d: StorageDisk }) {
  const t = tempTone(d.temp_c, d.type === "ssd");
  return (
    <div className={`st-disk ${d.health === "good" ? "" : healthTone[d.health]}`} title={[d.model, d.serial ? `S/N ${d.serial}` : ""].filter(Boolean).join(" · ")}>
      <div className="st-disk-top">
        <span className={`dot ${healthTone[d.health]}`} />
        <strong>{d.slot}</strong>
        <span className="muted small">{d.type === "ssd" ? "SSD" : d.type === "hdd" ? "HDD" : ""}</span>
        {!!d.temp_c && <span className={`st-temp ${t}`}><Icon name="thermo" size={13} />{d.temp_c} °C</span>}
      </div>
      <div className="small st-disk-model">{d.model || "Unknown model"}</div>
      <div className="muted small">{[d.size ? bytes(d.size) : "", d.pool].filter(Boolean).join(" · ")}</div>
      <div className="st-disk-foot">
        <span className={`pill ${healthTone[d.health]}`}>SMART {d.smart || healthWord[d.health].toLowerCase()}</span>
        {d.status && d.status.toLowerCase() !== (d.smart ?? "").toLowerCase() && <span className="muted small">{d.status}</span>}
      </div>
    </div>
  );
}

function Shares({ src, canOperate, isAdmin, onChanged }: { src: StorageSource; canOperate: boolean; isAdmin: boolean; onChanged: () => void }) {
  const inv = src.inventory!;
  const can = (c: string) => inv.capabilities.includes(c);
  const [open, setOpen] = useState<string | null>(null);
  const [hidden, setHidden] = useState(false);
  const [creating, setCreating] = useState(false);
  const list = inv.shares.filter((s) => hidden || !s.hidden);
  const nfs = inv.shares.some((s) => s.clients?.length);
  const snaps = can("snapshot.list");
  const cols = 4 + (nfs ? 1 : 0) + (snaps ? 1 : 0);
  if (inv.shares.length === 0 && !can("share.create")) return null;
  return (
    <>
      <div className="card-head st-sub-head">
        <h3 className="st-sub"><Icon name="share" size={15} /> Shares <span className="muted small">{list.length}</span></h3>
        <div className="row">
          {inv.shares.some((s) => s.hidden) && <label className="check"><input type="checkbox" checked={hidden} onChange={(e) => setHidden(e.target.checked)} /> Show hidden</label>}
          {isAdmin && can("share.create") && <button onClick={() => setCreating(!creating)} aria-expanded={creating}><Icon name="plus" size={15} />New share</button>}
        </div>
      </div>
      {creating && <NewShare src={src} onDone={(ok) => { setCreating(false); if (ok) onChanged(); }} />}
      <div className="scroll-x">
        <table className="st-shares">
          <thead><tr><th>Name</th><th>Volume</th><th>Protocol</th>{nfs && <th>Allowed</th>}<th className="num">Used</th>{snaps && <th className="num">Snapshots</th>}</tr></thead>
          <tbody>
            {list.map((sh) => {
              const expandable = canOperate && (can("folder.create") || snaps);
              return (
                <Fragment key={sh.name}>
                  <tr className={expandable ? "clickable" : ""} onClick={() => expandable && setOpen(open === sh.name ? null : sh.name)}>
                    <td><span className="devname"><Icon name="folder" size={16} className="muted" /><span><strong>{sh.name}</strong>{sh.comment && <div className="muted small">{sh.comment}</div>}</span></span></td>
                    <td>{volName(inv, sh)}</td>
                    <td>{(sh.protocols ?? []).map((p) => <span key={p} className="pill" style={{ marginRight: 4 }}>{p}</span>)}{sh.encrypted && <span className="pill">encrypted</span>}</td>
                    {nfs && <td className="mono small">{sh.clients?.join(", ")}</td>}
                    <td className="num">{sh.used ? bytes(sh.used) : ""}{sh.total ? <div className="muted small">of {bytes(sh.total)}</div> : ""}</td>
                    {snaps && <td className="num">{sh.snapshots || <span className="muted">0</span>}</td>}
                  </tr>
                  {open === sh.name && (
                    <tr className="detail"><td colSpan={cols}>
                      <ShareDetail src={src} share={sh} snapshots={inv.snapshots.filter((x) => x.share === sh.name)} isAdmin={isAdmin} onChanged={onChanged} />
                    </td></tr>
                  )}
                </Fragment>
              );
            })}
            {list.length === 0 && <tr><td colSpan={cols} className="muted">No shares read.</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}

function volName(inv: StorageInventory, sh: StorageShare) {
  if (!sh.volume) return <span className="muted">–</span>;
  return inv.volumes.find((v) => v.id === sh.volume)?.name.replace(/ \(\+\d+ shares?\)$/, "") ?? sh.volume;
}

function NewShare({ src, onDone }: { src: StorageSource; onDone: (ok: boolean) => void }) {
  const inv = src.inventory!;
  const [f, setF] = useState({ name: "", volume: inv.volumes[0]?.id ?? "", comment: "" });
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      await api("POST", "/api/storage/shares", { id: src.id, name: f.name.trim(), volume: f.volume, comment: f.comment });
      onDone(true);
    } catch (e) {
      setErr((e as Error).message);
    }
    setBusy(false);
  };
  return (
    <form className="subcard" onSubmit={save}>
      <div className="row">
        <label>Share name<input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required maxLength={64} placeholder="backups" /></label>
        <label>Volume<select value={f.volume} onChange={(e) => setF({ ...f, volume: e.target.value })}>
          {inv.volumes.map((v) => <option key={v.id} value={v.id}>{v.name} · {bytes(v.total - v.used)} free</option>)}
        </select></label>
        <label>Description<input value={f.comment} onChange={(e) => setF({ ...f, comment: e.target.value })} maxLength={256} /></label>
      </div>
      <p className="muted small" style={{ marginTop: 0 }}>The share is created with the NAS defaults (recycle bin on, admins only). Set user permissions on the NAS afterwards.</p>
      {err && <div className="error block">{err}</div>}
      <div className="row">
        <button className="primary" disabled={busy || !f.name.trim()}>{busy ? "Creating…" : "Create share"}</button>
        <button type="button" onClick={() => onDone(false)}>Cancel</button>
      </div>
    </form>
  );
}

function ShareDetail({ src, share, snapshots, isAdmin, onChanged }: { src: StorageSource; share: StorageShare; snapshots: StorageSnapshot[]; isAdmin: boolean; onChanged: () => void }) {
  const inv = src.inventory!;
  const can = (c: string) => inv.capabilities.includes(c);
  const [folder, setFolder] = useState("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState("");
  const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [del, setDel] = useState<StorageSnapshot | null>(null);

  const run = async (what: string, call: () => Promise<unknown>, done: string) => {
    setBusy(what);
    setNote(null);
    try {
      await call();
      setNote({ ok: true, text: done });
      onChanged();
    } catch (e) {
      setNote({ ok: false, text: (e as Error).message });
    }
    setBusy("");
  };

  return (
    <div className="vm-actions">
      {share.path && <div className="muted small mono" style={{ marginBottom: 10 }}>{share.path}</div>}
      {can("folder.create") && (
        <form className="row st-folder" onSubmit={(e) => {
          e.preventDefault();
          run("folder", () => api("POST", "/api/storage/folders", { id: src.id, share: share.name, path: folder.trim() }), `Created ${share.name}/${folder.trim()}.`).then(() => setFolder(""));
        }}>
          <label>New folder in {share.name}<input value={folder} onChange={(e) => setFolder(e.target.value)} placeholder="scans/2024" /></label>
          <button disabled={!!busy || !folder.trim()}><Icon name="folder" size={15} />{busy === "folder" ? "Creating…" : "Create folder"}</button>
        </form>
      )}
      {can("snapshot.list") && (
        <div className="st-snaps">
          <div className="card-head" style={{ marginTop: 12 }}>
            <strong><Icon name="snapshot" size={15} /> Snapshots of {share.name}</strong>
            {can("snapshot.create") && (
              <form className="row" style={{ alignItems: "center" }} onSubmit={(e) => {
                e.preventDefault();
                run("snap", () => api("POST", "/api/storage/snapshots", { id: src.id, share: share.name, comment }), `Snapshot of ${share.name} taken.`).then(() => setComment(""));
              }}>
                <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Description (optional)" maxLength={256} aria-label="Snapshot description" />
                <button disabled={!!busy}><Icon name="snapshot" size={15} />{busy === "snap" ? "Taking…" : "Take snapshot"}</button>
              </form>
            )}
          </div>
          {snapshots.length === 0 ? <p className="muted small">No snapshots yet.</p> : (
            <ul className="list">
              {snapshots.map((sn) => (
                <li key={sn.id}>
                  <Icon name="snapshot" size={15} className="muted" />
                  <span className="grow-col"><strong>{sn.created ? new Date(sn.created).toLocaleString() : sn.name}</strong>
                    {sn.comment && <span className="muted"> · {sn.comment}</span>}
                    {sn.locked && <span className="pill" style={{ marginLeft: 6 }}>kept by retention</span>}</span>
                  <span className="muted small">{sn.created ? ago(sn.created) : ""}</span>
                  {isAdmin && can("snapshot.delete") && !sn.locked && (
                    <button className="iconbtn" title="Delete snapshot" aria-label={`Delete snapshot ${sn.name}`} onClick={() => setDel(del?.id === sn.id ? null : sn)}><Icon name="trash" size={15} /></button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {del && (
            <div className="subcard danger-zone">
              <p className="small" style={{ marginTop: 0 }}>Delete the snapshot of <strong>{share.name}</strong> from {del.created ? new Date(del.created).toLocaleString() : del.name}? Files can no longer be restored from it.</p>
              <div className="row">
                <button className="danger-solid" disabled={!!busy} onClick={() => run("del", () => api("POST", "/api/storage/snapshots/delete", { id: src.id, share: share.name, snapshot: del.id }), "Snapshot deleted.").then(() => setDel(null))}>
                  {busy === "del" ? "Deleting…" : "Delete snapshot"}</button>
                <button onClick={() => setDel(null)}>Cancel</button>
              </div>
            </div>
          )}
        </div>
      )}
      {note && <div className={note.ok ? "ok block" : "error block"}>{note.text}</div>}
    </div>
  );
}

function PowerConfirm({ src, action, onClose, onDone }: { src: StorageSource; action: "restart" | "shutdown"; onClose: () => void; onDone: (msg: string) => void }) {
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const go = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api("POST", "/api/storage/power", { id: src.id, action, confirm });
      onDone(action === "restart" ? `${src.name} is restarting. It is usually back in a few minutes; NCC reads it again after four.` : `${src.name} is shutting down. Start it again with its power button or Wake-on-LAN.`);
    } catch (e) {
      setErr((e as Error).message);
    }
    setBusy(false);
  };
  return (
    <form className="subcard danger-zone" onSubmit={go}>
      <p className="small" style={{ marginTop: 0 }}>
        {action === "restart" ? "Restarting" : "Shutting down"} <strong>{src.name}</strong> disconnects every share, backup job and app running on it
        {action === "shutdown" ? " until someone powers it on again" : " for a few minutes"}. Type the connection name to confirm.
      </p>
      <div className="row">
        <label>Connection name<input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={src.name} autoComplete="off" /></label>
        <button className="danger-solid" disabled={busy || confirm !== src.name}>{busy ? "Sending…" : action === "restart" ? "Restart now" : "Shut down now"}</button>
        <button type="button" onClick={onClose}>Cancel</button>
      </div>
      {err && <div className="error block">{err}</div>}
    </form>
  );
}
