import { Fragment, useEffect, useMemo, useState } from "react";
import { api, User, VM, VMHost, VMView } from "../api";
import { ago, uptime } from "../live";
import { Icon, IconName } from "../icons";
import { Meter } from "../charts";
import { bytes } from "./Traffic";
import { AddTarget, Kind } from "./Settings";

const platformLabel: Record<string, string> = { proxmox: "Proxmox VE", vmware: "VMware" };
const typeLabel: Record<string, string> = { qemu: "VM", lxc: "Container", vm: "VM" };
const stateTone: Record<string, string> = { running: "good", suspended: "warn", stopped: "", unknown: "warn" };

function pct(n: number) {
  return `${Math.round(Math.max(0, Math.min(1, n)) * 100)}%`;
}

function load(n: number): "good" | "warn" | "bad" {
  return n >= 0.9 ? "bad" : n >= 0.75 ? "warn" : "good";
}

export function VirtualMachines({ tick, user }: { tick: number; user: User }) {
  const [view, setView] = useState<VMView | null>(null);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const [state, setState] = useState("");
  const [host, setHost] = useState("");
  const [templates, setTemplates] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [adding, setAdding] = useState<Kind | null>(null);
  const [busy, setBusy] = useState(false);
  const isAdmin = user.role === "admin";
  const canPower = user.role !== "viewer";
  const [pending, setPending] = useState<Record<string, string>>({});
  const [note, setNote] = useState<{ id: string; ok: boolean; text: string } | null>(null);

  const refetch = () => api<VMView>("GET", "/api/vms").then((v) => { setView(v); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { refetch(); }, [tick]);

  const refresh = async () => {
    if (!view) return;
    setBusy(true);
    const fails: string[] = [];
    await Promise.all(view.sources.filter((s) => s.enabled).map((s) =>
      api("POST", `/api/targets/${s.id}/poll`).catch((e) => fails.push(`${s.name}: ${(e as Error).message}`))));
    setErr(fails.join(" · "));
    setBusy(false);
    refetch();
  };

  const power = async (v: VM, action: Action) => {
    const ask: Partial<Record<Action, string>> = {
      shutdown: `Shut down ${v.name}? The guest OS is asked to shut down cleanly.`,
      stop: `Power off ${v.name} now? This is like pulling the plug: unsaved work in the machine is lost.`,
      reboot: `Restart ${v.name}?`,
    };
    if (ask[action] && !window.confirm(ask[action])) return;
    setPending((p) => ({ ...p, [v.id]: actionLabel[action].busy }));
    try {
      await api("POST", "/api/vms/power", { id: v.id, action });
      setNote({ id: v.id, ok: true, text: actionLabel[action].done(v.name) });
    } catch (e) {
      setNote({ id: v.id, ok: false, text: `${v.name}: ${(e as Error).message}` });
      setOpen(v.id);
    }
    setPending((p) => { const n = { ...p }; delete n[v.id]; return n; });
    refetch();
  };

  const vms = view?.vms ?? [];
  const hosts = view?.hosts ?? [];
  const sources = view?.sources ?? [];

  const shown = useMemo(() => {
    const s = q.toLowerCase();
    return vms.filter((v) =>
      (templates || !v.template) &&
      (!state || v.state === state) &&
      (!host || `${v.target}/${v.host}` === host) &&
      (!s || [v.name, v.host, v.os, v.target, ...(v.ips ?? []), ...(v.tags ?? [])].some((x) => x?.toLowerCase().includes(s))),
    ).sort((a, b) => (a.state === "running" ? 0 : 1) - (b.state === "running" ? 0 : 1) || a.name.localeCompare(b.name));
  }, [vms, q, state, host, templates]);

  const real = vms.filter((v) => !v.template);
  const running = real.filter((v) => v.state === "running");
  const vcpu = running.reduce((s, v) => s + v.cpus, 0);
  const threads = hosts.reduce((s, h) => s + h.cpus, 0);
  const memAlloc = running.reduce((s, v) => s + v.mem_bytes, 0);
  const memHost = hosts.reduce((s, h) => s + h.mem_bytes, 0);
  const hostsOnline = hosts.filter((h) => h.online).length;
  const failing = sources.filter((s) => s.enabled && s.last_error);
  const multiSource = new Set(hosts.map((h) => h.target)).size > 1;

  if (!view) return <><h1>Virtual machines</h1>{err ? <div className="error block">{err}</div> : <p className="muted">Loading…</p>}</>;

  const addButtons = isAdmin && !adding && (
    <div className="row">
      <button className={sources.length ? "" : "primary"} onClick={() => setAdding("proxmox")}>Add Proxmox VE</button>
      <button onClick={() => setAdding("vmware")}>Add VMware vCenter or ESXi</button>
    </div>
  );

  if (sources.length === 0) {
    return (
      <>
        <h1>Virtual machines</h1>
        <p className="muted lede">See every virtual machine and container on your Proxmox VE cluster or VMware vCenter and ESXi hosts in one list.</p>
        <section className="card">
          <div className="empty" style={{ alignItems: "flex-start", textAlign: "left", padding: 0 }}>
            <span className="tile-icon"><Icon name="vm" size={17} /></span>
            <p style={{ margin: "4px 0 10px" }}>
              Nothing connected yet. NCC reads each machine's state, host, CPU, memory, disk, IP addresses and uptime. It only reads, and the
              login is kept in the vault like your other credentials.
            </p>
          </div>
          {isAdmin ? addButtons : <p className="muted small">Ask an admin to add a Proxmox VE or VMware connection.</p>}
          {adding && <AddTarget kind={adding} onDone={() => { setAdding(null); refetch(); }} />}
        </section>
      </>
    );
  }

  return (
    <>
      <div className="card-head" style={{ marginBottom: 4 }}>
        <h1 style={{ margin: 0 }}>Virtual machines</h1>
        {user.role !== "viewer" && <button onClick={refresh} disabled={busy}>{busy ? "Refreshing…" : "Refresh now"}</button>}
      </div>
      <p className="muted lede">
        {running.length} of {real.length} machines running on {hosts.length} host{hosts.length === 1 ? "" : "s"}
        {" · "}from {sources.map((s) => s.name).join(", ")}
        {sources[0]?.taken_at && <> · updated {ago(sources[0].taken_at)}</>}
      </p>
      {err && <div className="error block">{err}</div>}
      {failing.map((s) => (
        <div key={s.id} className="banner bad" role="alert">
          <Icon name="alert" size={16} /><strong>{s.name}</strong><span>{s.last_error}</span>
          {s.taken_at && <span className="muted small">Showing the list from {ago(s.taken_at)}.</span>}
        </div>
      ))}
      {sources.flatMap((s) => (s.warnings ?? []).map((w) => (
        <div key={s.id + w} className="banner warn"><Icon name="alert" size={16} /><strong>{s.name}</strong><span>{w}</span></div>
      )))}

      <div className="tiles">
        <Tile label="Running" icon="vm" tone={running.length ? "good" : undefined}
          value={<>{running.length}<small> / {real.length}</small></>}
          sub={`${real.filter((v) => v.state === "stopped").length} stopped${vms.length - real.length ? ` · ${vms.length - real.length} templates` : ""}`} />
        <Tile label="vCPUs in use" icon="devices" iconTone="c2" value={<>{vcpu}<small>{threads ? ` / ${threads}` : ""}</small></>}
          sub={threads ? `${(vcpu / threads).toFixed(1)}× host threads` : "allocated to running machines"} />
        <Tile label="Memory allocated" icon="dashboard" iconTone="c3" valueClass="small-value"
          value={<>{bytes(memAlloc)}<small>{memHost ? ` / ${bytes(memHost)}` : ""}</small></>}
          sub={memHost ? `${pct(memAlloc / memHost)} of host memory` : "to running machines"} />
        <Tile label="Hosts online" icon="server" tone={hostsOnline < hosts.length ? "bad" : "good"}
          value={<>{hostsOnline}<small> / {hosts.length}</small></>}
          sub={[...new Set(sources.map((s) => platformLabel[s.kind]))].join(" · ")} />
      </div>

      <section className="card">
        <h2><Icon name="server" size={16} /> Hosts</h2>
        <div className="hostgrid">
          {hosts.map((h) => <HostCard key={h.target + h.name} h={h} vms={real.filter((v) => v.target === h.target && v.host === h.name)}
            showTarget={multiSource} active={host === `${h.target}/${h.name}`}
            onPick={() => setHost(host === `${h.target}/${h.name}` ? "" : `${h.target}/${h.name}`)} />)}
          {hosts.length === 0 && <p className="muted">No hosts read yet.</p>}
        </div>
      </section>

      <div className="toolbar">
        <input placeholder="Search name, IP, OS or tag" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={state} onChange={(e) => setState(e.target.value)}>
          <option value="">All states</option>
          <option value="running">Running</option>
          <option value="stopped">Stopped</option>
          <option value="suspended">Suspended / paused</option>
        </select>
        <select value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">All hosts</option>
          {hosts.map((h) => <option key={h.target + h.name} value={`${h.target}/${h.name}`}>{multiSource ? `${h.target} / ${h.name}` : h.name}</option>)}
        </select>
        <label className="check"><input type="checkbox" checked={templates} onChange={(e) => setTemplates(e.target.checked)} /> Show templates</label>
        <span className="muted">{shown.length} of {vms.length}</span>
      </div>

      <div className="card flush">
        <table className="vmtable">
          <thead>
            <tr><th>Name</th><th>State</th><th>Host</th><th>CPU</th><th>Memory</th><th>Disk</th><th>IP addresses</th><th className="num">Uptime</th>{canPower && <th />}</tr>
          </thead>
          <tbody>
            {shown.map((v) => (
              <Fragment key={v.id}>
                <tr className="clickable" onClick={() => setOpen(open === v.id ? null : v.id)}>
                  <td>
                    <span className="devname">
                      <span className={`kind-chip k-${v.type}`} title={typeLabel[v.type]}><Icon name={(v.type === "lxc" ? "container" : "vm") as IconName} size={16} /></span>
                      <span>
                        <strong>{v.name}</strong>
                        <div className="muted small">{typeLabel[v.type]}{v.template ? " template" : ""}{v.os ? ` · ${v.os}` : ""}</div>
                      </span>
                    </span>
                  </td>
                  <td><span className={`pill ${stateTone[v.state] ?? ""}`}>{v.state}</span></td>
                  <td>{v.host}{multiSource && <div className="muted small">{v.target}</div>}</td>
                  <td><Usage label={`${v.cpus} vCPU`} value={v.state === "running" ? v.cpu_usage : undefined} detail={v.state === "running" ? pct(v.cpu_usage) : ""} /></td>
                  <td><Usage label={bytes(v.mem_bytes)} value={v.state === "running" && v.mem_used ? v.mem_used / v.mem_bytes : undefined}
                    detail={v.state === "running" && v.mem_used ? `${bytes(v.mem_used)} used` : ""} /></td>
                  <td><Usage label={v.disk_bytes ? bytes(v.disk_bytes) : "–"} value={v.disk_used && v.disk_bytes ? v.disk_used / v.disk_bytes : undefined}
                    detail={v.disk_used ? `${bytes(v.disk_used)} used` : ""} /></td>
                  <td className="mono small">{(v.ips ?? []).slice(0, 2).map((ip) => <div key={ip}>{ip}</div>)}
                    {(v.ips?.length ?? 0) > 2 && <div className="muted">+{v.ips!.length - 2} more</div>}
                    {!v.ips?.length && v.state === "running" && <span className="muted" title={v.guest_tools}>—</span>}</td>
                  <td className="num">{v.state === "running" ? uptime(v.uptime_s) : ""}</td>
                  {canPower && (
                    <td className="vm-quick" onClick={(e) => e.stopPropagation()}>
                      {!v.template && (pending[v.id] ? <span className="muted small">{pending[v.id]}…</span> : v.state === "running" ? (
                        <button className="iconbtn" title="Shut down" aria-label={`Shut down ${v.name}`} onClick={() => power(v, "shutdown")}><Icon name="power" size={16} /></button>
                      ) : (
                        <button className="iconbtn start" title="Start" aria-label={`Start ${v.name}`} onClick={() => power(v, "start")}><Icon name="play" size={16} /></button>
                      ))}
                    </td>
                  )}
                </tr>
                {open === v.id && (
                  <tr className="detail">
                    <td colSpan={canPower ? 9 : 8}>
                      {(canPower || isAdmin) && !v.template && (
                        <VMActions vm={v} isAdmin={isAdmin} pending={pending[v.id]} power={power} onDone={(msg) => { setNote({ id: v.id, ok: true, text: msg }); refetch(); }}
                          onError={(text) => setNote({ id: v.id, ok: false, text })} />
                      )}
                      {isAdmin && v.template && <VMActions vm={v} isAdmin={isAdmin} templateOnly power={power} onDone={(msg) => { setNote({ id: v.id, ok: true, text: msg }); refetch(); }}
                        onError={(text) => setNote({ id: v.id, ok: false, text })} />}
                      {note?.id === v.id && <div className={note.ok ? "ok block" : "error block"}>{note.text}</div>}
                      <dl className="kv">
                        <dt>Platform</dt><dd>{platformLabel[v.platform]} · {v.target}</dd>
                        <dt>ID</dt><dd className="mono">{v.id.slice(v.target.length + 1)}</dd>
                        {v.os && (<><dt>Guest OS</dt><dd>{v.os}</dd></>)}
                        {v.guest_tools && (<><dt>Guest tools</dt><dd>{v.guest_tools}</dd></>)}
                        {v.ips && v.ips.length > 0 && (<><dt>All addresses</dt><dd className="mono">{v.ips.join(", ")}</dd></>)}
                        {v.tags && v.tags.length > 0 && (<><dt>Tags</dt><dd>{v.tags.map((t) => <span key={t} className="pill" style={{ marginRight: 4 }}>{t}</span>)}</dd></>)}
                        {v.notes && (<><dt>Notes</dt><dd style={{ whiteSpace: "pre-wrap" }}>{v.notes}</dd></>)}
                      </dl>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {shown.length === 0 && <tr><td colSpan={canPower ? 9 : 8} className="muted">{vms.length ? "No machines match the filters." : "No virtual machines read yet."}</td></tr>}
          </tbody>
        </table>
      </div>

      {isAdmin && (
        <section className="card" style={{ marginTop: 18 }}>
          <div className="card-head"><h2><Icon name="link" size={16} /> Connections</h2><a href="#/settings">Manage in Settings →</a></div>
          <ul className="list">
            {sources.map((s) => (
              <li key={s.id}>
                <span className={`dot ${!s.enabled ? "" : s.last_error ? "bad" : s.taken_at ? "good" : "warn"}`} />
                <span className="grow-col"><strong>{s.name}</strong> <span className="muted small">{platformLabel[s.kind]}{s.version ? ` · ${s.version}` : ""}</span></span>
                <span className="mono small muted">{s.address}</span>
              </li>
            ))}
          </ul>
          {addButtons}
          {adding && <AddTarget kind={adding} onDone={() => { setAdding(null); refetch(); }} />}
        </section>
      )}
    </>
  );
}

type Action = "start" | "shutdown" | "stop" | "reboot";

const actionLabel: Record<Action, { label: string; busy: string; icon: IconName; done: (n: string) => string }> = {
  start: { label: "Start", busy: "Starting", icon: "play", done: (n) => `${n} is starting.` },
  shutdown: { label: "Shut down", busy: "Shutting down", icon: "power", done: (n) => `${n} was asked to shut down. It may take a minute.` },
  reboot: { label: "Restart", busy: "Restarting", icon: "restart", done: (n) => `${n} is restarting.` },
  stop: { label: "Power off", busy: "Powering off", icon: "power", done: (n) => `${n} was powered off.` },
};

function VMActions({ vm, isAdmin, pending, power, onDone, onError, templateOnly }: {
  vm: VM; isAdmin: boolean; pending?: string; power: (v: VM, a: Action) => void; onDone: (msg: string) => void; onError: (msg: string) => void; templateOnly?: boolean;
}) {
  const [mode, setMode] = useState<"" | "edit" | "delete">("");
  const [f, setF] = useState({ name: vm.name, cpus: String(vm.cpus), memory: String(Math.round(vm.mem_bytes / 1048576)), notes: vm.notes ?? "" });
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const running = vm.state === "running";
  const actions: Action[] = running ? ["shutdown", "reboot", "stop"] : vm.state === "suspended" ? ["start", "stop"] : ["start"];

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    const body: Record<string, unknown> = { id: vm.id };
    if (f.name.trim() !== vm.name) body.name = f.name.trim();
    if (Number(f.cpus) !== vm.cpus) body.cpus = Number(f.cpus);
    if (Number(f.memory) !== Math.round(vm.mem_bytes / 1048576)) body.memory_mb = Number(f.memory);
    if (f.notes !== (vm.notes ?? "")) body.notes = f.notes;
    if (Object.keys(body).length === 1) { setMode(""); return; }
    setBusy(true);
    try {
      await api("POST", "/api/vms/settings", body);
      setMode("");
      onDone(running && (body.cpus || body.memory_mb)
        ? `Saved. On a running machine, CPU and memory changes may only take effect after the next restart.`
        : "Saved.");
    } catch (e) {
      onError((e as Error).message);
    }
    setBusy(false);
  };

  const del = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api("POST", "/api/vms/delete", { id: vm.id, confirm });
      onDone(`${vm.name} was deleted.`);
    } catch (e) {
      onError((e as Error).message);
    }
    setBusy(false);
  };

  return (
    <div className="vm-actions">
      <div className="row" style={{ alignItems: "center" }}>
        {!templateOnly && actions.map((a) => (
          <button key={a} disabled={!!pending} className={a === "stop" ? "danger-outline" : ""} onClick={() => power(vm, a)}>
            <Icon name={actionLabel[a].icon} size={15} />{actionLabel[a].label}
          </button>
        ))}
        {pending && <span className="muted small">{pending}…</span>}
        {isAdmin && (
          <>
            <span className="grow" />
            <button onClick={() => setMode(mode === "edit" ? "" : "edit")} aria-expanded={mode === "edit"}><Icon name="edit" size={15} />Edit settings</button>
            <button className="danger-outline" onClick={() => setMode(mode === "delete" ? "" : "delete")} aria-expanded={mode === "delete"}><Icon name="trash" size={15} />Delete</button>
          </>
        )}
      </div>
      {mode === "edit" && (
        <form className="subcard" onSubmit={save}>
          <div className="row">
            <label>Name<input value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required maxLength={80} /></label>
            <label>vCPUs<input type="number" min={1} max={512} value={f.cpus} onChange={(e) => setF({ ...f, cpus: e.target.value })} required /></label>
            <label>Memory (MB)<input type="number" min={16} step={1} value={f.memory} onChange={(e) => setF({ ...f, memory: e.target.value })} required /></label>
          </div>
          <label>Notes<textarea rows={3} value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} maxLength={8192} /></label>
          {running && <p className="muted small">This machine is running. {vm.platform === "vmware"
            ? "VMware only changes CPU or memory on a running machine when hot-add is turned on; otherwise shut it down first."
            : "Proxmox applies CPU and memory changes at the next restart unless hotplug is enabled for them."}</p>}
          <div className="row">
            <button className="primary" disabled={busy}>{busy ? "Saving…" : "Save changes"}</button>
            <button type="button" onClick={() => setMode("")}>Cancel</button>
          </div>
        </form>
      )}
      {mode === "delete" && (
        <form className="subcard danger-zone" onSubmit={del}>
          {vm.state !== "stopped" ? (
            <p className="small" style={{ margin: 0 }}>Shut down or power off <strong>{vm.name}</strong> before deleting it.</p>
          ) : (
            <>
              <p className="small" style={{ marginTop: 0 }}>
                This permanently deletes <strong>{vm.name}</strong> and its disks from {vm.host}. It can't be undone from NCC.
                Type the machine's name to confirm.
              </p>
              <div className="row">
                <label>Machine name<input value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={vm.name} autoComplete="off" /></label>
                <button className="danger-solid" disabled={busy || confirm !== vm.name}>{busy ? "Deleting…" : "Delete permanently"}</button>
                <button type="button" onClick={() => setMode("")}>Cancel</button>
              </div>
            </>
          )}
        </form>
      )}
    </div>
  );
}

function Usage({ label, value, detail }: { label: string; value?: number; detail?: string }) {
  return (
    <div className="usage">
      <div className="usage-top"><span>{label}</span>{detail && <span className="muted">{detail}</span>}</div>
      {value !== undefined && <Meter value={value} tone={load(value)} />}
    </div>
  );
}

function HostCard({ h, vms, showTarget, active, onPick }: { h: VMHost; vms: VM[]; showTarget: boolean; active: boolean; onPick: () => void }) {
  const run = vms.filter((v) => v.state === "running").length;
  const mem = h.mem_bytes ? h.mem_used / h.mem_bytes : 0;
  return (
    <button className={`hostcard ${active ? "on" : ""} ${h.online ? "" : "down"}`} onClick={onPick} title="Show only this host's machines">
      <div className="hostcard-top">
        <span className={`dot ${h.online ? "good" : "bad"}`} />
        <strong>{h.name}</strong>
        <span className="muted small grow-right">{run} / {vms.length} running</span>
      </div>
      <div className="muted small hostcard-sub">{[showTarget ? h.target : "", h.model, h.online ? `up ${uptime(h.uptime_s)}` : "offline"].filter(Boolean).join(" · ")}</div>
      <div className="usage-top small"><span>CPU · {h.cpus} threads</span><span className="muted">{pct(h.cpu_usage)}</span></div>
      <Meter value={h.cpu_usage} tone={load(h.cpu_usage)} />
      <div className="usage-top small" style={{ marginTop: 8 }}><span>Memory · {bytes(h.mem_bytes)}</span><span className="muted">{pct(mem)}</span></div>
      <Meter value={mem} tone={load(mem)} />
    </button>
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
      {sub && <div className="muted small">{sub}</div>}
    </div>
  );
}
