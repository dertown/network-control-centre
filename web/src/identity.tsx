// What a topology node really is: the identity NCC worked out from its other sources (VMs,
// storage, DNS, IoT, connections) with the evidence and a confidence, the controls to confirm
// or correct it, and what those sources know about the node (its VMs, storage, DNS names).
import { FormEvent, useEffect, useState } from "react";
import { api, GNode, NodeIdentity, NodeRelated, NodeRole } from "./api";
import { Icon, roleIcon } from "./icons";
import { roleLabel } from "./live";
import { ago, bytes, pct } from "./format";

/** Where each piece of evidence came from, as the chip in front of it says. */
const sourceLabel: Record<string, string> = {
  vm: "VMs", hypervisor: "Hypervisor", storage: "Storage", dns: "DNS", connection: "Connection", iot: "IoT",
  mac: "MAC range", lldp: "LLDP", clients: "Port clients", name: "Name",
};

const roles = Object.keys(roleLabel) as NodeRole[];

function confidencePill(id: NodeIdentity): { cls: string; text: string } {
  if (id.source === "confirmed") return { cls: "good", text: "Confirmed" };
  if (id.source === "manual") return { cls: "good", text: "Set by hand" };
  if (id.confidence === "high") return { cls: "good", text: "High confidence" };
  if (id.confidence === "medium") return { cls: "warn", text: "Medium confidence" };
  return { cls: "", text: "Low confidence" };
}

/** True when the map should show the identity as settled rather than a guess. */
export function identitySure(id?: NodeIdentity): boolean {
  return !!id && (id.source !== "auto" || id.confidence === "high");
}

/** The second line under a node's name on the map. */
export function identityLine(id: NodeIdentity): string {
  return id.confidence === "low" && id.source === "auto" ? `${id.what}?` : id.what;
}

export function IdentityPanel({ node, canEdit, onSaved }: { node: GNode; canEdit: boolean; onSaved: () => void }) {
  const id = node.identity;
  const [editing, setEditing] = useState(false);
  const [role, setRole] = useState<NodeRole>(id?.role ?? "switch");
  const [name, setName] = useState(id?.name ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => { setEditing(false); setErr(""); setRole(node.identity?.role ?? "switch"); setName(node.identity?.name ?? ""); }, [node.id, node.identity?.role, node.identity?.name]);

  const call = async (method: "PUT" | "DELETE", body?: unknown) => {
    setBusy(true); setErr("");
    try {
      await api(method, `/api/topology/identity/${encodeURIComponent(node.id)}`, body);
      setEditing(false);
      onSaved();
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  const save = (ev: FormEvent) => { ev.preventDefault(); call("PUT", { role, name: name.trim() }); };
  const managed = node.discovery === "controller";
  if (!id && (managed || node.kind === "internet")) return null;

  const pill = id ? confidencePill(id) : null;
  return (
    <section className="ident" aria-label="What this is">
      <h3 className="small">What this is</h3>
      {id ? (
        <>
          <div className="ident-head">
            <span className="ident-icon"><Icon name={roleIcon[id.role] ?? "unknown"} size={18} /></span>
            <div className="ident-what">
              <strong>{id.what}</strong>
              {id.name && <span className="muted small">{id.name}</span>}
              {pill && <span className={`pill ${pill.cls}`}>{pill.text}</span>}
            </div>
          </div>
          {id.source !== "auto" && id.by && (
            <p className="small muted ident-note">{id.source === "confirmed" ? "Confirmed" : "Set"} by {id.by}{id.at ? `, ${ago(id.at)}` : ""}.</p>
          )}
          {id.label && <p className="small muted ident-note">The network calls it “{id.label}”.</p>}
          {id.evidence && id.evidence.length > 0 && (
            <ul className="ident-evidence">
              {id.evidence.map((e, i) => (
                <li key={i}><span className="ev-src">{sourceLabel[e.source] ?? e.source}</span><span>{e.text}</span></li>
              ))}
            </ul>
          )}
          {id.guess && (
            <p className="small muted ident-note">
              NCC's own guess: {id.guess.what}{id.guess.name ? ` (${id.guess.name})` : ""}, {id.guess.confidence} confidence.
            </p>
          )}
          {id.merged && <p className="small muted ident-note">Its own network port, <span className="mono">{id.merged}</span>, is shown as part of it.</p>}
        </>
      ) : (
        <p className="small muted ident-note">NCC found nothing in its other sources that says what this is.</p>
      )}
      {canEdit && !editing && (
        <div className="ident-actions">
          {id && id.source === "auto" && (
            <button className="small-btn primary" disabled={busy} onClick={() => call("PUT", { role: id.role, name: id.name ?? "", confirmed: true })}>
              <Icon name="check" size={14} />Confirm
            </button>
          )}
          <button className="small-btn" disabled={busy} onClick={() => setEditing(true)}>
            <Icon name="edit" size={14} />{id ? "Change" : "Say what it is"}
          </button>
          {id && id.source !== "auto" && (
            <button className="small-btn" disabled={busy} onClick={() => call("DELETE")}>
              <Icon name="restart" size={14} />Use NCC's guess
            </button>
          )}
        </div>
      )}
      {editing && (
        <form className="ident-form" onSubmit={save}>
          <label>
            <span className="small muted">It is a</span>
            <select value={role} onChange={(e) => setRole(e.target.value as NodeRole)}>
              {roles.map((r) => <option key={r} value={r}>{roleLabel[r]}</option>)}
            </select>
          </label>
          <label>
            <span className="small muted">Name on the map (optional)</span>
            <input value={name} maxLength={64} placeholder={id?.label ?? node.label} onChange={(e) => setName(e.target.value)} />
          </label>
          <div className="ident-actions">
            <button type="submit" className="small-btn primary" disabled={busy}>Save</button>
            <button type="button" className="small-btn" disabled={busy} onClick={() => setEditing(false)}>Cancel</button>
          </div>
        </form>
      )}
      {err && <p className="small bad-text" role="alert">{err}</p>}
    </section>
  );
}

const VM_LIST = 8;

export function RelatedPanel({ related }: { related?: NodeRelated }) {
  const [allVMs, setAllVMs] = useState(false);
  if (!related) return null;
  const { host, vms, vm, storage, dns, connections, iot } = related;
  const shown = allVMs ? vms ?? [] : (vms ?? []).slice(0, VM_LIST);
  return (
    <section className="related" aria-label="Known from other sources">
      {host && (
        <>
          <h3 className="small">{vm ? "Runs on" : "Hypervisor"}</h3>
          <dl className="kv">
            <dt>Host</dt><dd>{host.name} <span className="muted small">{host.platform}</span></dd>
            {!vm && <><dt>Load</dt><dd>CPU {pct(host.cpu_usage)}{host.mem_bytes ? ` · memory ${bytes(host.mem_used ?? 0)} of ${bytes(host.mem_bytes)}` : ""}</dd></>}
            {!vm && <><dt>Guests</dt><dd>{host.vms} ({host.running} running)</dd></>}
            <dt>Connection</dt><dd><a href="#/vms">{host.target}</a></dd>
          </dl>
        </>
      )}
      {vm && (
        <>
          <h3 className="small">{vm.type === "lxc" ? "Container" : "Virtual machine"}</h3>
          <dl className="kv">
            <dt>Name</dt><dd>{vm.name}</dd>
            <dt>State</dt><dd><span className={`pill ${vm.state === "running" ? "good" : ""}`}>{vm.state}</span></dd>
            {vm.os && (<><dt>OS</dt><dd>{vm.os}</dd></>)}
            {vm.cpus ? (<><dt>Size</dt><dd>{vm.cpus} vCPU{vm.mem_bytes ? ` · ${bytes(vm.mem_bytes)}` : ""}</dd></>) : null}
            {vm.ips?.length ? (<><dt>Addresses</dt><dd className="mono small">{vm.ips.join(", ")}</dd></>) : null}
          </dl>
          <a className="link small" href="#/vms">Open in Virtual Machines</a>
        </>
      )}
      {vms && vms.length > 0 && (
        <>
          <h3 className="small">Virtual machines ({vms.length})</h3>
          <ul className="rel-vms">
            {shown.map((v) => (
              <li key={v.id}>
                <i className={`state-dot ${v.state === "running" ? "on" : ""}`} aria-hidden="true" />
                <span className="rel-vm-name">{v.name}{v.type === "lxc" && <span className="muted small"> CT</span>}</span>
                <span className="mono small muted">{v.ips?.[0] ?? v.state}</span>
              </li>
            ))}
          </ul>
          {vms.length > VM_LIST && (
            <button className="link small" onClick={() => setAllVMs(!allVMs)}>{allVMs ? "Show fewer" : `Show all ${vms.length}`}</button>
          )}
          <a className="link small" href="#/vms">Open in Virtual Machines</a>
        </>
      )}
      {storage && (
        <>
          <h3 className="small">Storage</h3>
          <dl className="kv">
            <dt>System</dt><dd>{[storage.vendor, storage.model].filter(Boolean).join(" ") || storage.target}</dd>
            <dt>Health</dt><dd><span className={`pill ${storage.health === "good" ? "good" : storage.health === "critical" ? "bad" : "warn"}`}>{storage.health}</span>
              {storage.alerts ? <span className="muted small"> {storage.alerts} alert{storage.alerts === 1 ? "" : "s"}</span> : null}</dd>
            {storage.total > 0 && (<><dt>Used</dt><dd>{bytes(storage.used)} of {bytes(storage.total)}</dd></>)}
            <dt>Holds</dt><dd>{storage.volumes} volume{storage.volumes === 1 ? "" : "s"}, {storage.shares} share{storage.shares === 1 ? "" : "s"}</dd>
          </dl>
          <a className="link small" href="#/storage">Open in Storage</a>
        </>
      )}
      {iot && (
        <>
          <h3 className="small">IoT inventory</h3>
          <dl className="kv">
            <dt>Type</dt><dd>{iot.type}</dd>
            {iot.location && (<><dt>Where</dt><dd>{iot.location}</dd></>)}
            {iot.owner && (<><dt>Owner</dt><dd>{iot.owner}</dd></>)}
          </dl>
          <a className="link small" href="#/iot">Open in IoT Devices</a>
        </>
      )}
      {dns && dns.length > 0 && (
        <>
          <h3 className="small">DNS names</h3>
          <ul className="rel-dns">
            {dns.map((d) => <li key={d.name + d.type}><span className="mono small">{d.name}</span> <span className="muted small">{d.type} · {d.server}</span></li>)}
          </ul>
        </>
      )}
      {connections && connections.length > 0 && (
        <>
          <h3 className="small">NCC connections at this address</h3>
          <ul className="rel-dns">
            {connections.map((c) => <li key={c.id}><a href="#/settings">{c.name}</a> <span className="muted small">{c.kind}</span></li>)}
          </ul>
        </>
      )}
    </section>
  );
}
