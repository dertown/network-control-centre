// Devices page: every gateway, switch and access point found, with make, model, firmware and ports.
import { Fragment, useEffect, useMemo, useState } from "react";
import { api, Device } from "../api";
import { discoveryLabel, kindLabel } from "../live";
import { uptime } from "../format";
import { Icon, kindIcon } from "../icons";

export function Devices({ tick }: { tick: number }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    api<Device[]>("GET", "/api/devices").then(setDevices).catch(() => {});
  }, [tick]);

  const shown = useMemo(() => {
    const s = q.toLowerCase();
    const order = ["gateway", "switch", "unmanaged-switch", "ap", "unknown"];
    const rank = (k: string) => (order.indexOf(k) + 1 || 99);
    return [...devices].sort((a, b) => rank(a.kind) - rank(b.kind) || a.name.localeCompare(b.name)).filter(
      (d) =>
        (!kind || d.kind === kind) &&
        (!s || [d.name, d.make, d.model, d.model_code, d.ip, d.mac].some((v) => v?.toLowerCase().includes(s))),
    );
  }, [devices, q, kind]);

  return (
    <>
      <h1>Devices</h1>
      <p className="muted">
        Make and model come from three places: devices adopted by your UniFi console report their own model; other switches
        that speak LLDP are identified from their LLDP description; and a UniFi port with several wired clients on it is shown
        as an unmanaged switch.
      </p>
      <div className="toolbar">
        <input placeholder="Search name, model, IP or MAC" value={q} onChange={(e) => setQ(e.target.value)} />
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All kinds</option>
          {Object.entries(kindLabel).filter(([k]) => k !== "client").map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <span className="muted">{shown.length} of {devices.length}</span>
      </div>
      <div className="card flush">
        <table>
          <thead>
            <tr><th>Name</th><th>Kind</th><th>Make</th><th>Model</th><th>IP</th><th>Firmware</th><th>Clients</th><th>How found</th><th>Status</th></tr>
          </thead>
          <tbody>
            {shown.map((d) => (
              <Fragment key={d.id}>
                <tr className="clickable" onClick={() => setOpen(open === d.id ? null : d.id)}>
                  <td><span className="devname"><span className={`kind-chip k-${d.kind}`}><Icon name={kindIcon[d.kind] ?? "unknown"} size={16} /></span><strong>{d.name}</strong></span></td>
                  <td>{kindLabel[d.kind] ?? d.kind}</td>
                  <td>{d.make}</td>
                  <td title={d.detail}>{d.model}{d.model_code && d.model_code !== d.model && <span className="muted small"> {d.model_code}</span>}</td>
                  <td className="mono">{d.ip}</td>
                  <td className="mono">{d.firmware}</td>
                  <td>{d.clients || ""}</td>
                  <td className="small">{discoveryLabel[d.discovery] ?? d.discovery}</td>
                  <td>{d.online ? <span className="pill good">online</span> : <span className="pill bad">offline</span>}</td>
                </tr>
                {open === d.id && (
                  <tr className="detail">
                    <td colSpan={9}>
                      <dl className="kv">
                        <dt>MAC</dt><dd className="mono">{d.mac || "—"}</dd>
                        {d.serial && (<><dt>Serial</dt><dd className="mono">{d.serial}</dd></>)}
                        {d.uptime_s ? (<><dt>Uptime</dt><dd>{uptime(d.uptime_s)}</dd></>) : null}
                        <dt>Source</dt><dd>{d.target}</dd>
                        {d.detail && (<><dt>Detail</dt><dd>{d.detail}</dd></>)}
                      </dl>
                      {d.ports && d.ports.length > 0 && (
                        <div className="ports">
                          {d.ports.map((p) => (
                            <div key={p.index} className={`port ${p.up ? "up" : "down"} ${p.uplink ? "uplink" : ""}`} title={`${p.name}${p.speed_mbps ? ` · ${p.speed_mbps} Mbps` : ""}${p.poe_watts ? ` · PoE ${p.poe_watts} W` : ""}`}>
                              <span>{p.index}</span>
                              <small>{p.up ? (p.speed_mbps ? (p.speed_mbps >= 1000 ? `${p.speed_mbps / 1000}G` : `${p.speed_mbps}M`) : "up") : "—"}</small>
                            </div>
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
            {shown.length === 0 && <tr><td colSpan={9} className="muted">No devices yet. Add your UniFi console in Settings.</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}
