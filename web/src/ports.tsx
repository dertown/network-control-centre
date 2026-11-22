// Port faceplate with click-through: pick a port to see the clients and network devices on it.
import { useEffect, useState } from "react";
import { api, DevicePorts, PortClient, PortView } from "./api";
import { kindLabel } from "./live";

function speedShort(mbps?: number) {
  if (!mbps) return "up";
  return mbps >= 1000 ? `${mbps / 1000}G` : `${mbps}M`;
}

function speedLong(mbps?: number) {
  if (!mbps) return "";
  return mbps >= 1000 ? `${mbps / 1000} Gbps` : `${mbps} Mbps`;
}

function portLabel(p: PortView) {
  return p.name || `Port ${p.index}`;
}

function ClientRows({ clients, swatch }: { clients: PortClient[]; swatch?: (networkID?: string) => string | undefined }) {
  return (
    <ul className="port-clients">
      {clients.map((c) => {
        const colour = swatch?.(c.network_id);
        return (
          <li key={c.mac}>
            <div className="pc-name">
              <strong>{c.name}</strong>
              {(c.network || c.vlan) ? (
                <span className="pc-net">
                  {colour && <i className="vlan-swatch" style={{ background: colour }} />}
                  {c.network}{c.vlan ? <span className="muted"> VLAN {c.vlan}</span> : null}
                </span>
              ) : null}
            </div>
            <div className="pc-meta mono">
              {c.ip && <span>{c.ip}</span>}
              <span className="muted">{c.mac}</span>
            </div>
            {(c.vendor || c.ssid || c.behind) && (
              <div className="pc-meta muted">
                {[c.vendor, c.ssid && `Wi-Fi ${c.ssid}`, c.behind && `via ${c.behind}`].filter(Boolean).join(" · ")}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

/** The ports of device `id`. Clicking a port lists what is plugged into it. */
export function PortsPanel({ id, tick, swatch, onPick }: {
  id: string; tick: number;
  /** Colour for a network id, to match the topology map's VLAN colours. */
  swatch?: (networkID?: string) => string | undefined;
  /** Called when a connected network device is clicked (e.g. to select it on the map). */
  onPick?: (deviceID: string) => void;
}) {
  const [data, setData] = useState<DevicePorts | null>(null);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState<number | null>(null);

  useEffect(() => { setOpen(null); setData(null); setErr(""); }, [id]);
  useEffect(() => {
    let live = true;
    api<DevicePorts>("GET", `/api/devices/${encodeURIComponent(id)}/ports`)
      .then((d) => { if (live) { setData(d); setErr(""); } })
      .catch((e) => { if (live) setErr(e instanceof Error ? e.message : String(e)); });
    return () => { live = false; };
  }, [id, tick]);

  if (err && !data) return <p className="muted small">Couldn't load the ports: {err}</p>;
  if (!data) return null;
  const port = data.ports.find((p) => p.index === open) ?? null;
  const attachedTitle = data.kind === "ap" ? "Wireless clients" : "Clients";

  return (
    <div className="port-panel">
      {data.ports.length > 0 && (
        <>
          <div className="ports" role="group" aria-label="Ports">
            {data.ports.map((p) => {
              const n = p.clients.length || p.devices.length;
              return (
                <button key={p.index} type="button"
                  className={`port ${p.up ? "up" : "down"} ${p.uplink ? "uplink" : ""}${open === p.index ? " on" : ""}`}
                  aria-pressed={open === p.index}
                  title={`${portLabel(p)}${p.speed_mbps ? ` · ${speedLong(p.speed_mbps)}` : ""}${p.poe_watts ? ` · PoE ${p.poe_watts} W` : ""}${p.clients.length ? ` · ${p.clients.length} client${p.clients.length === 1 ? "" : "s"}` : ""}${p.devices.length ? ` · ${p.devices.map((d) => d.name).join(", ")}` : ""}`}
                  onClick={() => setOpen(open === p.index ? null : p.index)}>
                  <span>{p.index}</span>
                  <small>{p.up ? speedShort(p.speed_mbps) : "—"}</small>
                  {n > 0 && <b className="port-count">{n}</b>}
                </button>
              );
            })}
          </div>
          {!port && <p className="muted small port-hint">Click a port to see what's plugged into it.</p>}
        </>
      )}
      {port && (
        <section className="port-detail" aria-live="polite">
          <div className="port-detail-head">
            <strong>{portLabel(port)}</strong>
            {port.up ? <span className="pill good">up{port.speed_mbps ? ` · ${speedLong(port.speed_mbps)}` : ""}</span> : <span className="pill">down</span>}
            {port.uplink && <span className="pill">uplink</span>}
            {port.poe_watts ? <span className="pill">PoE {port.poe_watts} W</span> : null}
            {port.stp && port.stp !== "forwarding" && <span className="pill warn">STP {port.stp}</span>}
            <button className="link" onClick={() => setOpen(null)} aria-label="Close port">Close</button>
          </div>
          {port.profile && <p className="muted small">Port profile: {port.profile}</p>}
          {port.devices.length > 0 && (
            <>
              <h4>Network device{port.devices.length === 1 ? "" : "s"}</h4>
              <ul className="port-clients">
                {port.devices.map((d) => (
                  <li key={d.id}>
                    <div className="pc-name">
                      {onPick ? <button className="link" onClick={() => onPick(d.id)}><strong>{d.name}</strong></button> : <strong>{d.name}</strong>}
                      <span className={`pill ${d.online ? "good" : "bad"}`}>{d.online ? "online" : "offline"}</span>
                    </div>
                    <div className="pc-meta muted">
                      {[kindLabel[d.kind] ?? d.kind, d.port && `its ${d.port}`, d.clients ? `${d.clients} client${d.clients === 1 ? "" : "s"}` : ""].filter(Boolean).join(" · ")}
                    </div>
                  </li>
                ))}
              </ul>
            </>
          )}
          {port.clients.length > 0 && (
            <>
              <h4>{port.clients.length} client{port.clients.length === 1 ? "" : "s"}</h4>
              <ClientRows clients={port.clients} swatch={swatch} />
            </>
          )}
          {port.clients.length === 0 && port.devices.length === 0 && (
            <p className="muted small">{port.up ? "The link is up, but no clients were seen on this port." : "Nothing is plugged in."}</p>
          )}
        </section>
      )}
      {data.attached.length > 0 && (
        <section className="port-detail">
          <h4>{data.attached.length} {attachedTitle.toLowerCase()}</h4>
          <ClientRows clients={data.attached} swatch={swatch} />
        </section>
      )}
    </div>
  );
}
