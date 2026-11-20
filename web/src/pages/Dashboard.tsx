import { useEffect, useState } from "react";
import { api, Cert, Client, Device, Target, TrafficView } from "../api";
import { ago, kindLabel } from "../live";
import { Icon, IconName, kindIcon } from "../icons";
import { Donut, Meter, Sparkline } from "../charts";
import { record, recent } from "../history";
import { bytes, rate } from "./Traffic";

export function Dashboard({ tick }: { tick: number }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [certs, setCerts] = useState<Cert[]>([]);
  const [traffic, setTraffic] = useState<TrafficView | null>(null);
  const [hist, setHist] = useState({ clients: recent("clients"), down: recent("down"), up: recent("up") });

  useEffect(() => {
    api<Device[]>("GET", "/api/devices").then(setDevices).catch(() => {});
    api<Client[]>("GET", "/api/clients").then((c) => {
      setClients(c);
      setHist((h) => ({ ...h, clients: record("clients", c.length) }));
    }).catch(() => {});
    api<Target[]>("GET", "/api/targets").then(setTargets).catch(() => {});
    api<Cert[]>("GET", "/api/certs").then(setCerts).catch(() => {});
    api<TrafficView>("GET", "/api/traffic?window=session").then((t) => {
      setTraffic(t);
      const online = t.clients.filter((c) => c.online);
      setHist((h) => ({
        ...h,
        down: record("down", online.reduce((s, c) => s + c.down_rate, 0)),
        up: record("up", online.reduce((s, c) => s + c.up_rate, 0)),
      }));
    }).catch(() => {});
  }, [tick]);

  const infra = devices.filter((d) => d.discovery === "controller");
  const offline = infra.filter((d) => !d.online);
  const passive = devices.filter((d) => d.discovery !== "controller");
  const certAlerts = certs.filter((c) => c.status !== "ok");
  const wireless = clients.filter((c) => !c.wired).length;
  const badTargets = targets.filter((t) => t.enabled && t.last_error);
  const liveDown = hist.down.at(-1) ?? 0;
  const liveUp = hist.up.at(-1) ?? 0;

  const kinds = ["gateway", "switch", "unmanaged-switch", "ap", "unknown"];
  const kindColors = ["var(--c1)", "var(--c2)", "var(--c6)", "var(--c3)", "var(--c4)"];
  const mix = kinds.map((k, i) => ({ label: kindLabel[k], value: devices.filter((d) => d.kind === k).length, color: kindColors[i] })).filter((s) => s.value > 0);

  const talkers = [...(traffic?.clients ?? [])]
    .sort((a, b) => b.window_down + b.window_up - (a.window_down + a.window_up))
    .filter((c) => c.window_down + c.window_up > 0)
    .slice(0, 6);
  const talkMax = talkers[0] ? talkers[0].window_down + talkers[0].window_up : 1;

  const health = offline.length ? "warn" : "good";

  return (
    <>
      <h1>Dashboard</h1>
      <p className="muted lede">
        {devices.length === 0
          ? "Connect your network to see it here."
          : offline.length
            ? `${offline.length} of ${infra.length} managed devices are offline. Everything else is reporting normally.`
            : `All ${infra.length} managed devices are online and reporting.`}
      </p>

      <div className="tiles">
        <Tile label="Devices online" icon="devices" tone={health} href="#/devices"
          value={<>{infra.length - offline.length}<small> / {infra.length}</small></>}
          sub={passive.length ? `+${passive.length} found by LLDP or inference` : "managed by your controller"} />
        <Tile label="Clients" icon="client" iconTone="c2" href="#/traffic" value={clients.length}
          sub={`${clients.length - wireless} wired · ${wireless} wireless`}
          spark={<Sparkline values={hist.clients} color="var(--c2)" />} />
        <Tile label="Internet, now" icon="traffic" iconTone="c3" href="#/traffic" value={rate(liveDown)} valueClass="small-value"
          sub={<><Icon name="download" size={12} /> down · <Icon name="upload" size={12} /> {rate(liveUp)} up</>}
          spark={<Sparkline values={hist.down} color="var(--c3)" />} />
        <Tile label="Certificates" icon="cert" tone={certAlerts.length ? "warn" : "good"} href="#/vault"
          value={certs.length} sub={certAlerts.length ? `${certAlerts.length} need attention` : "none expiring soon"} />
        <Tile label="Integrations" icon="link" tone={badTargets.length ? "bad" : targets.length ? "good" : undefined} href="#/settings"
          value={<>{targets.length - badTargets.length}<small> / {targets.length}</small></>}
          sub={badTargets.length ? `${badTargets.length} failing` : "all healthy"} />
      </div>

      <div className="grid-3">
        <section className="card">
          <h2><Icon name="check" size={16} /> Device health</h2>
          <Donut center={infra.length ? `${Math.round(((infra.length - offline.length) / infra.length) * 100)}%` : "–"} sub="online"
            segments={[
              { label: "Online", value: infra.length - offline.length, color: "var(--good)" },
              { label: "Offline", value: offline.length, color: "var(--bad)" },
              { label: "Passive (not polled)", value: passive.length, color: "var(--c6)" },
            ]} />
        </section>
        <section className="card">
          <h2><Icon name="devices" size={16} /> Device mix</h2>
          <Donut center={devices.length} sub="devices" segments={mix} />
        </section>
        <section className="card">
          <h2><Icon name="client" size={16} /> Clients by connection</h2>
          <Donut center={clients.length} sub="clients" segments={[
            { label: "Wired", value: clients.length - wireless, color: "var(--c1)" },
            { label: "Wireless", value: wireless, color: "var(--c2)" },
          ]} />
        </section>
      </div>

      <div className="grid-main">
        <div>
          <section className="card">
            <div className="card-head">
              <h2><Icon name="topology" size={16} /> Availability</h2>
              <a href="#/topology">Open map →</a>
            </div>
            {devices.length === 0 ? (
              <p className="muted">No devices yet. Add your UniFi console in <a href="#/settings">Settings</a>.</p>
            ) : (
              <div className="avail">
                {[...devices].sort((a, b) => kinds.indexOf(a.kind) - kinds.indexOf(b.kind) || a.name.localeCompare(b.name)).map((d) => (
                  <a key={d.id} href="#/devices" className={d.discovery !== "controller" ? "passive" : d.online ? "" : "down"}
                    title={`${d.name} · ${kindLabel[d.kind] ?? d.kind} · ${d.discovery !== "controller" ? "not polled" : d.online ? "online" : "offline"}`}>
                    <Icon name={kindIcon[d.kind] ?? "unknown"} size={18} />
                    <span style={{ minWidth: 0 }}><div className="nm">{d.name}</div><div className="md">{d.model || kindLabel[d.kind]}</div></span>
                  </a>
                ))}
              </div>
            )}
          </section>

          <section className="card flush">
            <div className="card-head" style={{ padding: "16px 20px 0" }}>
              <h2><Icon name="link" size={16} /> Connections</h2>
              <a href="#/settings">Manage →</a>
            </div>
            {targets.length === 0 ? (
              <p className="muted" style={{ padding: "0 20px 16px" }}>Nothing connected yet. Add your Dream Router and PowerDNS server in <a href="#/settings">Settings</a>.</p>
            ) : (
              <table>
                <thead><tr><th>Name</th><th>Type</th><th>Address</th><th>Last poll</th><th>Status</th></tr></thead>
                <tbody>
                  {targets.map((t) => (
                    <tr key={t.id}>
                      <td><strong>{t.name}</strong></td>
                      <td><span className="pill">{t.kind}</span></td>
                      <td className="mono">{t.address}</td>
                      <td className="muted">{ago(t.last_poll)}</td>
                      <td>{!t.enabled ? <span className="pill">disabled</span> : t.last_error ? <span className="pill bad" title={t.last_error}>error</span> : !t.last_poll ? <span className="pill">not checked</span> : <span className="pill good">healthy</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </div>

        <div>
          <section className="card">
            <div className="card-head">
              <h2><Icon name="traffic" size={16} /> Top talkers</h2>
              <a href="#/traffic">Traffic →</a>
            </div>
            {talkers.length === 0 ? <p className="muted">No traffic data yet.</p> : (
              <ul className="list">
                {talkers.map((c) => (
                  <li key={c.mac}>
                    <span className="tile-icon" style={{ width: 28, height: 28 }}><Icon name={c.wired ? "client" : "ap"} size={15} /></span>
                    <div className="grow-col">
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                        <strong className="small" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{c.name}</strong>
                        <span className="small muted">{bytes(c.window_down + c.window_up)}</span>
                      </div>
                      <Meter value={(c.window_down + c.window_up) / talkMax} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <div className="card-head">
              <h2><Icon name="cert" size={16} /> Certificates</h2>
              <a href="#/vault">Vault →</a>
            </div>
            {certs.length === 0 ? <p className="muted">No certificates imported.</p> : certAlerts.length === 0 ? (
              <div className="empty"><Icon name="check" size={28} />All {certs.length} certificates are valid for more than 30 days.</div>
            ) : (
              <ul className="list">
                {[...certs].sort((a, b) => a.days_left - b.days_left).slice(0, 6).map((c) => {
                  const tone = c.status === "ok" ? "good" : c.status === "expiring" ? "warn" : "bad";
                  return (
                    <li key={c.id}>
                      <div className="grow-col">
                        <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                          <span className="small" style={{ fontWeight: 550 }}>{c.name}</span>
                          <span className={`pill ${tone}`}>{c.days_left < 0 ? "expired" : `${c.days_left} days`}</span>
                        </div>
                        <Meter value={Math.max(c.days_left, 0) / 90} tone={tone} />
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          {offline.length > 0 && (
            <section className="card">
              <h2><Icon name="alert" size={16} /> Offline devices</h2>
              <ul className="list">
                {offline.map((d) => (
                  <li key={d.id}><span className="dot bad" /><span className="grow-col">{d.name} <span className="muted small">{d.model}</span></span><span className="mono small muted">{d.ip || d.mac}</span></li>
                ))}
              </ul>
            </section>
          )}
        </div>
      </div>
    </>
  );
}

function Tile({ label, value, sub, tone, icon, iconTone, href, spark, valueClass }: {
  label: string; value: React.ReactNode; sub?: React.ReactNode; tone?: "good" | "warn" | "bad"; icon: IconName;
  iconTone?: string; href: string; spark?: React.ReactNode; valueClass?: string;
}) {
  return (
    <a className={`tile ${tone ?? ""}`} href={href}>
      <div className="tile-top">
        <span className="tile-label">{label}</span>
        <span className={`tile-icon ${iconTone ?? tone ?? ""}`}><Icon name={icon} size={17} /></span>
      </div>
      <div className={`tile-value ${valueClass ?? ""}`}>{value}</div>
      {sub && <div className="muted small">{sub}</div>}
      {spark}
    </a>
  );
}
