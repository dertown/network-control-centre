import { useEffect, useState } from "react";
import { api, Cert, Client, Device, Target } from "../api";
import { ago } from "../live";

export function Dashboard({ tick }: { tick: number }) {
  const [devices, setDevices] = useState<Device[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [certs, setCerts] = useState<Cert[]>([]);

  useEffect(() => {
    api<Device[]>("GET", "/api/devices").then(setDevices).catch(() => {});
    api<Client[]>("GET", "/api/clients").then(setClients).catch(() => {});
    api<Target[]>("GET", "/api/targets").then(setTargets).catch(() => {});
    api<Cert[]>("GET", "/api/certs").then(setCerts).catch(() => {});
  }, [tick]);

  const infra = devices.filter((d) => d.discovery === "controller");
  const offline = infra.filter((d) => !d.online);
  const switches = devices.filter((d) => d.kind === "switch" || d.kind === "unmanaged-switch");
  const aps = devices.filter((d) => d.kind === "ap");
  const certAlerts = certs.filter((c) => c.status !== "ok");

  return (
    <>
      <h1>Dashboard</h1>
      <div className="tiles">
        <Tile label="Devices online" value={`${infra.length - offline.length} / ${infra.length}`} tone={offline.length ? "warn" : "good"} href="#/devices" />
        <Tile label="Switches" value={switches.length} sub={`${switches.filter((s) => !s.managed).length} not managed by UniFi`} href="#/devices" />
        <Tile label="Access points" value={aps.length} href="#/devices" />
        <Tile label="Clients" value={clients.length} sub={`${clients.filter((c) => !c.wired).length} wireless`} href="#/topology" />
        <Tile label="Certificates needing attention" value={certAlerts.length} tone={certAlerts.length ? "warn" : "good"} href="#/vault" />
      </div>

      {offline.length > 0 && (
        <section className="card">
          <h2>Offline devices</h2>
          <ul className="plain">{offline.map((d) => <li key={d.id}>{d.name} <span className="muted">({d.model}, {d.ip || d.mac})</span></li>)}</ul>
        </section>
      )}

      <section className="card">
        <h2>Connections</h2>
        {targets.length === 0 ? (
          <p className="muted">Nothing connected yet. Add your Dream Router and PowerDNS server in <a href="#/settings">Settings</a>.</p>
        ) : (
          <table>
            <thead><tr><th>Name</th><th>Type</th><th>Address</th><th>Last poll</th><th>Status</th></tr></thead>
            <tbody>
              {targets.map((t) => (
                <tr key={t.id}>
                  <td>{t.name}</td>
                  <td>{t.kind}</td>
                  <td className="mono">{t.address}</td>
                  <td>{t.category === "device" ? ago(t.last_poll) : "on demand"}</td>
                  <td>{!t.enabled ? <span className="pill">disabled</span> : t.last_error ? <span className="pill bad" title={t.last_error}>error</span> : <span className="pill good">ok</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {certAlerts.length > 0 && (
        <section className="card">
          <h2>Certificates expiring soon</h2>
          <ul className="plain">{certAlerts.map((c) => <li key={c.id}>{c.name}: <span className={`pill ${c.status === "expiring" ? "warn" : "bad"}`}>{c.days_left < 0 ? "expired" : `${c.days_left} days left`}</span></li>)}</ul>
        </section>
      )}
    </>
  );
}

function Tile({ label, value, sub, tone, href }: { label: string; value: string | number; sub?: string; tone?: "good" | "warn"; href: string }) {
  return (
    <a className={`tile ${tone ?? ""}`} href={href}>
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="muted small">{sub}</div>}
    </a>
  );
}
