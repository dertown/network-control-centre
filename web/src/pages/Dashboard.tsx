// Dashboard: a one-screen overview of the whole network.
//
// Layout, top to bottom:
//   - a one-line verdict ("Everything is healthy" / "2 problems need attention"),
//   - one status tile per area (internet, devices, clients, VMs, storage, smart home,
//     certificates, exposed ports); optional areas only appear once they are set up,
//   - "Needs attention": every problem from every area in one list, worst first,
//   - device availability, top talkers and ports open to the internet.
//
// Connection health is not listed here (Settings has the full list); a connection NCC
// can't read shows up in "Needs attention" instead.
//
// Each fact is shown once: tiles summarise an area, the attention list names the problems,
// and the lower cards give the detail that no other panel shows. Data loading and the
// problem rules live in dashboardModel.ts.

import { useState } from "react";
import { kindLabel } from "../live";
import { Icon, kindIcon } from "../icons";
import { Meter, Sparkline } from "../charts";
import { bytes, rate } from "../format";
import { Tile, Tone } from "../ui";
import { Attention, buildAttention, DashData, internetState, openForwards, plural, useDashboardData } from "./dashboardModel";

/** Device kinds in the order they are listed: core of the network first. */
const kindOrder = ["gateway", "switch", "unmanaged-switch", "ap", "unknown"];
/** How many problems to show before "Show all". */
const attentionLimit = 6;

export function Dashboard({ tick }: { tick: number }) {
  const d = useDashboardData(tick);
  const attention = buildAttention(d);
  const critical = attention.filter((a) => a.level === "critical").length;
  const loaded = d.devices !== undefined || d.targets !== undefined;
  const empty = loaded && !d.devices?.length && !d.targets?.length;

  return (
    <>
      <h1>Dashboard</h1>
      <p className="muted lede">{verdict(d, attention.length, critical, empty)}</p>

      <AreaTiles d={d} attention={attention} />
      {!empty && <AttentionCard items={attention} loaded={loaded} />}

      <div className="grid-main">
        <div>
          <Availability d={d} />
        </div>
        <div>
          <TopTalkers d={d} />
          <ExposedPorts d={d} />
        </div>
      </div>
    </>
  );
}

/** verdict is the sentence under the title: the state of the network in plain words. */
function verdict(d: DashData, problems: number, critical: number, empty: boolean): string {
  if (!d.devices && !d.targets) return "Loading…";
  if (empty) return "Connect your router, DNS server and other systems in Settings to see them here.";
  const infra = (d.devices ?? []).filter((x) => x.discovery === "controller");
  const online = infra.filter((x) => x.online).length;
  const devices = `${online} of ${plural(infra.length, "network device")} online`;
  if (problems === 0) return `Everything is healthy. ${devices}, no alerts.`;
  if (critical) return `${plural(critical, "critical problem")}${problems > critical ? ` and ${plural(problems - critical, "warning")}` : ""} need attention. ${devices}.`;
  return `${plural(problems, "warning")} to look at, nothing critical. ${devices}.`;
}

// ---------------------------------------------------------------------------------------
// Area tiles: one per area, each with its own one-line summary. Tone follows the worst
// problem in that area from the attention list, so tiles and list always agree.

function AreaTiles({ d, attention }: { d: DashData; attention: Attention[] }) {
  const toneFor = (area: string, ok: boolean): Tone | undefined => {
    const own = attention.filter((a) => a.area === area);
    if (own.some((a) => a.level === "critical")) return "bad";
    if (own.length) return "warn";
    return ok ? "good" : undefined;
  };

  const net = internetState(d.devices);
  const down = d.hist.down.at(-1) ?? 0;
  const up = d.hist.up.at(-1) ?? 0;

  const infra = (d.devices ?? []).filter((x) => x.discovery === "controller");
  const offline = infra.filter((x) => !x.online);
  const passive = (d.devices ?? []).length - infra.length;

  const clients = d.clients ?? [];
  const wireless = clients.filter((c) => !c.wired).length;

  const vms = (d.vms?.vms ?? []).filter((v) => !v.template);
  const running = vms.filter((v) => v.state === "running").length;
  const hosts = d.vms?.hosts ?? [];

  const storage = (d.storage ?? []).flatMap((s) => s.inventory?.volumes ?? []);
  const stUsed = storage.reduce((s, v) => s + v.used, 0);
  const stTotal = storage.reduce((s, v) => s + v.total, 0);

  const smartDevices = (d.smart ?? []).flatMap((s) => s.inventory?.devices ?? []);
  const smartOnline = smartDevices.filter((x) => x.online).length;

  const certs = [...(d.certs ?? [])].sort((a, b) => a.days_left - b.days_left);
  const next = certs[0];

  const forwards = openForwards(d.firewall);

  return (
    <div className="tiles dash-tiles">
      <Tile label="Internet" icon="internet" href="#/traffic"
        tone={net.state === "down" ? "bad" : net.state === "up" ? "good" : undefined}
        value={net.state === "up" ? "Online" : net.state === "down" ? "Down" : "Unknown"}
        sub={<><Icon name="download" size={12} /> {rate(down)} · <Icon name="upload" size={12} /> {rate(up)}</>}>
        <Sparkline values={d.hist.down} color="var(--c3)" />
      </Tile>

      <Tile label="Network devices" icon="devices" href="#/devices" tone={toneFor("Devices", infra.length > 0)}
        value={<>{infra.length - offline.length}<small> / {infra.length} online</small></>}
        sub={offline.length ? `Offline: ${offline.map((x) => x.name).join(", ")}` : passive ? `+${passive} unmanaged (found by LLDP)` : "managed by your controller"} />

      <Tile label="Clients" icon="client" iconTone="c2" href="#/traffic" value={clients.length}
        sub={`${clients.length - wireless} wired · ${wireless} wireless`}>
        <Sparkline values={d.hist.clients} color="var(--c2)" />
      </Tile>

      {hosts.length > 0 && (
        <Tile label="Virtual machines" icon="vm" href="#/vms" tone={toneFor("Virtual machines", true)}
          value={<>{running}<small> / {vms.length} running</small></>}
          sub={`on ${plural(hosts.length, "host")}${hosts.some((h) => !h.online) ? `, ${hosts.filter((h) => !h.online).length} offline` : ""}`} />
      )}

      {stTotal > 0 && (
        <Tile label="Storage" icon="nas" href="#/storage" tone={toneFor("Storage", true)}
          value={<>{Math.round((stUsed / stTotal) * 100)}%<small> used</small></>}
          sub={`${bytes(stTotal - stUsed)} free of ${bytes(stTotal)}`}>
          <Meter value={stUsed / stTotal} tone={stUsed / stTotal > 0.9 ? "bad" : stUsed / stTotal > 0.8 ? "warn" : undefined} />
        </Tile>
      )}

      {smartDevices.length > 0 && (
        <Tile label="Smart home" icon="home" href="#/iot" tone={toneFor("Smart home", true)}
          value={<>{smartOnline}<small> / {smartDevices.length} online</small></>}
          sub={attention.some((a) => a.area === "Smart home") ? plural(attention.filter((a) => a.area === "Smart home").length, "alert") : "no alerts"} />
      )}

      {next && (
        <Tile label="Certificates" icon="cert" href="#/vault" tone={toneFor("Vault", true)}
          value={next.days_left < 0 ? "Expired" : <>{next.days_left}<small> days left</small></>}
          sub={`${next.name} is next to expire`} />
      )}

      {d.firewall && d.firewall.length > 0 && (
        <Tile label="Open to the internet" icon="firewall" href="#/firewall" tone={forwards.length ? undefined : "good"}
          value={<>{forwards.length}<small> port forward{forwards.length === 1 ? "" : "s"}</small></>}
          sub={forwards.length ? "listed below" : "nothing exposed"} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------
// Needs attention

function AttentionCard({ items, loaded }: { items: Attention[]; loaded: boolean }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, attentionLimit);
  const critical = items.filter((a) => a.level === "critical").length;
  return (
    <section className="card attn-card">
      <div className="card-head">
        <h2><Icon name="alert" size={16} /> Needs attention</h2>
        {items.length > 0 && (
          <span>
            {critical > 0 && <span className="pill bad">{critical} critical</span>}{" "}
            {items.length > critical && <span className="pill warn">{items.length - critical} warning{items.length - critical === 1 ? "" : "s"}</span>}
          </span>
        )}
      </div>
      {!loaded ? <p className="muted">Checking…</p> : items.length === 0 ? (
        <div className="empty"><Icon name="check" size={28} />All clear. No outages, loops, failing disks, expiring certificates or connection errors.</div>
      ) : (
        <>
          <ul className="list attn">
            {shown.map((a) => {
              const tone = a.level === "critical" ? "bad" : "warn";
              return (
                <li key={a.key} className={tone}>
                  <span className={`tile-icon ${tone}`}><Icon name={a.icon} size={16} /></span>
                  <div className="grow-col">
                    <strong className="attn-title">{a.title}</strong>
                    {a.detail && <div className="muted small attn-detail">{a.detail}</div>}
                  </div>
                  <a className="small" href={a.href}>{a.area} →</a>
                </li>
              );
            })}
          </ul>
          {items.length > attentionLimit && (
            <button className="small attn-more" onClick={() => setAll(!all)}>
              {all ? "Show fewer" : `Show all ${items.length}`}
            </button>
          )}
        </>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------------------
// Detail cards

/** Availability: every network device as a chip, red when offline, dashed when not polled. */
function Availability({ d }: { d: DashData }) {
  const devices = [...(d.devices ?? [])].sort((a, b) => kindOrder.indexOf(a.kind) - kindOrder.indexOf(b.kind) || a.name.localeCompare(b.name));
  return (
    <section className="card">
      <div className="card-head">
        <h2><Icon name="topology" size={16} /> Network devices</h2>
        <a href="#/topology">Open map →</a>
      </div>
      {devices.length === 0 ? (
        <p className="muted">No devices yet. Add your UniFi console in <a href="#/settings">Settings</a>.</p>
      ) : (
        <div className="avail">
          {devices.map((x) => {
            const polled = x.discovery === "controller";
            const state = !polled ? "not polled" : x.online ? "online" : "offline";
            return (
              <a key={x.id} href="#/devices" className={!polled ? "passive" : x.online ? "" : "down"}
                title={`${x.name} · ${kindLabel[x.kind] ?? x.kind} · ${state}`} aria-label={`${x.name}, ${state}`}>
                <Icon name={kindIcon[x.kind] ?? "unknown"} size={18} />
                <span style={{ minWidth: 0 }}><div className="nm">{x.name}</div><div className="md">{x.model || kindLabel[x.kind]}</div></span>
              </a>
            );
          })}
        </div>
      )}
      {devices.length > 0 && (
        <p className="muted small avail-key">
          <span className="dot good" />online <span className="dot bad" />offline <span className="dot" />unmanaged (seen by LLDP or inferred)
        </p>
      )}
    </section>
  );
}

/** TopTalkers: the clients that moved the most data this session. */
function TopTalkers({ d }: { d: DashData }) {
  const talkers = (d.traffic?.clients ?? [])
    .map((c) => ({ ...c, total: c.window_down + c.window_up }))
    .filter((c) => c.total > 0)
    .sort((a, b) => b.total - a.total)
    .slice(0, 5);
  const max = talkers[0]?.total || 1;
  return (
    <section className="card">
      <div className="card-head">
        <h2><Icon name="traffic" size={16} /> Top talkers</h2>
        <a href="#/traffic">Traffic →</a>
      </div>
      {talkers.length === 0 ? <p className="muted">No traffic data yet.</p> : (
        <ul className="list">
          {talkers.map((c) => (
            <li key={c.mac}>
              <span className="tile-icon" style={{ width: 28, height: 28 }}><Icon name={c.wired ? "client" : "wifi"} size={15} /></span>
              <div className="grow-col">
                <div className="row-between">
                  <strong className="small ellipsis">{c.name}</strong>
                  <span className="small muted">{bytes(c.total)}</span>
                </div>
                <Meter value={c.total / max} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** ExposedPorts: what the router forwards from the internet to the inside. */
function ExposedPorts({ d }: { d: DashData }) {
  const forwards = openForwards(d.firewall);
  if (!forwards.length) return null;
  const limit = 6;
  return (
    <section className="card">
      <div className="card-head">
        <h2><Icon name="firewall" size={16} /> Open to the internet</h2>
        <a href="#/firewall">Firewall →</a>
      </div>
      <ul className="list">
        {forwards.slice(0, limit).map((f) => {
          const anyone = !f.source || f.source.toLowerCase() === "any";
          return (
            <li key={`${f.target}-${f.id}`}>
              <div className="grow-col">
                <div className="row-between">
                  <strong className="small ellipsis">{f.name}</strong>
                  <span className="mono small">{f.protocol.toUpperCase()} {f.external_port}</span>
                </div>
                <div className="muted small">
                  to <span className="mono">{f.forward_client || f.forward_ip}:{f.forward_port}</span> · {anyone ? "from anyone" : `from ${f.source}`}
                </div>
              </div>
            </li>
          );
        })}
      </ul>
      {forwards.length > limit && <p className="muted small">and {forwards.length - limit} more on the Firewall page.</p>}
    </section>
  );
}
