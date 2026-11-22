// Firewall page (read-only): the router's firewall policies or legacy rule sets and its port
// forwards, with zones, groups and clients named.
import { Fragment, useEffect, useMemo, useState } from "react";
import { api, Firewall as FirewallData, FirewallEndpoint, FirewallRule, PortForward } from "../api";
import { Icon } from "../icons";
import { Tile } from "../ui";

const actionTone: Record<string, string> = { allow: "good", block: "bad", reject: "warn" };

function Endpoint({ e, zones }: { e: FirewallEndpoint; zones: boolean }) {
  return (
    <span className="fw-ep">
      {zones && e.zone && <span className="pill">{e.zone}</span>}
      <span>{e.negate && <span className="muted">not </span>}{e.match}</span>
      {e.port && <span className="muted small mono">port {e.port}</span>}
    </span>
  );
}

function matches(q: string, ...vals: (string | undefined)[]) {
  return !q || vals.some((v) => v?.toLowerCase().includes(q));
}

export function Firewall({ tick }: { tick: number }) {
  const [data, setData] = useState<FirewallData[] | null>(null);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const [enabledOnly, setEnabledOnly] = useState(true);
  const [builtin, setBuiltin] = useState(false);
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    api<FirewallData[]>("GET", "/api/firewall").then((d) => { setData(d); setErr(""); }).catch((e) => setErr((e as Error).message));
  }, [tick]);

  const all = data ?? [];
  const many = all.length > 1;
  const zones = all.some((f) => f.mode === "zones");
  const rules = all.flatMap((f) => f.rules);
  const forwards = all.flatMap((f) => f.forwards);
  const s = q.trim().toLowerCase();

  const shownRules = useMemo(() => rules.filter((r) =>
    (!enabledOnly || r.enabled) && (builtin || !r.builtin) &&
    matches(s, r.name, r.description, r.ruleset, r.protocol, r.action, r.source.zone, r.source.match, r.source.port,
      r.destination.zone, r.destination.match, r.destination.port)), [rules, enabledOnly, builtin, s]);
  const shownForwards = useMemo(() => forwards.filter((f) =>
    (!enabledOnly || f.enabled) &&
    matches(s, f.name, f.external_port, f.forward_ip, f.forward_port, f.forward_client, f.source, f.protocol)), [forwards, enabledOnly, s]);

  const custom = rules.filter((r) => !r.builtin);
  const builtinCount = rules.length - custom.length;
  const blocking = custom.filter((r) => r.enabled && r.action !== "allow").length;
  const fwdOn = forwards.filter((f) => f.enabled).length;

  if (data && all.length === 0) {
    return (
      <>
        <h1>Firewall</h1>
        <div className="banner warn">No firewall data yet. Add your UniFi console in <a href="#/settings">Settings</a>; rules appear after the next poll.</div>
      </>
    );
  }

  return (
    <>
      <h1>Firewall</h1>
      <p className="muted">
        The firewall rules and port forwards your router has, read from it on every poll. This page is read-only: change rules
        in UniFi Network under Settings › Security{zones ? " › Firewall policies" : ""} and Settings › Routing › Port forwarding.
      </p>
      {err && <div className="banner bad" role="alert">Could not load firewall rules: {err}</div>}
      {all.flatMap((f) => (f.notes ?? []).map((n) => (
        <div key={f.target + n} className="banner warn"><Icon name="alert" size={16} />{many ? `${f.target}: ` : ""}{n}</div>
      )))}

      <div className="tiles">
        <Tile label="Your rules enabled" icon="firewall" value={<>{custom.filter((r) => r.enabled).length}<small> / {custom.length}</small></>}
          sub={builtinCount ? `plus ${builtinCount} built-in` : zones ? "zone-based firewall" : "rule sets"} />
        <Tile label="Blocking rules on" icon="alert" tone={blocking ? "bad" : undefined} value={blocking}
          sub="block or reject" />
        <Tile label="Port forwards on" icon="internet" tone={fwdOn ? "warn" : "good"} value={<>{fwdOn}<small> / {forwards.length}</small></>}
          sub={fwdOn ? "open to the internet" : "nothing open from outside"} />
      </div>

      <div className="toolbar">
        <input placeholder="Search name, address, port or network" value={q} onChange={(e) => setQ(e.target.value)} />
        <label className="check"><input type="checkbox" checked={enabledOnly} onChange={(e) => setEnabledOnly(e.target.checked)} /> Enabled only</label>
        {builtinCount > 0 && (
          <label className="check"><input type="checkbox" checked={builtin} onChange={(e) => setBuiltin(e.target.checked)} /> Show built-in rules</label>
        )}
      </div>

      <div className="card flush">
        <div className="card-head fw-head">
          <h2>Firewall rules</h2>
          <span className="muted small">{shownRules.length} of {rules.length}{zones ? " · zone-based firewall" : ""}</span>
        </div>
        <table className="fw-table">
          <thead>
            <tr>
              {many && <th>Router</th>}
              <th>Name</th><th>Action</th>{!zones && <th>Rule set</th>}<th>Source</th><th>Destination</th><th>Protocol</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            {shownRules.map((r) => <RuleRow key={r.target + r.id} r={r} many={many} zones={zones} open={open === r.target + r.id}
              onToggle={() => setOpen(open === r.target + r.id ? null : r.target + r.id)} />)}
            {shownRules.length === 0 && (
              <tr><td colSpan={8} className="muted">
                {rules.length === 0 ? "The router reported no firewall rules." : "No rules match. Clear the search or untick Enabled only."}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card flush">
        <div className="card-head fw-head">
          <h2>Port forwarding</h2>
          <span className="muted small">{shownForwards.length} of {forwards.length}</span>
        </div>
        <table className="fw-table">
          <thead>
            <tr>
              {many && <th>Router</th>}
              <th>Name</th><th>WAN</th><th>Protocol</th><th>External port</th><th>Forward to</th><th>Allowed from</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            {shownForwards.map((f) => <ForwardRow key={f.target + f.id} f={f} many={many} />)}
            {shownForwards.length === 0 && (
              <tr><td colSpan={8} className="muted">
                {forwards.length === 0 ? "No port forwards: nothing on your network is reachable from the internet through the router." : "No port forwards match."}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function RuleRow({ r, many, zones, open, onToggle }: { r: FirewallRule; many: boolean; zones: boolean; open: boolean; onToggle: () => void }) {
  const cols = 7 + (many ? 1 : 0) + (zones ? 0 : 1);
  return (
    <Fragment>
      <tr className={`clickable ${r.enabled ? "" : "fw-off"}`} onClick={onToggle}>
        {many && <td>{r.target}</td>}
        <td>
          <strong>{r.name}</strong>
          {r.builtin && <span className="pill fw-tag">built-in</span>}
          {r.description && <div className="muted small">{r.description}</div>}
        </td>
        <td><span className={`pill ${actionTone[r.action] ?? ""}`}>{r.action}</span></td>
        {!zones && <td className="mono">{r.ruleset}</td>}
        <td><Endpoint e={r.source} zones={zones} /></td>
        <td><Endpoint e={r.destination} zones={zones} /></td>
        <td>{r.protocol}{r.ip_version && <span className="muted small"> {r.ip_version}</span>}</td>
        <td>{r.enabled ? <span className="pill good">on</span> : <span className="pill">off</span>}</td>
      </tr>
      {open && (
        <tr className="detail">
          <td colSpan={cols}>
            <dl className="kv">
              <dt>Order</dt><dd className="mono">{r.index}</dd>
              <dt>Connection states</dt><dd>{r.states?.length ? r.states.join(", ") : "all"}</dd>
              <dt>Schedule</dt><dd>{r.schedule ?? "always"}</dd>
              <dt>Logging</dt><dd>{r.logging ? "on" : "off"}</dd>
              <dt>Rule id</dt><dd className="mono">{r.id}</dd>
            </dl>
          </td>
        </tr>
      )}
    </Fragment>
  );
}

function ForwardRow({ f, many }: { f: PortForward; many: boolean }) {
  return (
    <tr className={f.enabled ? "" : "fw-off"}>
      {many && <td>{f.target}</td>}
      <td><strong>{f.name}</strong>{f.logging && <span className="pill fw-tag">logged</span>}</td>
      <td>{f.interface}{f.destination && <div className="muted small mono">{f.destination}</div>}</td>
      <td>{f.protocol}</td>
      <td className="mono">{f.external_port}</td>
      <td>
        <span className="mono">{f.forward_ip}:{f.forward_port}</span>
        {f.forward_client && <div className="muted small">{f.forward_client}</div>}
      </td>
      <td>{f.source === "Any" ? <span className="warn-text">Anyone</span> : f.source}</td>
      <td>{f.enabled ? <span className="pill good">on</span> : <span className="pill">off</span>}</td>
    </tr>
  );
}
