import { Fragment, useEffect, useMemo, useState } from "react";
import { api, AppUsage, SiteCount, TrafficClient, TrafficView } from "../api";
import { ago } from "../live";

const windows = [
  { id: "1h", label: "Last hour" },
  { id: "24h", label: "Last 24 hours" },
  { id: "7d", label: "Last 7 days" },
  { id: "session", label: "Since each client connected" },
];

export function bytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const v = n / 1024 ** i;
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}

export function rate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8;
  if (bits < 1e3) return `${bits.toFixed(0)} bit/s`;
  if (bits < 1e6) return `${(bits / 1e3).toFixed(0)} kbit/s`;
  if (bits < 1e9) return `${(bits / 1e6).toFixed(1)} Mbit/s`;
  return `${(bits / 1e9).toFixed(2)} Gbit/s`;
}

function appLabel(a: AppUsage): string {
  return a.name || `${a.category} (app ${a.app})`;
}

function siteLabel(s: SiteCount): string {
  return s.service ? `${s.service} (${s.site})` : s.site;
}

// byCategory folds a client's per-application DPI rows into categories.
function byCategory(apps: AppUsage[] = []): AppUsage[] {
  const m = new Map<number, AppUsage>();
  for (const a of apps) {
    const c = m.get(a.cat) ?? { ...a, app: -1, name: a.category, down_bytes: 0, up_bytes: 0 };
    c.down_bytes += a.down_bytes;
    c.up_bytes += a.up_bytes;
    m.set(a.cat, c);
  }
  return [...m.values()].sort((x, y) => y.down_bytes + y.up_bytes - (x.down_bytes + x.up_bytes));
}

function Bar({ value, max }: { value: number; max: number }) {
  const pct = max > 0 ? Math.max(1, Math.round((value / max) * 100)) : 0;
  return <div className="bar" aria-hidden><span style={{ width: `${pct}%` }} /></div>;
}

export function Traffic({ tick }: { tick: number }) {
  const [win, setWin] = useState(() => new URLSearchParams(window.location.hash.split("?")[1]).get("window") ?? "24h");
  const [view, setView] = useState<TrafficView | null>(null);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    api<TrafficView>("GET", `/api/traffic?window=${win}`)
      .then((v) => { setView(v); setErr(""); })
      .catch((e) => setErr((e as Error).message));
  }, [tick, win]);

  const shown = useMemo(() => {
    const s = q.toLowerCase();
    return (view?.clients ?? []).filter(
      (c) => !s || [c.name, c.ip, c.mac, c.vendor, ...(c.sites ?? []).map((x) => x.site)].some((v) => v?.toLowerCase().includes(s)),
    );
  }, [view, q]);

  const choose = (w: string) => {
    setWin(w);
    window.history.replaceState(null, "", `#/traffic?window=${w}`);
  };

  if (!view) return <><h1>Traffic</h1>{err ? <p className="error">{err}</p> : <p className="muted">Loading…</p>}</>;

  const maxTotal = Math.max(0, ...shown.map((c) => c.window_down + c.window_up));
  const liveDown = view.clients.reduce((n, c) => n + (c.down_rate || 0), 0);
  const liveUp = view.clients.reduce((n, c) => n + (c.up_rate || 0), 0);
  const top = view.clients[0];
  const catMax = Math.max(0, ...view.categories.map((c) => c.down_bytes + c.up_bytes));
  const siteMax = Math.max(0, ...view.sites.map((s) => s.count));
  const winLabel = windows.find((w) => w.id === win)?.label.toLowerCase() ?? win;

  return (
    <>
      <h1>Traffic</h1>
      <p className="muted">
        Which clients use the most data, what kind of traffic it is, and which sites they look up. Totals come from your
        UniFi console; application types come from its Traffic Identification (DPI); sites come from DNS query logs. Encrypted
        traffic hides page contents, so NCC shows the sites and services a device talks to, not what is on the page.
      </p>

      <div className="toolbar">
        <div className="seg" role="group" aria-label="Time window">
          {windows.map((w) => (
            <button key={w.id} className={w.id === win ? "on" : ""} onClick={() => choose(w.id)}>{w.label}</button>
          ))}
        </div>
        <input placeholder="Search client, IP, MAC or site" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="muted small">{view.taken_at ? `updated ${ago(view.taken_at)}` : "no data yet"}</span>
      </div>

      {view.clients.length === 0 && (
        <div className="banner warn">No traffic data yet. Add your UniFi console in <a href="#/settings">Settings</a>; numbers appear after the first poll.</div>
      )}
      {(view.dpi_notes ?? []).map((n) => <div key={n} className="banner warn">Application types unavailable from {n}.</div>)}
      {win !== "session" && view.clients.length > 0 && view.clients.every((c) => !c.window_down && !c.window_up) && (
        <div className="banner warn">NCC keeps a sample every 5 minutes, so totals for {winLabel} start after it has been running a little while. Choose "Since each client connected" to see the console's own counters now.</div>
      )}

      <div className="tiles">
        <div className="tile"><div className="tile-label">Downloading now</div><div className="tile-value">{rate(liveDown)}</div><div className="muted small">all clients</div></div>
        <div className="tile"><div className="tile-label">Uploading now</div><div className="tile-value">{rate(liveUp)}</div><div className="muted small">all clients</div></div>
        <div className="tile"><div className="tile-label">Top client, {winLabel}</div><div className="tile-value small-value">{top && top.window_down + top.window_up > 0 ? top.name : "—"}</div><div className="muted small">{top ? bytes(top.window_down + top.window_up) : ""}</div></div>
        <div className="tile"><div className="tile-label">Clients online</div><div className="tile-value">{view.clients.filter((c) => c.online).length}</div></div>
      </div>

      <div className="two">
        <section className="card">
          <h2>What the internet connection is used for</h2>
          {view.categories.length === 0 ? (
            <p className="muted">No application data. Turn on <strong>Traffic Identification</strong> in UniFi Network (Settings → Traffic &amp; Security) to see streaming, gaming, social media and other categories.</p>
          ) : (
            <table className="compact">
              <tbody>
                {view.categories.slice(0, 10).map((c) => (
                  <tr key={c.cat}>
                    <td>{c.category}</td>
                    <td className="barcell"><Bar value={c.down_bytes + c.up_bytes} max={catMax} /></td>
                    <td className="num">{bytes(c.down_bytes + c.up_bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {view.categories.length > 0 && <p className="muted small">Gateway DPI totals since the console last reset them.</p>}
        </section>
        <section className="card">
          <h2>Most looked-up sites</h2>
          <DNSHint view={view} />
          {view.sites.length > 0 && (
            <table className="compact">
              <tbody>
                {view.sites.slice(0, 10).map((s) => (
                  <tr key={s.site}>
                    <td>{siteLabel(s)}</td>
                    <td className="barcell"><Bar value={s.count} max={siteMax} /></td>
                    <td className="num">{s.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>

      <div className="card flush">
        <table>
          <thead>
            <tr><th>Client</th><th className="num">Download</th><th className="num">Upload</th><th>Total, {winLabel}</th><th className="num">Now ↓ / ↑</th><th>Mostly</th><th>Top sites</th></tr>
          </thead>
          <tbody>
            {shown.map((c) => (
              <Fragment key={c.mac}>
                <tr className="clickable" onClick={() => setOpen(open === c.mac ? null : c.mac)}>
                  <td>
                    <strong>{c.name}</strong>{!c.online && <span className="pill"> offline</span>}
                    <div className="muted small mono">{c.ip || c.mac}</div>
                  </td>
                  <td className="num">{bytes(c.window_down)}</td>
                  <td className="num">{bytes(c.window_up)}</td>
                  <td className="barcell"><div className="barwrap"><Bar value={c.window_down + c.window_up} max={maxTotal} /><span className="small">{bytes(c.window_down + c.window_up)}</span></div></td>
                  <td className="num small">{c.online ? <>{rate(c.down_rate)}<br />{rate(c.up_rate)}</> : "—"}</td>
                  <td>{byCategory(c.apps).slice(0, 2).map((a) => <span key={a.cat} className="pill">{a.category}</span>)}</td>
                  <td className="small">{(c.sites ?? []).slice(0, 3).map((s) => s.service || s.site).filter((v, i, a) => a.indexOf(v) === i).join(", ")}</td>
                </tr>
                {open === c.mac && (
                  <tr className="detail">
                    <td colSpan={7}><ClientDetail c={c} /></td>
                  </tr>
                )}
              </Fragment>
            ))}
            {shown.length === 0 && view.clients.length > 0 && <tr><td colSpan={7} className="muted">No client matches.</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}

function DNSHint({ view }: { view: TrafficView }) {
  const d = view.dns_log;
  if (!d.enabled) {
    return (
      <p className="muted">
        Not set up. Point PowerDNS Recursor or dnsdist's protobuf query logging at NCC and add a <code>dns_log</code> section to
        NCC's config; the README has both snippets.
      </p>
    );
  }
  if (!d.received) {
    return <p className="muted">Listening on <span className="mono">{d.listen}</span>, but no query logs have arrived since NCC started.</p>;
  }
  const routerOnly = (view.unmatched_sources ?? []).length > 0 && view.clients.every((c) => !c.sites?.length);
  return (
    <>
      <p className="muted small">From {d.senders?.join(", ")}, last {ago(d.last_message)}.</p>
      {routerOnly && (
        <p className="warn-text small">
          Lookups arrive from {view.unmatched_sources!.join(", ")}, which is not a known client. If that is your router, it is
          forwarding everyone's queries; hand out the PowerDNS resolver directly in DHCP to see sites per device.
        </p>
      )}
    </>
  );
}

function ClientDetail({ c }: { c: TrafficClient }) {
  const apps = c.apps ?? [];
  const cats = byCategory(apps);
  const sites = c.sites ?? [];
  const max = Math.max(0, ...cats.map((a) => a.down_bytes + a.up_bytes));
  return (
    <div className="two">
      <div>
        <h3>Traffic types (DPI)</h3>
        {cats.length === 0 ? <p className="muted">No application data for this client.</p> : (
          <table className="compact">
            <tbody>
              {cats.map((a) => (
                <Fragment key={a.cat}>
                  <tr>
                    <td><strong>{a.category}</strong></td>
                    <td className="barcell"><Bar value={a.down_bytes + a.up_bytes} max={max} /></td>
                    <td className="num">{bytes(a.down_bytes)} ↓ · {bytes(a.up_bytes)} ↑</td>
                  </tr>
                  {apps.filter((x) => x.cat === a.cat && x.app >= 0).length > 1 &&
                    apps.filter((x) => x.cat === a.cat).map((x) => (
                      <tr key={`${x.cat}-${x.app}`} className="muted small">
                        <td style={{ paddingLeft: 18 }}>{appLabel(x)}</td><td /><td className="num">{bytes(x.down_bytes + x.up_bytes)}</td>
                      </tr>
                    ))}
                </Fragment>
              ))}
            </tbody>
          </table>
        )}
        <dl className="kv">
          <dt>MAC</dt><dd className="mono">{c.mac}</dd>
          {c.vendor && <><dt>Vendor</dt><dd>{c.vendor}</dd></>}
          <dt>Connection</dt><dd>{c.wired ? "Wired" : `Wi-Fi${c.ssid ? ` (${c.ssid})` : ""}`}{c.network ? ` · ${c.network}` : ""}</dd>
          {c.online && <><dt>Since connected</dt><dd>{bytes(c.down_bytes)} ↓ · {bytes(c.up_bytes)} ↑</dd></>}
        </dl>
      </div>
      <div>
        <h3>Sites looked up</h3>
        {sites.length === 0 ? <p className="muted">No DNS lookups recorded for {c.ip || "this client"}.</p> : (
          <table className="compact">
            <tbody>
              {sites.map((s) => <tr key={s.site}><td>{siteLabel(s)}</td><td className="num">{s.count.toLocaleString()}</td></tr>)}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
