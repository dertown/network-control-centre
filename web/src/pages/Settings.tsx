import { useEffect, useState } from "react";
import { api, Target, User } from "../api";
import { ago } from "../live";

type Kind = "unifi" | "powerdns";

const blank = {
  unifi: { name: "dream-router", address: "https://192.168.1.1", site: "default", auth: "password", username: "", password: "", api_key: "", tls: "pin" },
  powerdns: { name: "powerdns", address: "http://192.168.1.10:8081", server_id: "localhost", api_key: "", tls: "verify" },
};

export function Settings({ user, tick }: { user: User; tick: number }) {
  const isAdmin = user.role === "admin";
  const [targets, setTargets] = useState<Target[]>([]);
  const [adding, setAdding] = useState<Kind | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<number | null>(null);

  const load = () => api<Target[]>("GET", "/api/targets").then(setTargets).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [tick]);

  const poll = async (t: Target) => {
    setErr("");
    setBusy(t.id);
    try {
      await api("POST", `/api/targets/${t.id}/poll`);
    } catch (e) {
      setErr(`${t.name}: ${(e as Error).message}`);
    }
    setBusy(null);
    load();
  };
  const toggle = async (t: Target) => { await api("PATCH", `/api/targets/${t.id}`, { enabled: !t.enabled }); load(); };
  const del = async (t: Target) => {
    if (!window.confirm(`Remove ${t.name} and its stored credentials?`)) return;
    await api("DELETE", `/api/targets/${t.id}`);
    load();
  };

  return (
    <>
      <h1>Settings</h1>
      {err && <div className="error block">{err}</div>}
      <section className="card">
        <h2>Connections</h2>
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Address</th><th>Last poll</th><th>Status</th><th /></tr></thead>
          <tbody>
            {targets.map((t) => (
              <tr key={t.id}>
                <td><strong>{t.name}</strong></td>
                <td>{t.kind}</td>
                <td className="mono small">{t.address}{t.options.tls_fingerprint && <div className="muted" title={t.options.tls_fingerprint}>cert pinned {t.options.tls_fingerprint.slice(0, 16)}…</div>}</td>
                <td>{ago(t.last_poll)}</td>
                <td>{!t.enabled ? <span className="pill">disabled</span> : t.last_error ? <span className="pill bad" title={t.last_error}>error</span> : !t.last_poll ? <span className="pill">not checked</span> : <span className="pill good">ok</span>}
                  {t.last_error && <div className="error small">{t.last_error}</div>}</td>
                <td className="actions">
                  {user.role !== "viewer" && <button className="link" disabled={busy === t.id} onClick={() => poll(t)}>{busy === t.id ? (t.category === "dns" ? "Checking…" : "Polling…") : (t.category === "dns" ? "Check now" : "Poll now")}</button>}
                  {isAdmin && <button className="link" onClick={() => toggle(t)}>{t.enabled ? "Disable" : "Enable"}</button>}
                  {isAdmin && <button className="link danger" onClick={() => del(t)}>Remove</button>}
                </td>
              </tr>
            ))}
            {targets.length === 0 && <tr><td colSpan={6} className="muted">No connections yet.</td></tr>}
          </tbody>
        </table>
        {isAdmin && !adding && (
          <div className="row">
            <button onClick={() => setAdding("unifi")}>Add UniFi console</button>
            <button onClick={() => setAdding("powerdns")}>Add PowerDNS server</button>
          </div>
        )}
        {adding && <AddTarget kind={adding} onDone={() => { setAdding(null); load(); }} />}
      </section>
      <MFA user={user} />
      {isAdmin && <Users />}
    </>
  );
}

function AddTarget({ kind, onDone }: { kind: Kind; onDone: () => void }) {
  const [f, setF] = useState<Record<string, string>>({ ...blank[kind] });
  const [err, setErr] = useState("");
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    const body =
      kind === "unifi"
        ? {
            kind, category: "device", name: f.name, address: f.address,
            options: { site: f.site, tls: f.tls },
            credentials: f.auth === "apikey" ? { api_key: f.api_key } : { username: f.username, password: f.password },
          }
        : {
            kind, category: "dns", name: f.name, address: f.address,
            options: { server_id: f.server_id, tls: f.tls }, credentials: { api_key: f.api_key },
          };
    try {
      await api("POST", "/api/targets", body);
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <form className="subcard" onSubmit={save}>
      <h3>{kind === "unifi" ? "Add UniFi console" : "Add PowerDNS server"}</h3>
      {kind === "unifi" ? (
        <p className="muted small">
          For a Dream Router 7, use its LAN address and a <strong>local</strong> admin account (UniFi OS → Admins → add a local-access-only
          user with a Network role of View Only). View Only is enough: NCC only reads. Its self-signed certificate is pinned on first connection.
        </p>
      ) : (
        <p className="muted small">Use the address of the PowerDNS webserver (<code>webserver-address</code>/<code>webserver-port</code>) and the <code>api-key</code> from pdns.conf.</p>
      )}
      <div className="row">
        <label>Name<input value={f.name} onChange={set("name")} /></label>
        <label>Address<input value={f.address} onChange={set("address")} /></label>
      </div>
      {kind === "unifi" ? (
        <>
          <div className="row">
            <label>Site<input value={f.site} onChange={set("site")} /></label>
            <label>Sign in with<select value={f.auth} onChange={set("auth")}><option value="password">Local username + password</option><option value="apikey">API key</option></select></label>
            <label>Certificate<select value={f.tls} onChange={set("tls")}><option value="pin">Pin on first use (self-signed)</option><option value="verify">Verify with trusted CAs</option></select></label>
          </div>
          {f.auth === "apikey" ? (
            <label>API key<input type="password" value={f.api_key} onChange={set("api_key")} autoComplete="off" /></label>
          ) : (
            <div className="row">
              <label>Username<input value={f.username} onChange={set("username")} autoComplete="off" /></label>
              <label>Password<input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" /></label>
            </div>
          )}
        </>
      ) : (
        <div className="row">
          <label>Server id<input value={f.server_id} onChange={set("server_id")} /></label>
          <label>API key<input type="password" value={f.api_key} onChange={set("api_key")} autoComplete="off" /></label>
          <label>Certificate (HTTPS only)<select value={f.tls} onChange={set("tls")}><option value="verify">Verify with trusted CAs</option><option value="pin">Pin on first use</option></select></label>
        </div>
      )}
      {err && <div className="error">{err}</div>}
      <div className="row">
        <button className="primary">Save</button>
        <button type="button" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}

function MFA({ user }: { user: User }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState("");
  const start = async () => setSetup(await api("POST", "/api/me/mfa/start"));
  const confirm = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api("POST", "/api/me/mfa/confirm", { secret: setup!.secret, code });
      setSetup(null);
      setMsg("MFA is on. You will need a code from your authenticator app at your next login.");
    } catch (e) {
      setMsg((e as Error).message);
    }
  };
  return (
    <section className="card">
      <h2>Two-factor sign-in</h2>
      {user.mfa && !setup ? (
        <p>MFA is on for your account.</p>
      ) : setup ? (
        <form onSubmit={confirm}>
          <p>Add this key to an authenticator app (1Password, Google Authenticator, Authy…), then enter the 6-digit code it shows.</p>
          <p className="mono">{setup.secret.match(/.{1,4}/g)?.join(" ")}</p>
          <p className="muted small mono wrap">{setup.uri}</p>
          <div className="row"><input inputMode="numeric" placeholder="123456" value={code} onChange={(e) => setCode(e.target.value)} /><button className="primary">Turn on MFA</button></div>
        </form>
      ) : (
        <button onClick={start}>Set up an authenticator app</button>
      )}
      {msg && <p className="small">{msg}</p>}
    </section>
  );
}

function Users() {
  const [users, setUsers] = useState<User[]>([]);
  const [f, setF] = useState({ username: "", password: "", role: "viewer" });
  const [err, setErr] = useState("");
  const load = () => api<User[]>("GET", "/api/users").then(setUsers).catch(() => {});
  useEffect(() => { load(); }, []);
  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await api("POST", "/api/users", f);
      setF({ username: "", password: "", role: "viewer" });
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <section className="card">
      <h2>Users</h2>
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>MFA</th></tr></thead>
        <tbody>{users.map((u) => <tr key={u.id}><td>{u.username}</td><td>{u.role}</td><td>{u.mfa ? "on" : "off"}</td></tr>)}</tbody>
      </table>
      <form className="row" onSubmit={add}>
        <input placeholder="username" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} />
        <input type="password" placeholder="password (12+)" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" />
        <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
          <option value="viewer">viewer: read only</option>
          <option value="operator">operator: DNS changes</option>
          <option value="admin">admin: everything</option>
        </select>
        <button>Add user</button>
      </form>
      {err && <div className="error">{err}</div>}
    </section>
  );
}
