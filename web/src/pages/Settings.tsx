// Settings page: the one place connections (network devices, DNS servers, virtualization,
// storage, smart home) are listed by group, added with the wizard, edited, polled, disabled and
// removed; plus password, two-factor sign-in and user management. The connection forms come
// from the server's catalog (connectionWizard.tsx).
import { Fragment, useEffect, useState } from "react";
import { api, Target, User } from "../api";
import { ago } from "../format";
import { AddConnection, EditConnection, VendorLabel } from "../connectionWizard";
import { Icon } from "../icons";

// The connection table is grouped by what the connections are, in this order.
const categories: [Target["category"], string][] = [
  ["device", "Routers, Firewalls & Switches"], ["dns", "DNS"], ["hypervisor", "Virtualization"], ["storage", "Storage"], ["smarthome", "Smart Home"],
];

export function Settings({ user, tick }: { user: User; tick: number }) {
  const isAdmin = user.role === "admin";
  const [targets, setTargets] = useState<Target[]>([]);
  const [adding, setAdding] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  const [editing, setEditing] = useState<number | null>(null);

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
            {categories.map(([cat, label]) => {
              const list = targets.filter((t) => t.category === cat);
              if (!list.length) return null;
              return (
                <Fragment key={cat}>
                  <tr className="group-row"><th colSpan={6}>{label}</th></tr>
                  {list.map((t) => (
              <Fragment key={t.id}>
              <tr>
                <td><strong>{t.name}</strong></td>
                <td><VendorLabel t={t} /></td>
                <td className="mono small">{t.address}{t.options.tls_fingerprint && <div className="muted" title={t.options.tls_fingerprint}>cert pinned {t.options.tls_fingerprint.slice(0, 16)}…</div>}</td>
                <td>{ago(t.last_poll)}</td>
                <td>{!t.enabled ? <span className="pill">disabled</span> : t.last_error ? <span className="pill bad" title={t.last_error}>error</span> : !t.last_poll ? <span className="pill">not checked</span> : <span className="pill good">ok</span>}
                  {t.last_error && <div className="error small">{t.last_error}</div>}</td>
                <td className="actions">
                  {user.role !== "viewer" && <button className="link" disabled={busy === t.id} onClick={() => poll(t)}>{busy === t.id ? (t.category === "dns" ? "Checking…" : "Polling…") : (t.category === "dns" ? "Check now" : t.category === "device" ? "Poll now" : "Refresh")}</button>}
                  {isAdmin && <button className="link" onClick={() => setEditing(editing === t.id ? null : t.id)}>Edit</button>}
                  {isAdmin && <button className="link" onClick={() => toggle(t)}>{t.enabled ? "Disable" : "Enable"}</button>}
                  {isAdmin && <button className="link danger" onClick={() => del(t)}>Remove</button>}
                </td>
              </tr>
              {editing === t.id && (
                <tr className="detail"><td colSpan={6}><EditConnection t={t} onDone={() => { setEditing(null); load(); }} /></td></tr>
              )}
              </Fragment>
                  ))}
                </Fragment>
              );
            })}
            {targets.length === 0 && <tr><td colSpan={6} className="muted">No connections yet.</td></tr>}
          </tbody>
        </table>
        {isAdmin && !adding && (
          <div className="row">
            <button className="primary" onClick={() => setAdding(true)}><Icon name="plus" size={15} />Add connection</button>
          </div>
        )}
        {adding && <AddConnection onDone={() => { setAdding(false); load(); }} />}
      </section>
      <ChangePassword />
      <MFA user={user} />
      {isAdmin && <Users me={user} />}
    </>
  );
}

function ChangePassword() {
  const empty = { current: "", next: "", confirm: "" };
  const [f, setF] = useState(empty);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const set = (k: keyof typeof empty) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    setMsg("");
    if (f.next !== f.confirm) {
      setErr("The new passwords do not match.");
      return;
    }
    try {
      await api("POST", "/api/me/password", { current_password: f.current, new_password: f.next });
      setF(empty);
      setMsg("Password changed. Any other browsers signed in as you have been logged out.");
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <section className="card">
      <h2>Change my password</h2>
      <form onSubmit={save}>
        <div className="row">
          <label>Current password<input type="password" value={f.current} onChange={set("current")} autoComplete="current-password" required /></label>
          <label>New password (12+)<input type="password" value={f.next} onChange={set("next")} autoComplete="new-password" minLength={12} required /></label>
          <label>Confirm new password<input type="password" value={f.confirm} onChange={set("confirm")} autoComplete="new-password" minLength={12} required /></label>
        </div>
        <button className="primary">Change password</button>
      </form>
      {err && <div className="error">{err}</div>}
      {msg && <p className="small">{msg}</p>}
    </section>
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

function Users({ me }: { me: User }) {
  const [users, setUsers] = useState<User[]>([]);
  const [f, setF] = useState({ username: "", password: "", role: "viewer" });
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [resetting, setResetting] = useState<User | null>(null);
  const [newPw, setNewPw] = useState("");
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
  const reset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetting) return;
    setErr("");
    setMsg("");
    try {
      await api("PUT", `/api/users/${resetting.id}/password`, { password: newPw });
      setMsg(`Password for ${resetting.username} was reset and they were logged out everywhere.`);
      setResetting(null);
      setNewPw("");
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const del = async (u: User) => {
    if (!window.confirm(`Delete the user ${u.username}? They will be logged out and cannot sign in again.`)) return;
    setErr("");
    setMsg("");
    try {
      await api("DELETE", `/api/users/${u.id}`);
      setMsg(`Deleted ${u.username}.`);
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <section className="card">
      <h2>Users</h2>
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>MFA</th><th /></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.username}{u.id === me.id && <span className="muted small"> (you)</span>}</td>
              <td>{u.role}</td>
              <td>{u.mfa ? "on" : "off"}</td>
              <td className="actions">
                {u.id !== me.id && <button className="link" onClick={() => { setResetting(u); setNewPw(""); }}>Reset password</button>}
                {u.id !== me.id && <button className="link danger" onClick={() => del(u)}>Delete</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {resetting && (
        <form className="subcard" onSubmit={reset}>
          <h3>Reset password for {resetting.username}</h3>
          <p className="muted small">They will be logged out of every browser and must sign in with the new password.</p>
          <div className="row">
            <input type="password" placeholder="new password (12+)" value={newPw} onChange={(e) => setNewPw(e.target.value)} autoComplete="new-password" minLength={12} required />
            <button className="primary">Set password</button>
            <button type="button" onClick={() => setResetting(null)}>Cancel</button>
          </div>
        </form>
      )}
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
      {msg && <p className="small">{msg}</p>}
    </section>
  );
}
