// First-run setup (create the admin and the vault passphrase) and the login form with optional TOTP.
import { useState } from "react";
import { api, setCSRF } from "../api";
import { Icon } from "../icons";

// AuthFrame is the split sign-in layout: a branded panel with a drawn network on the left, the form on the right.
function AuthFrame({ children }: { children: React.ReactNode }) {
  const nodes: [number, number, number][] = [[120, 140, 7], [300, 90, 5], [470, 200, 8], [220, 300, 6], [400, 380, 5], [600, 320, 7], [140, 470, 5], [330, 540, 8], [560, 520, 6], [700, 140, 5], [690, 650, 6], [90, 660, 6], [460, 690, 5]];
  const links = [[0, 1], [1, 2], [0, 3], [3, 2], [2, 4], [2, 5], [3, 6], [4, 7], [5, 8], [2, 9], [5, 9], [7, 8], [8, 10], [6, 11], [7, 12], [6, 7]];
  return (
    <div className="auth">
      <div className="auth-art">
        <svg className="net" viewBox="0 0 760 760" preserveAspectRatio="xMidYMid slice" aria-hidden>
          {links.map(([a, b], i) => <line key={i} x1={nodes[a][0]} y1={nodes[a][1]} x2={nodes[b][0]} y2={nodes[b][1]} stroke="#6b8cff" strokeOpacity="0.35" strokeWidth="1.2" />)}
          {nodes.map(([x, y, r], i) => (
            <g key={i}>
              <circle cx={x} cy={y} r={r * 2.6} fill={i % 3 ? "#2dd4bf" : "#6b8cff"} fillOpacity="0.1" />
              <circle cx={x} cy={y} r={r} fill="#0a1222" stroke={i % 3 ? "#2dd4bf" : "#8aa4ff"} strokeWidth="1.6" />
            </g>
          ))}
        </svg>
        <div className="brand">
          <span className="brand-mark"><Icon name="topology" size={19} /></span>
          <span><div className="brand-name">NCC</div><div className="brand-sub">Network Control Centre</div></span>
        </div>
        <div>
          <h2>Your routers, switches, DNS and certificates in one place.</h2>
          <p>See the live network map, add DNS records with automatic reverse entries, and keep every credential and key in an encrypted vault.</p>
        </div>
      </div>
      <div className="auth-form">{children}</div>
    </div>
  );
}

export function Setup({ onDone }: { onDone: () => void }) {
  const [f, setF] = useState({ username: "admin", password: "", confirm: "", vault_passphrase: "" });
  const [err, setErr] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (f.password !== f.confirm) return setErr("Passwords do not match");
    try {
      await api("POST", "/api/setup", { username: f.username, password: f.password, vault_passphrase: f.vault_passphrase });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <AuthFrame>
      <form onSubmit={submit}>
        <h1>Set up Network Control Centre</h1>
        <p className="muted">Create the first admin account and the passphrase that unlocks the built-in vault. Keep the passphrase somewhere safe: without it the stored credentials cannot be decrypted.</p>
        <label>Admin username<input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></label>
        <label>Password (12+ characters)<input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></label>
        <label>Confirm password<input type="password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} /></label>
        <label>Vault passphrase (12+ characters)<input type="password" value={f.vault_passphrase} onChange={(e) => setF({ ...f, vault_passphrase: e.target.value })} autoComplete="off" /></label>
        {err && <div className="error">{err}</div>}
        <button className="primary">Create admin</button>
      </form>
    </AuthFrame>
  );
}

export function Login({ onDone }: { onDone: () => void }) {
  const [f, setF] = useState({ username: "", password: "", code: "" });
  const [err, setErr] = useState("");
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      const r = await api<{ csrf: string }>("POST", "/api/login", f);
      setCSRF(r.csrf);
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <AuthFrame>
      <form onSubmit={submit}>
        <h1>Sign in</h1>
        <p className="muted">Use your NCC account. Ask an admin if you need one.</p>
        <label>Username<input autoFocus value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></label>
        <label>Password<input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></label>
        <label>Authenticator code (if MFA is on)<input inputMode="numeric" autoComplete="one-time-code" value={f.code} onChange={(e) => setF({ ...f, code: e.target.value })} /></label>
        {err && <div className="error">{err}</div>}
        <button className="primary">Log in</button>
      </form>
    </AuthFrame>
  );
}
