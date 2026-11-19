import { useState } from "react";
import { api, setCSRF } from "../api";

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
    <div className="center">
      <form className="card narrow" onSubmit={submit}>
        <h1>Set up Network Control Centre</h1>
        <p className="muted">Create the first admin account and the passphrase that unlocks the built-in vault. Keep the passphrase somewhere safe: without it the stored credentials cannot be decrypted.</p>
        <label>Admin username<input value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></label>
        <label>Password (12+ characters)<input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></label>
        <label>Confirm password<input type="password" value={f.confirm} onChange={(e) => setF({ ...f, confirm: e.target.value })} /></label>
        <label>Vault passphrase (12+ characters)<input type="password" value={f.vault_passphrase} onChange={(e) => setF({ ...f, vault_passphrase: e.target.value })} autoComplete="off" /></label>
        {err && <div className="error">{err}</div>}
        <button className="primary">Create admin</button>
      </form>
    </div>
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
    <div className="center">
      <form className="card narrow" onSubmit={submit}>
        <h1>Network Control Centre</h1>
        <label>Username<input autoFocus value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} /></label>
        <label>Password<input type="password" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} /></label>
        <label>Authenticator code (if MFA is on)<input inputMode="numeric" autoComplete="one-time-code" value={f.code} onChange={(e) => setF({ ...f, code: e.target.value })} /></label>
        {err && <div className="error">{err}</div>}
        <button className="primary">Log in</button>
      </form>
    </div>
  );
}
