import { useEffect, useState } from "react";
import { api, Cert, User, VaultStatus } from "../api";

export function Vault({ user, vault, onVault }: { user: User; vault: VaultStatus | null; onVault: (v: VaultStatus) => void }) {
  const isAdmin = user.role === "admin";
  const [paths, setPaths] = useState<string[]>([]);
  const [revealed, setRevealed] = useState<Record<string, Record<string, string>>>({});
  const [certs, setCerts] = useState<Cert[]>([]);
  const [imp, setImp] = useState({ name: "", cert_pem: "", key_pem: "" });
  const [err, setErr] = useState("");

  const load = () => {
    api<Cert[]>("GET", "/api/certs").then(setCerts).catch(() => {});
    if (isAdmin) api<string[]>("GET", "/api/vault/secrets").then(setPaths).catch((e) => setErr(e.message));
  };
  useEffect(load, [isAdmin, vault?.sealed]);

  const reveal = async (path: string) => {
    if (revealed[path]) {
      const next = { ...revealed };
      delete next[path];
      return setRevealed(next);
    }
    try {
      const r = await api<{ values: Record<string, string> }>("POST", "/api/vault/reveal", { path });
      setRevealed({ ...revealed, [path]: r.values });
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const seal = async () => onVault(await api<VaultStatus>("POST", "/api/vault/seal"));

  const importCert = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await api("POST", "/api/certs", imp);
      setImp({ name: "", cert_pem: "", key_pem: "" });
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const readFile = (field: "cert_pem" | "key_pem") => (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) f.text().then((t) => setImp((cur) => ({ ...cur, [field]: t })));
  };

  const delCert = async (c: Cert) => {
    if (!window.confirm(`Delete ${c.name}${c.has_key ? " and its private key" : ""}?`)) return;
    await api("DELETE", `/api/certs/${c.id}`);
    load();
  };

  return (
    <>
      <h1>Vault &amp; certificates</h1>
      {err && <div className="error block">{err}</div>}

      <section className="card">
        <h2>Vault</h2>
        {vault && (
          <p>
            Backend: <strong>{vault.backend === "local" ? "built-in encrypted vault" : "HashiCorp Vault"}</strong> ·{" "}
            {vault.sealed ? <span className="pill bad">sealed</span> : <span className="pill good">unsealed</span>}
            {isAdmin && vault.backend === "local" && !vault.sealed && <button className="link" onClick={seal}> Seal now</button>}
          </p>
        )}
        <p className="muted small">
          Secrets are encrypted with AES-256-GCM, each with its own key, wrapped by a master key derived from your passphrase (Argon2id).
          Values are never sent to the browser unless an admin reveals them, and every reveal is written to the audit log.
        </p>
        {isAdmin && (
          <table>
            <thead><tr><th>Path</th><th>Values</th><th /></tr></thead>
            <tbody>
              {paths.map((p) => (
                <tr key={p}>
                  <td className="mono">{p}</td>
                  <td className="mono small">
                    {revealed[p] ? Object.entries(revealed[p]).map(([k, v]) => <div key={k}>{k}: {k.includes("private_key") ? v.split("\n")[0] + " …" : v}</div>) : "••••••"}
                  </td>
                  <td className="actions"><button className="link" onClick={() => reveal(p)}>{revealed[p] ? "Hide" : "Reveal"}</button></td>
                </tr>
              ))}
              {paths.length === 0 && <tr><td colSpan={3} className="muted">No secrets stored yet.</td></tr>}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <h2>Certificates</h2>
        <table>
          <thead><tr><th>Name</th><th>Names covered</th><th>Issuer</th><th>Expires</th><th>Key</th><th /></tr></thead>
          <tbody>
            {certs.map((c) => (
              <tr key={c.id}>
                <td><strong>{c.name}</strong></td>
                <td className="small">{c.sans?.join(", ")}</td>
                <td className="small">{c.issuer}</td>
                <td>
                  {new Date(c.not_after).toLocaleDateString()}{" "}
                  <span className={`pill ${c.status === "ok" ? "good" : c.status === "expiring" ? "warn" : "bad"}`}>
                    {c.days_left < 0 ? "expired" : `${c.days_left}d`}
                  </span>
                </td>
                <td>{c.has_key ? "in vault" : "—"}</td>
                <td className="actions">
                  <a className="link" href={`/api/certs/${c.id}/pem`} download={`${c.name}.pem`}>PEM</a>
                  {isAdmin && <button className="link danger" onClick={() => delCert(c)}>Delete</button>}
                </td>
              </tr>
            ))}
            {certs.length === 0 && <tr><td colSpan={6} className="muted">No certificates yet.</td></tr>}
          </tbody>
        </table>

        {isAdmin && (
          <form onSubmit={importCert} className="import">
            <h3>Import a certificate</h3>
            <label>Name (optional; defaults to the common name)<input value={imp.name} onChange={(e) => setImp({ ...imp, name: e.target.value })} /></label>
            <div className="row">
              <label>Certificate chain (PEM)<textarea rows={5} className="mono small" value={imp.cert_pem} onChange={(e) => setImp({ ...imp, cert_pem: e.target.value })} /><input type="file" accept=".pem,.crt,.cer" onChange={readFile("cert_pem")} /></label>
              <label>Private key (PEM, optional)<textarea rows={5} className="mono small" value={imp.key_pem} onChange={(e) => setImp({ ...imp, key_pem: e.target.value })} /><input type="file" accept=".pem,.key" onChange={readFile("key_pem")} /></label>
            </div>
            <button className="primary" disabled={!imp.cert_pem}>Import</button>
          </form>
        )}
      </section>
    </>
  );
}
