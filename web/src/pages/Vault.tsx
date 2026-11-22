// Vault & certificates page: vault status (seal, list and reveal secrets for admins) and the
// certificate inventory (import, CA bundles, expiry, delete).
import { Fragment, useEffect, useState } from "react";
import { api, Cert, User, VaultStatus } from "../api";

export function Vault({ user, vault, onVault }: { user: User; vault: VaultStatus | null; onVault: (v: VaultStatus) => void }) {
  const isAdmin = user.role === "admin";
  const [paths, setPaths] = useState<string[]>([]);
  const [revealed, setRevealed] = useState<Record<string, Record<string, string>>>({});
  const [certs, setCerts] = useState<Cert[]>([]);
  const [imp, setImp] = useState({ name: "", cert_pem: "", key_pem: "", ca_bundle_pem: "" });
  const [note, setNote] = useState("");
  const [bundleFor, setBundleFor] = useState<number | null>(null);
  const [bundle, setBundle] = useState("");
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
      const c = await api<Cert>("POST", "/api/certs", imp);
      setImp({ name: "", cert_pem: "", key_pem: "", ca_bundle_pem: "" });
      setNote(chainNote(c));
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const saveBundle = async (c: Cert, pemText: string) => {
    setErr("");
    try {
      const r = await api<Cert>("PUT", `/api/certs/${c.id}/chain`, { ca_bundle_pem: pemText });
      setNote(chainNote(r));
      setBundleFor(null);
      setBundle("");
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const readFile = (field: "cert_pem" | "key_pem" | "ca_bundle_pem") => (e: React.ChangeEvent<HTMLInputElement>) => {
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
      {note && <div className="ok block">{note} <button className="link" onClick={() => setNote("")}>Dismiss</button></div>}

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
          <thead><tr><th>Name</th><th>Names covered</th><th>Issuer</th><th>Expires</th><th>Key</th><th>CA chain</th><th /></tr></thead>
          <tbody>
            {certs.map((c) => (
              <Fragment key={c.id}>
              <tr>
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
                <td className="small" title={c.chain?.join(" → ")}>
                  {c.chain && c.chain.length > 0
                    ? <>{c.chain.length} CA {c.chain_complete ? <span className="pill good">to root</span> : <span className="muted">(no root)</span>}</>
                    : c.chain_complete ? <span className="muted">self-signed</span> : <span className="pill warn">leaf only</span>}
                </td>
                <td className="actions">
                  {isAdmin && <button className="link" onClick={() => { setBundleFor(bundleFor === c.id ? null : c.id); setBundle(""); }}>CA bundle</button>}
                  <a className="link" href={`/api/certs/${c.id}/pem`} download={`${c.name}.pem`}>PEM</a>
                  {isAdmin && c.has_key && <a className="link" href={`#/deploy?cert=${c.id}`}>Deploy</a>}
                  {isAdmin && <button className="link danger" onClick={() => delCert(c)}>Delete</button>}
                </td>
              </tr>
              {bundleFor === c.id && (
                <tr><td colSpan={7}>
                  <div className="bundle-edit">
                    <label>CA bundle for {c.name} (PEM: intermediates and, if you want, the root, in any order)
                      <textarea rows={5} className="mono small" value={bundle} onChange={(e) => setBundle(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" />
                      <input type="file" accept=".pem,.crt,.cer,.ca-bundle" onChange={(e) => { const f = e.target.files?.[0]; if (f) f.text().then(setBundle); }} />
                    </label>
                    <p className="field-help">This replaces the CA certificates stored with {c.name}{c.chain?.length ? ` (now: ${c.chain.join(" → ")})` : ""}. NCC puts them in order and leaves out any that did not issue this certificate.</p>
                    <div className="modal-actions">
                      {c.chain && c.chain.length > 0 && <button type="button" className="danger-outline" onClick={() => saveBundle(c, "")}>Remove CA certificates</button>}
                      <button type="button" onClick={() => setBundleFor(null)}>Cancel</button>
                      <button type="button" className="primary" disabled={!bundle.trim()} onClick={() => saveBundle(c, bundle)}>Save CA bundle</button>
                    </div>
                  </div>
                </td></tr>
              )}
              </Fragment>
            ))}
            {certs.length === 0 && <tr><td colSpan={7} className="muted">No certificates yet.</td></tr>}
          </tbody>
        </table>

        {isAdmin && (
          <form onSubmit={importCert} className="import">
            <h3>Import a certificate</h3>
            <label>Name (optional; defaults to the common name)<input value={imp.name} onChange={(e) => setImp({ ...imp, name: e.target.value })} /></label>
            <div className="row">
              <label>Certificate chain (PEM)<textarea rows={5} className="mono small" value={imp.cert_pem} onChange={(e) => setImp({ ...imp, cert_pem: e.target.value })} /><input type="file" accept=".pem,.crt,.cer" onChange={readFile("cert_pem")} /></label>
              <label>Private key (PEM, optional)<textarea rows={5} className="mono small" value={imp.key_pem} onChange={(e) => setImp({ ...imp, key_pem: e.target.value })} /><input type="file" accept=".pem,.key" onChange={readFile("key_pem")} /></label>
                          <label>CA bundle (PEM, optional)<textarea rows={5} className="mono small" value={imp.ca_bundle_pem} onChange={(e) => setImp({ ...imp, ca_bundle_pem: e.target.value })} placeholder="Intermediates and root from your CA" /><input type="file" accept=".pem,.crt,.cer,.ca-bundle" onChange={readFile("ca_bundle_pem")} /></label>
            </div>
            <button className="primary" disabled={!imp.cert_pem}>Import</button>
          </form>
        )}
      </section>
    </>
  );
}

function chainNote(c: Cert): string {
  const chain = c.chain?.length ? `${c.name}: chain ${c.chain.join(" → ")}${c.chain_complete ? "" : " (no root)"}.` : `${c.name}: no CA certificates stored.`;
  const dropped = c.dropped?.length ? ` Left out (did not issue this certificate): ${c.dropped.join(", ")}.` : "";
  return chain + dropped;
}
