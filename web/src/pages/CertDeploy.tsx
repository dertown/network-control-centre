// Certificate deployment page: servers that receive certificates from the vault (SSH or
// WinRM), a preview of every file, edit and command, background runs and their history.
import { Fragment, useEffect, useMemo, useState } from "react";
import { api, Cert, DeployKind, DeployPlan, DeployTarget, Deployment, ServedCert, User } from "../api";
import { ago } from "../format";
import { Icon } from "../icons";
import { Modal } from "../ui";

const statusTone: Record<string, string> = { ok: "good", running: "warn", failed: "bad" };
const stepIcon: Record<string, string> = { write: "upload", edit: "edit", run: "play" };

function certPill(c?: Cert) {
  if (!c) return null;
  const tone = c.status === "ok" ? "good" : c.status === "expiring" ? "warn" : "bad";
  return <span className={`pill ${tone}`}>{c.days_left < 0 ? "expired" : `${c.days_left}d`}</span>;
}

function wantedCert(): number {
  const q = window.location.hash.split("?")[1];
  return Number(new URLSearchParams(q ?? "").get("cert") ?? 0);
}

export function CertDeploy({ user, tick }: { user: User; tick: number }) {
  const isAdmin = user.role === "admin";
  const [kinds, setKinds] = useState<DeployKind[]>([]);
  const [targets, setTargets] = useState<DeployTarget[] | null>(null);
  const [certs, setCerts] = useState<Cert[]>([]);
  const [history, setHistory] = useState<Deployment[]>([]);
  const [served, setServed] = useState<Record<number, ServedCert | "loading">>({});
  const [err, setErr] = useState("");
  const [editing, setEditing] = useState<DeployTarget | "new" | null>(null);
  const [deploying, setDeploying] = useState<DeployTarget | null>(null);
  const [openRun, setOpenRun] = useState<number | null>(null);
  const [preset, setPreset] = useState(wantedCert());

  const load = () => {
    api<DeployTarget[]>("GET", "/api/certdeploy/targets").then((t) => { setTargets(t); setErr(""); }).catch((e) => setErr(e.message));
    api<Deployment[]>("GET", "/api/certdeploy/deployments?limit=25").then(setHistory).catch(() => {});
    api<Cert[]>("GET", "/api/certs").then(setCerts).catch(() => {});
  };
  useEffect(() => { api<DeployKind[]>("GET", "/api/certdeploy/kinds").then(setKinds).catch(() => {}); }, []);
  useEffect(load, [tick]);

  const probe = (t: DeployTarget) => {
    setServed((s) => ({ ...s, [t.id]: "loading" }));
    api<ServedCert>("GET", `/api/certdeploy/targets/${t.id}/served`)
      .then((r) => setServed((s) => ({ ...s, [t.id]: r })))
      .catch((e) => setServed((s) => ({ ...s, [t.id]: { error: (e as Error).message } })));
  };
  // check what each server serves once, when the list first loads
  const ids = (targets ?? []).map((t) => t.id).join(",");
  useEffect(() => { (targets ?? []).forEach((t) => { if (!served[t.id]) probe(t); }); }, [ids]);

  const kindOf = (id: string) => kinds.find((k) => k.id === id);
  const certOf = (id: number) => certs.find((c) => c.id === id);
  const presetCert = certOf(preset);

  const del = async (t: DeployTarget) => {
    if (!window.confirm(`Remove ${t.name}? Its saved login is deleted from the vault. Nothing changes on the server.`)) return;
    try {
      await api("DELETE", `/api/certdeploy/targets/${t.id}`);
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <>
      <h1>Certificate deployment</h1>
      <p className="muted">
        Install certificates from the vault on your servers: nginx, Apache, Tomcat, Splunk Enterprise, Splunk SOAR, Foundry VTT and other
        Linux services over SSH, and IIS over WinRM. Every deployment is previewed first, the old files are kept as <span className="mono">.ncc-bak</span>,
        NCC checks the server serves the new certificate afterwards, and everything is in the audit log.
      </p>
      {err && <div className="error block">{err}</div>}
      {presetCert && (
        <div className="banner warn block">
          <Icon name="cert" size={16} /> Choose a server to deploy <b>{presetCert.name}</b> to.
          <button className="link" onClick={() => { setPreset(0); window.location.hash = "#/deploy"; }}>Clear</button>
        </div>
      )}

      <div className="toolbar">
        {isAdmin && <button className="primary" onClick={() => setEditing("new")}><Icon name="plus" size={15} /> Add server</button>}
        <button onClick={() => { load(); (targets ?? []).forEach(probe); }}><Icon name="restart" size={15} /> Check again</button>
      </div>

      <section className="card flush">
        <table className="deploy-table">
          <thead><tr><th>Server</th><th>Certificate</th><th>Serving now</th><th>Last deployment</th><th /></tr></thead>
          <tbody>
            {(targets ?? []).map((t) => {
              const k = kindOf(t.kind);
              const c = certOf(t.cert_id);
              const s = served[t.id];
              const matches = s && s !== "loading" && c && s.fingerprint === c.fingerprint;
              return (
                <tr key={t.id}>
                  <td>
                    <div className="deploy-name"><Icon name={k?.transport === "winrm" ? "monitor" : "server"} size={16} /><strong>{t.name}</strong></div>
                    <div className="muted small">{k?.label ?? t.kind} · <span className="mono">{t.host}:{t.port}</span></div>
                  </td>
                  <td>
                    {c ? <><div>{c.name} {certPill(c)}</div><div className="muted small">until {new Date(c.not_after).toLocaleDateString()}</div></> : <span className="muted">none chosen</span>}
                  </td>
                  <td className="small">
                    {s === "loading" && <span className="muted">checking…</span>}
                    {s && s !== "loading" && (s.error
                      ? <span className="muted" title={s.error}>not reachable{s.port ? ` on ${s.port}` : ""}</span>
                      : <>
                          <div>{s.cert_name ?? s.subject?.replace(/^CN=/, "")} {c && (matches ? <span className="pill good">current</span> : <span className="pill warn">different</span>)}</div>
                          <div className="muted">port {s.port}, expires {s.not_after ? new Date(s.not_after).toLocaleDateString() : "?"}</div>
                        </>)}
                  </td>
                  <td className="small">
                    {t.last_deploy
                      ? <><span className={`pill ${statusTone[t.last_deploy.status]}`}>{t.last_deploy.status}</span> <span className="muted">{ago(t.last_deploy.started)} by {t.last_deploy.actor}</span>
                          <div className="muted">{t.last_deploy.cert_name}</div></>
                      : <span className="muted">never</span>}
                  </td>
                  <td className="actions">
                    {isAdmin && <button className="primary small-btn" onClick={() => setDeploying(t)}><Icon name="upload" size={14} /> Deploy</button>}
                    {isAdmin && <button className="link" onClick={() => setEditing(t)}>Edit</button>}
                    {isAdmin && <button className="link danger" onClick={() => del(t)}>Remove</button>}
                  </td>
                </tr>
              );
            })}
            {targets && targets.length === 0 && (
              <tr><td colSpan={5}>
                <div className="empty">
                  <Icon name="server" size={28} />
                  <p><b>No servers yet.</b><br /><span className="muted">Add a server to push certificates to it. Its login is kept in the vault.</span></p>
                  {isAdmin && <button className="primary" onClick={() => setEditing("new")}><Icon name="plus" size={15} /> Add server</button>}
                </div>
              </td></tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2><Icon name="audit" /> Recent deployments</h2>
        <div className="scroll-x">
        <table className="compact">
          <thead><tr><th>When</th><th>Server</th><th>Certificate</th><th>Result</th><th>By</th></tr></thead>
          <tbody>
            {history.map((d) => (
              <Fragment key={d.id}>
                <tr className="clickable" onClick={() => setOpenRun(openRun === d.id ? null : d.id)}>
                  <td className="small">{new Date(d.started).toLocaleString()}</td>
                  <td>{d.target_name}</td>
                  <td>{d.cert_name}</td>
                  <td>
                    <span className={`pill ${statusTone[d.status]}`}>{d.status}</span>{" "}
                    {d.status === "ok" && <span className={`small ${d.verified.startsWith("ok") ? "good" : "muted"}`}>{d.verified.startsWith("ok") ? "verified" : "not confirmed"}</span>}
                  </td>
                  <td className="small">{d.actor}</td>
                </tr>
                {openRun === d.id && <tr><td colSpan={5}><RunSteps d={d} /></td></tr>}
              </Fragment>
            ))}
            {history.length === 0 && <tr><td colSpan={5} className="muted">Nothing deployed yet.</td></tr>}
          </tbody>
        </table>
        </div>
      </section>

      {editing && (
        <TargetDialog kinds={kinds} certs={certs} target={editing === "new" ? null : editing} presetCert={preset}
          onClose={(saved) => { setEditing(null); if (saved) load(); }} />
      )}
      {deploying && (
        <DeployDialog target={deploying} kind={kindOf(deploying.kind)} certs={certs} initialCert={preset || deploying.cert_id}
          onClose={() => { setDeploying(null); load(); probe(deploying); }} />
      )}
    </>
  );
}

function RunSteps({ d }: { d: Deployment }) {
  return (
    <div className="run">
      <ol className="steps">
        {d.steps.map((s, i) => (
          <li key={i} className={`step ${s.status}`}>
            <span className="step-mark">{s.status === "ok" ? "✓" : s.status === "unchanged" ? "=" : s.status === "failed" ? "✕" : s.status === "running" ? <span className="spin" /> : s.status === "skipped" ? "–" : i + 1}</span>
            <div className="grow-col">
              <div>{s.title} {s.status === "unchanged" && <span className="muted small">(already set)</span>}</div>
              {s.path && <div className="mono small muted wrap">{s.path}</div>}
              {s.output && <pre className="step-out">{s.output}</pre>}
            </div>
          </li>
        ))}
      </ol>
      {d.error && <div className="error">{d.error}</div>}
      {d.status === "ok" && d.verified && (
        <div className={d.verified.startsWith("ok") ? "ok" : "warn-text small"}>
          <Icon name={d.verified.startsWith("ok") ? "check" : "alert"} size={14} /> {d.verified.replace(/^ok: /, "")}
        </div>
      )}
    </div>
  );
}

// ---- add / edit a server ----

const loginFields: Record<"ssh" | "winrm", { key: string; label: string; secret?: boolean; area?: boolean; help?: string }[]> = {
  ssh: [
    { key: "username", label: "SSH user" },
    { key: "password", label: "Password", secret: true, help: "Used for SSH and for sudo. Optional when you use a key." },
    { key: "ssh_private_key", label: "SSH private key (optional)", secret: true, area: true, help: "OpenSSH or PEM format." },
    { key: "ssh_passphrase", label: "Key passphrase", secret: true },
    { key: "sudo_password", label: "Sudo password (if different)", secret: true },
  ],
  winrm: [
    { key: "username", label: "Windows user", help: "An administrator, e.g. HOST\\Administrator or DOMAIN\\svc-ncc." },
    { key: "password", label: "Password", secret: true },
  ],
};

function TargetDialog({ kinds, certs, target, presetCert, onClose }: {
  kinds: DeployKind[]; certs: Cert[]; target: DeployTarget | null; presetCert: number; onClose: (saved: boolean) => void;
}) {
  const [kindID, setKindID] = useState(target?.kind ?? "");
  const kind = kinds.find((k) => k.id === kindID);
  const [name, setName] = useState(target?.name ?? "");
  const [host, setHost] = useState(target?.host ?? "");
  const [port, setPort] = useState(target ? String(target.port) : "");
  const [certID, setCertID] = useState(target?.cert_id || presetCert || 0);
  const [opts, setOpts] = useState<Record<string, string>>(target?.options ?? {});
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [clear, setClear] = useState<string[]>([]);
  const [advanced, setAdvanced] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const pick = (k: DeployKind) => {
    setKindID(k.id);
    setPort(String(k.default_port));
    const o: Record<string, string> = {};
    k.fields.forEach((f) => { if (f.default !== undefined) o[f.key] = f.default; });
    setOpts(o);
  };

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!kind) return;
    setBusy(true);
    setErr("");
    const body = { name, kind: kind.id, host, port: Number(port) || 0, options: opts, cert_id: certID, credentials: creds, clear_credentials: clear };
    try {
      if (target) await api("PATCH", `/api/certdeploy/targets/${target.id}`, body);
      else await api("POST", "/api/certdeploy/targets", body);
      onClose(true);
    } catch (ex) {
      setErr((ex as Error).message);
      setBusy(false);
    }
  };

  if (!kind) {
    return (
      <Modal title="Add a server" onClose={() => onClose(false)} wide>
        <p className="muted small">What kind of server is it?</p>
        <div className="kind-grid">
          {kinds.map((k) => (
            <button key={k.id} className="kind-card" onClick={() => pick(k)}>
              <span className="kind-title"><Icon name={k.transport === "winrm" ? "monitor" : "server"} size={16} /> {k.label}</span>
              <span className="muted small">{k.description}</span>
              <span className="kind-via small">{k.transport === "winrm" ? "WinRM (HTTPS)" : "SSH"}</span>
            </button>
          ))}
        </div>
      </Modal>
    );
  }

  const main = new Set(["cert_path", "key_path", "web_cert_path", "server_cert_path", "chain_path", "combined_path", "ca_path", "keystore_path", "format", "component", "splunk_home", "phantom_home", "data_path", "site", "host_header", "https_port", "restart", "reload"]);
  const mainFields = kind.fields.filter((f) => main.has(f.key));
  const moreFields = kind.fields.filter((f) => !main.has(f.key));
  const field = (f: DeployKind["fields"][number]) => {
    const v = opts[f.key] ?? "";
    const set = (val: string) => setOpts({ ...opts, [f.key]: val });
    if (f.type === "bool") {
      return (
        <label key={f.key} className="check field-check" title={f.help}>
          <input type="checkbox" checked={v === "true"} onChange={(e) => set(e.target.checked ? "true" : "false")} /> {f.label}
          {f.help && <span className="muted small field-help">{f.help}</span>}
        </label>
      );
    }
    return (
      <label key={f.key}>
        {f.label}
        {f.type === "select"
          ? <select value={v} onChange={(e) => set(e.target.value)}>{f.choices?.map((c) => <option key={c}>{c}</option>)}</select>
          : <input value={v} onChange={(e) => set(e.target.value)} placeholder={f.default} className={f.key.includes("path") || f.key === "reload" || f.key === "restart" ? "mono" : ""} />}
        {f.help && <span className="field-help">{f.help}</span>}
      </label>
    );
  };
  const secrets = [...loginFields[kind.transport], ...(kind.secrets ?? []).map((s) => ({ key: s.key, label: s.label, secret: true, area: false, help: s.help }))];

  return (
    <Modal title={target ? `Edit ${target.name}` : `Add ${kind.label} server`} onClose={() => onClose(false)} wide>
      <form onSubmit={save} className="target-form">
        {!target && <button type="button" className="link back" onClick={() => setKindID("")}>← Other server type</button>}
        <div className="row">
          <label>Name<input value={name} onChange={(e) => setName(e.target.value)} disabled={!!target} placeholder="splunk-prod" required /></label>
          <label className="grow2">Host name or IP<input value={host} onChange={(e) => setHost(e.target.value)} placeholder="splunk.home.lan" required /></label>
          <label className="port-field">{kind.transport === "winrm" ? "WinRM port" : "SSH port"}<input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" /></label>
        </div>
        <label>Certificate to deploy here
          <select value={certID} onChange={(e) => setCertID(Number(e.target.value))}>
            <option value={0}>Choose later</option>
            {certs.map((c) => <option key={c.id} value={c.id} disabled={!c.has_key}>{c.name}{c.has_key ? "" : " (no key)"} · {c.sans?.slice(0, 3).join(", ")}</option>)}
          </select>
        </label>

        <h3>Login (kept in the vault)</h3>
        <div className="cred-grid">
          {secrets.map((s) => {
            const saved = target?.credentials?.[s.key] && !clear.includes(s.key);
            const ph = saved ? "saved, leave empty to keep" : "";
            return (
              <label key={s.key} className={s.area ? "span2" : ""}>
                <span>{s.label} {saved && <button type="button" className="link" onClick={() => setClear([...clear, s.key])}>clear</button>}</span>
                {s.area
                  ? <textarea rows={3} className="mono small" value={creds[s.key] ?? ""} placeholder={ph || "-----BEGIN OPENSSH PRIVATE KEY-----"} onChange={(e) => setCreds({ ...creds, [s.key]: e.target.value })} />
                  : <input type={s.secret ? "password" : "text"} autoComplete="off" value={creds[s.key] ?? ""} placeholder={ph} onChange={(e) => setCreds({ ...creds, [s.key]: e.target.value })} />}
                {s.help && <span className="field-help">{s.help}</span>}
              </label>
            );
          })}
        </div>

        <h3>Where the certificate goes</h3>
        <p className="field-help">In paths, {"{cert}"} is the certificate's name and {"{splunk_home}"}-style names are filled in from the other settings.</p>
        <div className="cred-grid">{mainFields.map(field)}</div>
        <button type="button" className="link" onClick={() => setAdvanced(!advanced)}>{advanced ? "Hide" : "Show"} more settings ({moreFields.length})</button>
        {advanced && <div className="cred-grid more">{moreFields.map(field)}</div>}

        {err && <div className="error block">{err}</div>}
        <div className="modal-actions">
          <button type="button" onClick={() => onClose(false)}>Cancel</button>
          <button className="primary" disabled={busy || !name || !host}>{target ? "Save" : "Add server"}</button>
        </div>
      </form>
    </Modal>
  );
}

// ---- preview and deploy ----

function DeployDialog({ target, kind, certs, initialCert, onClose }: {
  target: DeployTarget; kind?: DeployKind; certs: Cert[]; initialCert: number; onClose: () => void;
}) {
  const usable = useMemo(() => certs.filter((c) => c.has_key), [certs]);
  const [certID, setCertID] = useState(initialCert || usable[0]?.id || 0);
  const [plan, setPlan] = useState<DeployPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [trust, setTrust] = useState(false);
  const [run, setRun] = useState<Deployment | null>(null);

  const preview = () => {
    if (!certID) return;
    setLoading(true);
    setErr("");
    setPlan(null);
    setTrust(false);
    api<DeployPlan>("POST", "/api/certdeploy/plan", { target_id: target.id, cert_id: certID, connect: true })
      .then(setPlan).catch((e) => setErr(e.message)).finally(() => setLoading(false));
  };
  useEffect(preview, [certID]);

  // follow a running deployment
  useEffect(() => {
    if (!run || run.status !== "running") return;
    const t = setTimeout(() => api<Deployment>("GET", `/api/certdeploy/deployments/${run.id}`).then(setRun).catch(() => {}), 1200);
    return () => clearTimeout(t);
  }, [run]);

  const conn = plan?.connection;
  const needsTrust = !!conn?.trust;
  const canDeploy = !!plan && !plan.blocked && (conn?.ok || (needsTrust && trust));

  const deploy = async () => {
    if (!plan) return;
    setErr("");
    try {
      const d = await api<Deployment>("POST", "/api/certdeploy/deploy", {
        target_id: target.id, cert_id: certID, accept_fingerprint: needsTrust && trust ? conn?.fingerprint : "",
      });
      setRun(d);
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  const title = `Deploy to ${target.name}`;
  if (run) {
    return (
      <Modal title={title} onClose={onClose} wide>
        <p className="muted small">
          {run.status === "running" ? "Deploying" : run.status === "ok" ? "Deployed" : "Deployment failed:"} <b>{run.cert_name}</b> to {target.name} ({kind?.label}).
          {run.status === "running" && " This keeps going if you close this window."}
        </p>
        <RunSteps d={run} />
        {run.status === "running" && kind && kind.verify_wait_s > 60 && <p className="muted small">After the restart NCC waits up to {Math.round(kind.verify_wait_s / 60)} minutes for {kind.label} to come back.</p>}
        <div className="modal-actions"><button className={run.status === "running" ? "" : "primary"} onClick={onClose}>{run.status === "running" ? "Close (keeps running)" : "Done"}</button></div>
      </Modal>
    );
  }

  return (
    <Modal title={title} onClose={onClose} wide>
      <label>Certificate
        <select value={certID} onChange={(e) => setCertID(Number(e.target.value))}>
          {usable.length === 0 && <option value={0}>No certificates with a private key in the vault</option>}
          {usable.map((c) => <option key={c.id} value={c.id}>{c.name} · expires {new Date(c.not_after).toLocaleDateString()} · {c.sans?.slice(0, 3).join(", ")}</option>)}
        </select>
      </label>
      {loading && <p className="muted"><span className="spin" /> Building the preview and testing the login…</p>}
      {err && <div className="error block">{err}</div>}
      {plan && (
        <>
          {plan.blocked && <div className="banner warn"><Icon name="alert" size={16} /> {plan.blocked}</div>}
          {conn && (conn.ok
            ? <div className="ok block"><Icon name="check" size={14} /> {conn.detail}</div>
            : needsTrust
              ? <div className="trust block">
                  <div><Icon name="alert" size={15} /> First connection to <b>{target.host}</b>. Check this {kind?.transport === "winrm" ? "WinRM certificate (SHA-256)" : "SSH host key"} matches the server before trusting it:</div>
                  <div className="mono small wrap fp">{conn.fingerprint}</div>
                  <label className="check"><input type="checkbox" checked={trust} onChange={(e) => setTrust(e.target.checked)} /> It matches. Trust and pin it.</label>
                  {kind?.transport !== "winrm" && <div className="muted small">On the server: <span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span></div>}
                </div>
              : <div className="error block"><Icon name="alert" size={14} /> {conn.error} <button className="link" onClick={preview}>Try again</button></div>)}
          {plan.warnings.map((w) => <div key={w} className="banner warn"><Icon name="alert" size={16} /> {w}</div>)}
          {!plan.blocked && (
            <>
              <h3>What NCC will do on {target.host}</h3>
              <ol className="steps plan-steps">
                {plan.steps.map((s, i) => (
                  <li key={i} className="step">
                    <span className="step-mark"><Icon name={stepIcon[s.op]} size={13} /></span>
                    <div className="grow-col">
                      <div>{s.title}</div>
                      {s.path && <div className="mono small wrap">{s.path}</div>}
                      {s.detail && <div className={`small wrap ${s.op === "run" ? "mono cmd" : "muted"}`}>{s.detail}</div>}
                    </div>
                  </li>
                ))}
              </ol>
              {plan.notes.length > 0 && <ul className="notes small muted">{plan.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
            </>
          )}
        </>
      )}
      <div className="modal-actions">
        <button onClick={onClose}>Cancel</button>
        <button className="primary" disabled={!canDeploy} onClick={deploy}><Icon name="upload" size={14} /> Deploy now</button>
      </div>
    </Modal>
  );
}
