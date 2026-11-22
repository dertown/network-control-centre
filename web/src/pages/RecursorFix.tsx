// RecursorFix is the "Fix" dialog on the router DNS check's "can't read the forwarders" and
// "refuses internet names" results. It first looks for the PowerDNS Recursor's API on the
// usual ports (often the API is on and only the saved URL is wrong). When nothing answers it
// logs in to the DNS server over SSH and previews the exact changes: turning the API on, or,
// when the server only runs the authoritative server, installing the Recursor and putting it
// on port 53. Nothing on the server changes until the person confirms the preview.
import { useEffect, useState } from "react";
import { api, RecursorDiscovery, RecursorPlan, RecursorResult } from "../api";
import { Icon } from "../icons";
import { Modal } from "../ui";

type Phase = "looking" | "found" | "ssh" | "plan" | "running" | "done";

interface SSHForm {
  host: string; port: string; user: string; password: string; private_key: string; passphrase: string;
  sudo: boolean; remember: boolean; make_resolver: boolean; useKey: boolean;
}

export function RecursorFix({ target, name, onClose }: { target: number; name: string; onClose: (changed: boolean) => void }) {
  const [phase, setPhase] = useState<Phase>("looking");
  const [disc, setDisc] = useState<RecursorDiscovery | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [apiKey, setApiKey] = useState("");
  const [form, setForm] = useState<SSHForm>({ host: "", port: "22", user: "root", password: "", private_key: "", passphrase: "", sudo: false, remember: true, make_resolver: false, useKey: false });
  const [hostKey, setHostKey] = useState<{ host: string; fp: string } | null>(null);
  const [trust, setTrust] = useState(false);
  const [accepted, setAccepted] = useState("");
  const [plan, setPlan] = useState<{ id: string; plan: RecursorPlan } | null>(null);
  const [result, setResult] = useState<RecursorResult | null>(null);
  const [changed, setChanged] = useState(false);
  const base = `/api/dns/recursor-fix/${target}`;

  useEffect(() => {
    api<RecursorDiscovery>("POST", `${base}/discover`, {}).then((d) => {
      setDisc(d);
      setForm((f) => ({ ...f, host: d.ssh.host, port: String(d.ssh.port || 22), user: d.ssh.user, sudo: d.ssh.sudo, make_resolver: d.no_resolver }));
      setPhase(d.discovery.found ? "found" : "ssh");
    }).catch((e) => { setErr((e as Error).message); setPhase("ssh"); });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target]);

  const use = async (url: string) => {
    setBusy(true); setErr("");
    try {
      await api("POST", `${base}/use`, { url, api_key: apiKey });
      setChanged(true);
      setResult({ ok: true, url, steps: [{ title: `Saved ${url} as the Recursor API URL`, ok: true }] });
      setPhase("done");
    } catch (e) { setErr((e as Error).message); }
    setBusy(false);
  };

  const preview = async (accept = accepted) => {
    setBusy(true); setErr(""); setPlan(null);
    try {
      const body = {
        host: form.host, port: Number(form.port) || 22, user: form.user, sudo: form.sudo, remember: form.remember,
        make_resolver: form.make_resolver, accept_host_key: accept,
        password: form.useKey ? "" : form.password, private_key: form.useKey ? form.private_key : "", passphrase: form.useKey ? form.passphrase : "",
      };
      const r = await api<{ plan_id?: string; plan?: RecursorPlan; host_key_unknown?: string; host?: string }>("POST", `${base}/plan`, body);
      if (r.host_key_unknown) {
        setHostKey({ host: r.host ?? form.host, fp: r.host_key_unknown }); setTrust(false);
      } else if (r.plan && r.plan_id) {
        if (accept) setAccepted(accept);
        setHostKey(null); setPlan({ id: r.plan_id, plan: r.plan }); setPhase("plan");
      }
    } catch (e) { setErr((e as Error).message); }
    setBusy(false);
  };

  const apply = async () => {
    if (!plan) return;
    setPhase("running"); setErr("");
    try {
      const r = await api<{ result: RecursorResult; mode: string }>("POST", `${base}/apply`, { plan_id: plan.id });
      setResult(r.result);
      setChanged(true);
      setPhase("done");
    } catch (e) { setErr((e as Error).message); setPhase("plan"); }
  };

  const close = () => onClose(changed);
  const found = disc?.discovery.found;
  const nothing = disc && !found;
  const canPreview = !!form.host && !!form.user && (form.useKey ? !!form.private_key || !!disc?.ssh.has_key : !!form.password || !!disc?.ssh.has_password);

  return (
    <Modal title={`Fix the Recursor API of ${name}`} onClose={close} wide>
      {phase === "looking" && <p className="muted"><span className="spin" /> Looking for the PowerDNS Recursor's API on the DNS server's usual ports…</p>}

      {phase === "found" && found && (
        <>
          <div className={`banner ${found.key_ok ? "good" : "warn"}`}>
            <Icon name={found.key_ok ? "check" : "alert"} size={16} />
            <span>
              Found the Recursor's API at <b className="mono">{found.url}</b>{found.version && <> (Recursor {found.version})</>}
              {disc?.current_url && disc.current_url !== found.url && <>. NCC had <span className="mono">{disc.current_url}</span> saved.</>}
              {!found.key_ok && <>. It needs its own API key (api-key in recursor.conf).</>}
            </span>
          </div>
          {!found.key_ok && (
            <label>Recursor API key<input type="password" autoComplete="off" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder="api-key from recursor.conf" /></label>
          )}
          {err && <div className="error block">{err}</div>}
          <div className="modal-actions">
            <button onClick={() => setPhase("ssh")}>Set it up over SSH instead</button>
            <button className="primary" disabled={busy || (!found.key_ok && !apiKey)} onClick={() => use(found.url)}>Use this URL</button>
          </div>
        </>
      )}

      {phase === "ssh" && (
        <>
          {nothing && (
            <div className="banner warn">
              <Icon name="alert" size={16} />
              <span>
                {disc!.no_resolver
                  ? <>No Recursor API answers, and {disc!.discovery.hosts[0] ?? "the server"} refuses internet lookups: it only runs the PowerDNS authoritative server. There is no Recursor to read yet.</>
                  : <>No Recursor API answers on {disc!.discovery.hosts.join(", ")}. Its web server is off, listens only on 127.0.0.1, or a firewall blocks it.</>}
              </span>
            </div>
          )}
          {nothing && <ProbeList disc={disc!} />}
          <h3>Log in to the DNS server</h3>
          <p className="muted small">NCC reads how PowerDNS is set up and shows every change before making it. The login is kept in the vault when you tick “Remember”.</p>
          <div className="row">
            <label className="grow2">Server<input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="192.168.1.70" /></label>
            <label className="port-field">SSH port<input value={form.port} inputMode="numeric" onChange={(e) => setForm({ ...form, port: e.target.value })} /></label>
            <label>User<input value={form.user} onChange={(e) => setForm({ ...form, user: e.target.value })} autoComplete="off" /></label>
          </div>
          <div className="seg" role="tablist" aria-label="SSH login">
            <button type="button" className={!form.useKey ? "on" : ""} onClick={() => setForm({ ...form, useKey: false })}>Password</button>
            <button type="button" className={form.useKey ? "on" : ""} onClick={() => setForm({ ...form, useKey: true })}>Private key</button>
          </div>
          {!form.useKey
            ? <label>Password<input type="password" autoComplete="off" value={form.password} placeholder={disc?.ssh.has_password ? "saved, leave empty to keep" : ""} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
            : <>
                <label>Private key<textarea rows={3} className="mono small" value={form.private_key} placeholder={disc?.ssh.has_key ? "saved, leave empty to keep" : "-----BEGIN OPENSSH PRIVATE KEY-----"} onChange={(e) => setForm({ ...form, private_key: e.target.value })} /></label>
                <label>Key passphrase (if any)<input type="password" autoComplete="off" value={form.passphrase} onChange={(e) => setForm({ ...form, passphrase: e.target.value })} /></label>
              </>}
          <label className="check"><input type="checkbox" checked={form.sudo} onChange={(e) => setForm({ ...form, sudo: e.target.checked })} /> Use sudo (for a user that isn't root; the password above is used for sudo)</label>
          <label className="check"><input type="checkbox" checked={form.make_resolver} onChange={(e) => setForm({ ...form, make_resolver: e.target.checked })} />
            Install the PowerDNS Recursor if it's missing and make it answer on port 53 (the authoritative server moves to 127.0.0.1:5300)</label>
          <label className="check"><input type="checkbox" checked={form.remember} onChange={(e) => setForm({ ...form, remember: e.target.checked })} /> Remember this login for {name}</label>
          {hostKey && (
            <div className="trust block">
              <div><Icon name="alert" size={15} /> First connection to <b>{hostKey.host}</b>. Check this SSH host key matches the server before trusting it:</div>
              <div className="mono small wrap fp">{hostKey.fp}</div>
              <label className="check"><input type="checkbox" checked={trust} onChange={(e) => setTrust(e.target.checked)} /> It matches. Trust and pin it.</label>
              <div className="muted small">On the server: <span className="mono">ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</span></div>
            </div>
          )}
          {err && <div className="error block">{err}</div>}
          <div className="modal-actions">
            <button onClick={close}>Cancel</button>
            <button className="primary" disabled={busy || !canPreview || (!!hostKey && !trust)} onClick={() => preview(hostKey && trust ? hostKey.fp : accepted)}>
              {busy ? <><span className="spin" /> Reading the server…</> : "Preview changes"}
            </button>
          </div>
        </>
      )}

      {(phase === "plan" || phase === "running") && plan && <PlanView plan={plan.plan} />}
      {phase === "plan" && plan && (
        <>
          {err && <div className="error block">{err}</div>}
          <div className="modal-actions">
            <button onClick={() => setPhase("ssh")}>Back</button>
            {!plan.plan.blocked && <button className="primary" onClick={apply}>
              {plan.plan.mode === "install" ? "Install the Recursor" : "Make these changes"}</button>}
          </div>
        </>
      )}
      {phase === "running" && <p className="muted"><span className="spin" /> Working on {plan?.plan.host}… {plan?.plan.mode === "install" ? "Installing can take a minute." : "This takes a few seconds."}</p>}

      {phase === "done" && result && (
        <>
          <div className={`banner ${result.ok ? "good" : "bad"}`}>
            <Icon name={result.ok ? "check" : "alert"} size={16} />
            <span>
              {result.ok
                ? plan?.plan.mode === "install"
                  ? <>The Recursor is installed (and stopped). Next, preview how it is set up.</>
                  : <>Done. NCC now reads the Recursor at <b className="mono">{result.url}</b>; the check is updated.</>
                : <>{result.error}{result.rolled_back && <>. Everything was put back as it was.</>}</>}
            </span>
          </div>
          <ol className="steps">
            {result.steps.map((s, i) => (
              <li key={i} className={`step ${s.ok ? "ok" : "failed"}`}>
                <span className="step-mark">{s.ok ? "✓" : "✕"}</span>
                <div className="grow-col"><div>{s.title}</div>{s.output && <pre className="step-out">{s.output}</pre>}</div>
              </li>
            ))}
          </ol>
          <div className="modal-actions">
            {result.ok && plan?.plan.mode === "install"
              ? <button className="primary" onClick={() => { setPhase("ssh"); setResult(null); preview(); }}>Preview the setup</button>
              : <button className="primary" onClick={close}>Done</button>}
          </div>
        </>
      )}
    </Modal>
  );
}

function ProbeList({ disc }: { disc: RecursorDiscovery }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="small">
      <button className="link" onClick={() => setOpen(!open)}>{open ? "Hide" : "Show"} what NCC tried ({disc.discovery.probes.length} addresses)</button>
      {open && (
        <ul className="plain mono small">
          {disc.discovery.probes.map((p) => (
            <li key={p.url}>{p.url}: {p.error ?? (p.daemon_type ? `PowerDNS ${p.daemon_type}` : `HTTP ${p.status}`)}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function PlanView({ plan }: { plan: RecursorPlan }) {
  const f = plan.facts;
  const what = plan.mode === "install" ? "Step 1 of 2: install the PowerDNS Recursor"
    : plan.mode === "resolver" ? "Make the Recursor answer DNS on port 53 and turn on its API" : "Turn on the Recursor's web server and API";
  return (
    <>
      {plan.blocked && <div className="banner warn"><Icon name="alert" size={16} /> <span>{plan.blocked}</span></div>}
      {!plan.blocked && <h3>{what} on {plan.host}</h3>}
      <p className="muted small">
        {[f.os, f.version && `Recursor ${f.version}`, f.config_file, f.on_port_53 && `port 53: ${f.on_port_53}`, f.ufw && "ufw on"].filter(Boolean).join(" · ")}
      </p>
      {plan.warnings.map((w) => <div key={w} className="banner warn"><Icon name="alert" size={16} /> <span>{w}</span></div>)}
      {!plan.blocked && (
        <ol className="steps plan-steps">
          {plan.steps.map((s, i) => (
            <li key={i} className="step">
              <span className="step-mark">{i + 1}</span>
              <div className="grow-col">
                <div>{s.title}</div>
                {s.file && <div className="mono small wrap">{s.file}</div>}
                {s.command && <div className="small wrap mono cmd">{s.command}</div>}
                {s.diff && s.diff.length > 0 && (
                  <pre className="step-out diff">{s.diff.map((d, j) => <div key={j} className={d.startsWith("-") ? "del" : "add"}>{d}</div>)}</pre>
                )}
                {s.note && <div className="muted small">{s.note}</div>}
              </div>
            </li>
          ))}
        </ol>
      )}
      {plan.new_key && !plan.blocked && plan.mode !== "install" && <p className="muted small">NCC makes a new random API key and keeps it in the vault; it is never shown.</p>}
      {plan.next && <p className="muted small">{plan.next}</p>}
    </>
  );
}
