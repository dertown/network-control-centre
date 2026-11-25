// Certificate Authority page: NCC's own internal root CA (and intermediate), created with a
// step-by-step wizard; certificates it signs (suggested from the DNS records, or typed in),
// renewal and revocation; downloads of the root and how to make every device trust it.
// The CA private keys are made on the server and never leave the vault.
import { Fragment, useEffect, useMemo, useState } from "react";
import { api, CAList, CertAuthority as CA, CertSuggestion, IssueResult, IssuedCert, TrustPlatform, User } from "../api";
import { Icon } from "../icons";
import { Modal, PageHeader, PageLoading } from "../ui";

const keyLabels: Record<string, string> = {
  "rsa-2048": "RSA 2048", "rsa-3072": "RSA 3072", "rsa-4096": "RSA 4096", "ecdsa-p256": "ECDSA P-256", "ecdsa-p384": "ECDSA P-384",
};
const statusTone: Record<string, string> = { active: "good", expiring: "warn", expired: "bad", revoked: "bad", replaced: "" };
const date = (iso: string) => new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
const colonFP = (h: string) => h.toUpperCase().match(/.{2}/g)?.join(":") ?? h;

function wantsNew(): boolean {
  return new URLSearchParams(window.location.hash.split("?")[1] ?? "").get("new") === "1";
}

export function CertAuthority({ user, tick }: { user: User; tick: number }) {
  const isAdmin = user.role === "admin";
  const [info, setInfo] = useState<CAList | null>(null);
  const [issued, setIssued] = useState<IssuedCert[]>([]);
  const [err, setErr] = useState("");
  const [note, setNote] = useState("");
  const [wizard, setWizard] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [renewing, setRenewing] = useState<IssuedCert | null>(null);
  const [revoking, setRevoking] = useState<IssuedCert | null>(null);
  const [showOld, setShowOld] = useState(false);

  const load = () => {
    api<CAList>("GET", "/api/ca").then((r) => { setInfo(r); setErr(""); }).catch((e) => setErr(e.message));
    api<IssuedCert[]>("GET", "/api/ca/issued").then(setIssued).catch(() => {});
  };
  useEffect(load, [tick]);
  // #/ca?new=1 (from Vault & Certificates) opens "New certificate" straight away
  useEffect(() => {
    if (info && wantsNew() && isAdmin) {
      if (info.cas.length) setIssuing(true); else setWizard(true);
      window.history.replaceState(null, "", "#/ca");
    }
  }, [info, isAdmin]);

  if (!info) return <PageLoading title="Certificate Authority" err={err} />;
  const roots = info.cas.filter((c) => c.root);
  const shown = showOld ? issued : issued.filter((i) => i.status !== "replaced" && i.status !== "expired" && i.status !== "revoked");
  const hidden = issued.length - issued.filter((i) => i.status !== "replaced" && i.status !== "expired" && i.status !== "revoked").length;

  return (
    <>
      <PageHeader title="Certificate Authority">
        {isAdmin && info.cas.length > 0 && <button className="primary" onClick={() => setIssuing(true)}><Icon name="plus" size={15} /> New Certificate</button>}
        {isAdmin && info.cas.length === 0 && <button className="primary" onClick={() => setWizard(true)}><Icon name="shield" size={15} /> Create Internal CA</button>}
      </PageHeader>
      <p className="muted lede">
        Your network's own certificate authority. Certificates it signs are accepted as valid by every device that trusts its root,
        with no browser warnings and no public CA. The CA's private keys are made here and kept in the vault; they are never shown or downloaded.
      </p>
      {err && <div className="error block">{err}</div>}
      {note && <div className="ok block">{note} <button className="link" onClick={() => setNote("")}>Dismiss</button></div>}

      {info.cas.length === 0 ? (
        <section className="card ca-empty">
          <span className="tile-icon c1"><Icon name="shield" size={22} /></span>
          <div>
            <h2>No internal CA yet</h2>
            <ol className="ca-howto">
              <li><b>Create the root</b> (and an issuing intermediate). A short wizard; the keys go straight into the vault.</li>
              <li><b>Issue certificates</b> for your servers. NCC suggests names from your DNS records.</li>
              <li><b>Trust the root</b> on your devices: downloads and instructions for every platform, or push it to servers over SSH and WinRM.</li>
              <li><b>Deploy</b> the certificates to nginx, Apache, IIS, Splunk and more from Certificate Deployment.</li>
            </ol>
            {isAdmin ? <button className="primary" onClick={() => setWizard(true)}><Icon name="shield" size={15} /> Create Internal CA</button>
              : <p className="muted small">An admin can create it.</p>}
          </div>
        </section>
      ) : (
        <>
          <section className="card">
            <div className="card-head"><h2><Icon name="shield" size={16} /> Authorities</h2></div>
            <div className="ca-list">
              {info.cas.map((c) => <CACard key={c.id} c={c} />)}
            </div>
            {isAdmin && roots.length > 0 && !info.cas.some((c) => !c.root) && (
              <AddIntermediate root={roots[0]} keyTypes={info.key_types} onDone={(m) => { setNote(m); load(); }} />
            )}
          </section>

          {roots.map((r) => <TrustGuide key={r.id} root={r} base={info.base} isAdmin={isAdmin} />)}

          <section className="card">
            <div className="card-head">
              <h2><Icon name="cert" size={16} /> Issued Certificates</h2>
              {hidden > 0 && <button className="link" onClick={() => setShowOld(!showOld)}>{showOld ? "Hide" : "Show"} {hidden} renewed, revoked or expired</button>}
            </div>
            <div className="scroll-x">
              <table className="ca-issued">
                <thead><tr><th>Name</th><th>Names covered</th><th>Signed by</th><th>Expires</th><th>Status</th><th /></tr></thead>
                <tbody>
                  {shown.map((i) => (
                    <tr key={i.id}>
                      <td><strong>{i.cert_name}</strong><div className="muted small">{i.usage === "server" ? "Server" : i.usage === "client" ? "Client" : "Server and client"} · {keyLabels[i.key_type] ?? i.key_type}</div></td>
                      <td className="small ca-sans">{i.sans.join(", ")}</td>
                      <td className="small">{i.ca_name}</td>
                      <td className="nowrap">{date(i.not_after)}{i.days_left >= 0 && i.status !== "revoked" && <div className="muted small">{i.days_left} days</div>}</td>
                      <td><span className={`pill ${statusTone[i.status] ?? ""}`}>{i.status === "expiring" ? "renew soon" : i.status}</span></td>
                      <td className="actions">
                        {i.inventory_id > 0 && <a className="link" href={`/api/certs/${i.inventory_id}/pem`} download={`${i.cert_name}.pem`}>PEM</a>}
                        {isAdmin && i.inventory_id > 0 && i.status !== "revoked" && <a className="link" href={`#/deploy?cert=${i.inventory_id}`}>Deploy</a>}
                        {isAdmin && !i.replaced_by && i.status !== "revoked" && <button className="link" onClick={() => setRenewing(i)}>Renew</button>}
                        {isAdmin && i.status !== "revoked" && i.status !== "expired" && <button className="link danger" onClick={() => setRevoking(i)}>Revoke</button>}
                      </td>
                    </tr>
                  ))}
                  {shown.length === 0 && <tr><td colSpan={6} className="muted">No certificates issued yet. {isAdmin && <button className="link" onClick={() => setIssuing(true)}>Issue one</button>}</td></tr>}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}

      {wizard && <CAWizard info={info} onClose={() => { setWizard(false); load(); }} />}
      {issuing && (
        <Modal title="New Certificate" wide onClose={() => { setIssuing(false); load(); }}>
          <IssuePanel info={info} onIssued={load} />
          <div className="modal-actions"><button onClick={() => { setIssuing(false); load(); }}>Close</button></div>
        </Modal>
      )}
      {renewing && <RenewDialog cert={renewing} onClose={(m) => { setRenewing(null); if (m) setNote(m); load(); }} />}
      {revoking && <RevokeDialog cert={revoking} reasons={info.reasons} onClose={(m) => { setRevoking(null); if (m) setNote(m); load(); }} />}
    </>
  );
}

// ---- authorities ----

function Downloads({ c }: { c: CA }) {
  const base = `/pki/ca/${c.id}`;
  return (
    <span className="ca-dl">
      <a className="button small-btn" href={`${base}.crt`} download title="DER: Windows, Android"><Icon name="download" size={14} /> .crt</a>
      <a className="button small-btn" href={`${base}.pem`} download title="PEM: Linux, apps, network gear"><Icon name="download" size={14} /> .pem</a>
      {c.root && <a className="button small-btn" href={`${base}.mobileconfig`} download title="iPhone, iPad, Mac"><Icon name="download" size={14} /> Apple profile</a>}
      <a className="button small-btn" href={`${base}.crl`} download title="Certificate revocation list"><Icon name="download" size={14} /> CRL</a>
    </span>
  );
}

function CACard({ c }: { c: CA }) {
  return (
    <div className={`ca-card ${c.root ? "" : "ca-sub"}`}>
      <div className="ca-card-head">
        <span className={`tile-icon ${c.root ? "c1" : "c3"}`}><Icon name={c.root ? "shield" : "cert"} size={17} /></span>
        <div className="grow-col">
          <div><strong>{c.name}</strong> <span className="pill">{c.root ? "Root" : "Intermediate"}</span>{c.issuing && <span className="pill good">signs new certificates</span>}</div>
          <div className="muted small">{c.subject}{c.parent ? ` · signed by ${c.parent}` : " · self-signed"}</div>
        </div>
      </div>
      <dl className="ca-facts">
        <div><dt>Valid until</dt><dd>{date(c.not_after)} <span className="muted small">({Math.round(c.days_left / 365 * 10) / 10} years)</span></dd></div>
        <div><dt>Key</dt><dd>{keyLabels[c.key_type] ?? c.key_type} <span className="muted small">in the vault</span></dd></div>
        <div><dt>Allowed names</dt><dd>{c.permitted_domains.length ? c.permitted_domains.join(", ") : <span className="muted">any</span>}</dd></div>
        <div><dt>Certificates</dt><dd>{c.active} valid{c.revoked ? `, ${c.revoked} revoked` : ""}</dd></div>
        <div className="span2"><dt>SHA-256 fingerprint</dt><dd className="mono small ca-fp">{colonFP(c.fingerprint)}</dd></div>
        {c.crl_url && <div className="span2"><dt>CRL address in its certificates</dt><dd className="mono small">{c.crl_url}</dd></div>}
      </dl>
      <Downloads c={c} />
    </div>
  );
}

function AddIntermediate({ root, keyTypes, onDone }: { root: CA; keyTypes: string[]; onDone: (msg: string) => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(root.name.replace(/Root CA$/i, "").trim() + " Issuing CA");
  const [years, setYears] = useState(5);
  const [kt, setKT] = useState(root.key_type);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  if (!open) return <p className="muted small">No intermediate yet: the root signs certificates directly. <button className="link" onClick={() => setOpen(true)}>Add an intermediate CA</button></p>;
  const save = async () => {
    setBusy(true); setErr("");
    try {
      const c = await api<CA>("POST", `/api/ca/${root.id}/intermediate`, { name, years, key_type: kt });
      onDone(`${c.name} created. New certificates are signed by it; the root's key can stay untouched.`);
    } catch (e) { setErr((e as Error).message); setBusy(false); }
  };
  return (
    <div className="subcard">
      <h3 style={{ marginTop: 0 }}>Add an intermediate CA</h3>
      <div className="row">
        <label>Name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label>Valid for (years)<input type="number" min={1} max={30} value={years} onChange={(e) => setYears(Number(e.target.value))} /></label>
        <label>Key type<select value={kt} onChange={(e) => setKT(e.target.value)}>{keyTypes.map((k) => <option key={k} value={k}>{keyLabels[k] ?? k}</option>)}</select></label>
      </div>
      {err && <div className="error block">{err}</div>}
      <div className="row"><button className="primary" disabled={busy} onClick={save}>{busy ? "Creating…" : "Create"}</button><button onClick={() => setOpen(false)}>Cancel</button></div>
    </div>
  );
}

// ---- trusting the root ----

function TrustGuide({ root, base, isAdmin }: { root: CA; base: string; isAdmin: boolean }) {
  const [plats, setPlats] = useState<TrustPlatform[]>([]);
  const [tab, setTab] = useState("windows");
  const [copied, setCopied] = useState("");
  useEffect(() => { api<TrustPlatform[]>("GET", `/api/ca/${root.id}/install`).then(setPlats).catch(() => {}); }, [root.id]);
  const p = plats.find((x) => x.id === tab) ?? plats[0];
  const copy = (t: string) => { navigator.clipboard?.writeText(t).then(() => { setCopied(t); setTimeout(() => setCopied(""), 1500); }).catch(() => {}); };
  const shareURL = `${base}/pki/ca/${root.id}-install.txt`;
  return (
    <section className="card">
      <div className="card-head">
        <h2><Icon name="check" size={16} /> Trust {root.name} on Your Network</h2>
        <a href={shareURL} target="_blank" rel="noreferrer">Instructions to share</a>
      </div>
      <p className="muted small">
        Each device needs the root certificate once. After that, every certificate this CA signs is accepted, including ones issued later.
        Check the fingerprint matches before trusting it: <span className="mono">{colonFP(root.fingerprint).slice(0, 23)}…</span>
      </p>
      <div className="seg ca-tabs" role="tablist" aria-label="Platform">
        {plats.map((x) => <button key={x.id} role="tab" aria-selected={p?.id === x.id} className={p?.id === x.id ? "on" : ""} onClick={() => setTab(x.id)}>{x.label}</button>)}
      </div>
      {p && (
        <div className="ca-guide">
          <ol>
            {p.steps.map((s, i) => <li key={i}>{s}</li>)}
          </ol>
          {p.commands?.map((c) => (
            <div key={c} className="ca-cmd">
              <code className="mono small">{c}</code>
              <button className="small-btn" onClick={() => copy(c)}>{copied === c ? "Copied" : "Copy"}</button>
            </div>
          ))}
          {p.pushable && isAdmin && (
            <div className="banner info-banner">
              <Icon name="upload" size={16} />
              <span>NCC can do this for you on servers it can log in to ({p.id === "windows" ? "WinRM" : "SSH"}): add a server of type <b>{p.id === "windows" ? "Windows trust store" : "Linux trust store"}</b> and deploy <b>{root.inventory_name}</b> to it.</span>
              {root.inventory_id > 0 && <a className="button small-btn" href={`#/deploy?cert=${root.inventory_id}`}>Push to servers</a>}
            </div>
          )}
          <div className="ca-dl-row"><Downloads c={root} /></div>
        </div>
      )}
    </section>
  );
}

// ---- issuing ----

const ipRe = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]*:[0-9a-fA-F:.]+)$/;

/** IssuePanel issues certificates: ticked DNS suggestions and/or typed names. Used by the
 *  wizard's "First certificates" step and by "New Certificate" any time later. */
export function IssuePanel({ info, onIssued }: { info: CAList; onIssued?: (r: IssueResult[]) => void }) {
  const [sugs, setSugs] = useState<CertSuggestion[] | null>(null);
  const [problems, setProblems] = useState<string[]>([]);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [showCovered, setShowCovered] = useState(false);
  const [manual, setManual] = useState("");
  const [mode, setMode] = useState<"each" | "one">("each");
  const [withIPs, setWithIPs] = useState(true);
  const [days, setDays] = useState(info.default_leaf_days);
  const [kt, setKT] = useState("rsa-2048");
  const [usage, setUsage] = useState("server");
  const issuing = info.cas.find((c) => c.issuing);
  const [caID, setCAID] = useState(issuing?.id ?? 0);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<IssueResult[]>([]);
  const [errs, setErrs] = useState<string[]>([]);

  const loadSugs = () => {
    setSugs(null);
    api<{ suggestions: CertSuggestion[]; problems: string[] }>("GET", "/api/ca/suggestions")
      .then((r) => { setSugs(r.suggestions); setProblems(r.problems); })
      .catch((e) => { setSugs([]); setProblems([(e as Error).message]); });
  };
  useEffect(loadSugs, []);

  const needs = (s: CertSuggestion) => !s.outside && (!s.covered_by || (s.covered_days ?? 0) <= 30);
  const visible = (sugs ?? []).filter((s) => showCovered || needs(s));
  const coveredCount = (sugs ?? []).filter((s) => !needs(s)).length;
  const zones = useMemo(() => [...new Set(visible.map((s) => s.zone))], [visible]);
  const toggle = (n: string) => { const next = new Set(picked); if (next.has(n)) next.delete(n); else next.add(n); setPicked(next); };

  const typed = manual.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
  const typedNames = typed.filter((x) => !ipRe.test(x));
  const typedIPs = typed.filter((x) => ipRe.test(x));

  type Req = { dns_names: string[]; ips: string[] };
  const requests = (): Req[] => {
    const sel = (sugs ?? []).filter((s) => picked.has(s.name));
    const out: Req[] = [];
    if (mode === "one") {
      const names = [...sel.map((s) => s.name), ...typedNames];
      const ips = [...(withIPs ? sel.flatMap((s) => s.ips) : []), ...typedIPs];
      if (names.length + ips.length) out.push({ dns_names: names, ips: [...new Set(ips)] });
      return out;
    }
    for (const s of sel) out.push({ dns_names: [s.name], ips: withIPs ? s.ips : [] });
    if (typedNames.length || typedIPs.length) out.push({ dns_names: typedNames, ips: typedIPs });
    return out;
  };
  const reqs = requests();

  const issue = async () => {
    setBusy(true); setErrs([]);
    const ok: IssueResult[] = [];
    const bad: string[] = [];
    for (const r of reqs) {
      try {
        ok.push(await api<IssueResult>("POST", "/api/ca/issue", { ...r, days, key_type: kt, usage, ca_id: caID }));
      } catch (e) {
        bad.push(`${r.dns_names[0] ?? r.ips[0]}: ${(e as Error).message}`);
      }
    }
    setDone([...done, ...ok]);
    setErrs(bad);
    setPicked(new Set());
    setManual("");
    setBusy(false);
    if (ok.length) { loadSugs(); onIssued?.(ok); }
  };

  return (
    <div className="issue-panel">
      {done.length > 0 && (
        <div className="ca-done">
          {done.map((r) => (
            <div key={r.issued.id} className="ca-done-row">
              <Icon name="check" size={15} />
              <span className="grow-col"><b>{r.cert.name}</b> <span className="muted small">{r.issued.sans.join(", ")} · until {date(r.issued.not_after)}</span>
                {r.notes.map((n) => <div key={n} className="muted small">{n}</div>)}</span>
              <a className="button small-btn" href={`#/deploy?cert=${r.cert.id}`}><Icon name="upload" size={14} /> Deploy</a>
            </div>
          ))}
        </div>
      )}
      {errs.map((e) => <div key={e} className="error block">{e}</div>)}

      <h3>From your DNS records</h3>
      {sugs === null ? <p className="muted small">Reading the zones on your DNS servers…</p> : (
        <>
          {problems.map((p) => <div key={p} className="warn-text small">{p}</div>)}
          {(sugs.length === 0) && <p className="muted small">No host names found. Add a DNS server under Settings, or type names below.</p>}
          {sugs.length > 0 && (
            <div className="sug-tools small">
              <span className="muted">{visible.filter(needs).length} name(s) without a certificate{coveredCount ? `, ${coveredCount} already covered or outside the CA's domains` : ""}.</span>
              <button className="link" onClick={() => setPicked(new Set(visible.filter((s) => needs(s) && s.kind === "host").map((s) => s.name)))}>Tick all hosts</button>
              {picked.size > 0 && <button className="link" onClick={() => setPicked(new Set())}>Clear</button>}
              {coveredCount > 0 && <button className="link" onClick={() => setShowCovered(!showCovered)}>{showCovered ? "Hide" : "Show"} covered</button>}
            </div>
          )}
          <div className="sug-list">
            {zones.map((z) => (
              <Fragment key={z}>
                <div className="sug-zone">{z || "other"}</div>
                {visible.filter((s) => s.zone === z).map((s) => {
                  const can = !s.outside;
                  return (
                    <label key={s.name} className={`sug ${can ? "" : "off"}`}>
                      <input type="checkbox" disabled={!can} checked={picked.has(s.name)} onChange={() => toggle(s.name)} />
                      <span className="grow-col">
                        <span className="mono">{s.name}</span>
                        <span className="muted small">
                          {s.kind === "wildcard" ? `covers ${s.hosts} names in ${s.zone} (one level only)` : s.alias ? `alias of ${s.alias}` : s.ips.join(", ")}
                          {s.server ? ` · ${s.server}` : ""}
                        </span>
                      </span>
                      {s.outside ? <span className="pill">outside CA domains</span>
                        : s.covered_by ? <span className={`pill ${(s.covered_days ?? 0) > 30 ? "good" : "warn"}`}>{s.covered_by} · {s.covered_days}d</span>
                        : s.kind === "wildcard" ? <span className="pill">wildcard</span> : null}
                    </label>
                  );
                })}
              </Fragment>
            ))}
          </div>
        </>
      )}

      <label>Other names or IP addresses
        <input value={manual} onChange={(e) => setManual(e.target.value)} placeholder="nas.home.arpa, 192.168.1.10" className="mono" />
        <span className="field-help">Separate with commas or spaces. A leading *. makes a wildcard (covers one level).</span>
      </label>

      <div className="row">
        <label>Certificates
          <select value={mode} onChange={(e) => setMode(e.target.value as "each" | "one")}>
            <option value="each">One per name</option>
            <option value="one">One with all names</option>
          </select>
        </label>
        <label>Valid for (days)<input type="number" min={1} max={info.max_leaf_days} value={days} onChange={(e) => setDays(Number(e.target.value))} /></label>
        <label>Key type<select value={kt} onChange={(e) => setKT(e.target.value)}>{info.key_types.map((k) => <option key={k} value={k}>{keyLabels[k] ?? k}</option>)}</select></label>
        <label>Use<select value={usage} onChange={(e) => setUsage(e.target.value)}>
          <option value="server">Server (HTTPS, TLS)</option><option value="client">Client</option><option value="server+client">Server and client</option>
        </select></label>
        {info.cas.length > 1 && (
          <label>Signed by<select value={caID} onChange={(e) => setCAID(Number(e.target.value))}>{info.cas.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}</select></label>
        )}
      </div>
      <label className="check block"><input type="checkbox" checked={withIPs} onChange={(e) => setWithIPs(e.target.checked)} /> Include the DNS records' IP addresses, so https://192.168.x.x works too</label>
      <p className="field-help">Up to {info.max_leaf_days} days: Apple devices refuse longer server certificates. RSA 2048 works with every device; pick ECDSA if everything on your network is recent.</p>
      <div className="row">
        <button className="primary" disabled={busy || reqs.length === 0} onClick={issue}>
          {busy ? "Issuing…" : reqs.length <= 1 ? "Issue Certificate" : `Issue ${reqs.length} Certificates`}
        </button>
      </div>
    </div>
  );
}

// ---- wizard ----

type WizStep = "root" | "intermediate" | "review" | "certs" | "trust";
const wizSteps: [WizStep, string][] = [["root", "Root CA"], ["intermediate", "Intermediate"], ["review", "Create"], ["certs", "First Certificates"], ["trust", "Trust & Deploy"]];

function CAWizard({ info, onClose }: { info: CAList; onClose: () => void }) {
  const [step, setStep] = useState<WizStep>("root");
  const [org, setOrg] = useState("");
  const [name, setName] = useState("Home Network Root CA");
  const [kt, setKT] = useState("rsa-4096");
  const [years, setYears] = useState(10);
  const [domains, setDomains] = useState("");
  const [zones, setZones] = useState<string[]>([]);
  const [withSub, setWithSub] = useState(true);
  const [subName, setSubName] = useState("");
  const [subYears, setSubYears] = useState(5);
  const [crl, setCRL] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [made, setMade] = useState<CAList | null>(null);
  const [issued, setIssued] = useState<IssueResult[]>([]);

  useEffect(() => {
    api<{ suggestions: CertSuggestion[] }>("GET", "/api/ca/suggestions")
      .then((r) => setZones([...new Set(r.suggestions.map((s) => s.zone).filter(Boolean))]))
      .catch(() => {});
  }, []);
  const sub = subName || name.replace(/\s*Root CA$/i, "").trim() + " Issuing CA";
  const domainList = domains.split(/[\s,;]+/).map((d) => d.trim()).filter(Boolean);
  const idx = wizSteps.findIndex(([s]) => s === step);

  const create = async () => {
    setBusy(true); setErr("");
    try {
      const r = await api<{ error?: string }>("POST", "/api/ca", {
        name, organization: org, key_type: kt, years, permitted_domains: domainList, publish_crl: crl,
        intermediate: withSub ? { name: sub, years: subYears, key_type: kt === "rsa-4096" ? "rsa-3072" : kt } : null,
      });
      if (r.error) setErr(r.error);
      setMade(await api<CAList>("GET", "/api/ca"));
      setStep("certs");
    } catch (e) {
      setErr((e as Error).message);
    }
    setBusy(false);
  };

  const root = made?.cas.find((c) => c.root);
  return (
    <Modal title="Create Internal CA" wide onClose={onClose}>
      <ol className="wiz-steps" aria-label="Steps">
        {wizSteps.map(([s, label], i) => <li key={s} className={i < idx ? "done" : i === idx ? "on" : ""}><span>{i < idx ? "✓" : i + 1}</span>{label}</li>)}
      </ol>

      {step === "root" && (
        <>
          <p className="muted small">The root is the certificate every device will trust. Keep it long-lived; it is only used to sign the intermediate (and to revoke).</p>
          <div className="row">
            <label>CA name<input value={name} onChange={(e) => setName(e.target.value)} /></label>
            <label>Organisation (optional)<input value={org} onChange={(e) => setOrg(e.target.value)} placeholder="Townsend Home" /></label>
          </div>
          <div className="row">
            <label>Key type<select value={kt} onChange={(e) => setKT(e.target.value)}>{info.key_types.map((k) => <option key={k} value={k}>{keyLabels[k] ?? k}</option>)}</select>
              <span className="field-help">RSA 4096 is trusted by every device, old ones included.</span></label>
            <label>Valid for (years)<input type="number" min={1} max={30} value={years} onChange={(e) => setYears(Number(e.target.value))} />
              <span className="field-help">10 years is usual. Every device has to trust a new root when it runs out.</span></label>
          </div>
          <label>Only allow these domains (optional)
            <input value={domains} onChange={(e) => setDomains(e.target.value)} placeholder="home.arpa, lan" className="mono" />
            <span className="field-help">Name constraints: the CA can then never sign for other names (google.com, your bank), even if its key leaked. Includes every name under each domain. Cannot be changed later.</span>
          </label>
          {zones.length > 0 && (
            <p className="small">Your DNS zones: {zones.map((z) => <code key={z} className="mono">{z} </code>)}
              <button className="link" onClick={() => setDomains(zones.join(", "))}>Use these</button></p>
          )}
          <label className="check block"><input type="checkbox" checked={crl} onChange={(e) => setCRL(e.target.checked)} /> Publish a revocation list address (CRL) in certificates</label>
          <p className="field-help">Points clients at {info.base}/pki/ca/…crl. Leave off unless every client can always reach NCC at this address: some Windows apps refuse certificates whose CRL they cannot fetch. Revoking works either way.</p>
        </>
      )}

      {step === "intermediate" && (
        <>
          <p className="muted small">An intermediate (issuing) CA signs your server certificates, so the root's key is used only once. If the intermediate is ever compromised, the root can replace it without touching your devices.</p>
          <label className="check block"><input type="checkbox" checked={withSub} onChange={(e) => setWithSub(e.target.checked)} /> Create an intermediate CA (recommended)</label>
          {withSub && (
            <div className="row">
              <label>Intermediate name<input value={sub} onChange={(e) => setSubName(e.target.value)} /></label>
              <label>Valid for (years)<input type="number" min={1} max={years} value={subYears} onChange={(e) => setSubYears(Number(e.target.value))} /></label>
            </div>
          )}
        </>
      )}

      {step === "review" && (
        <>
          <table className="compact">
            <tbody>
              <tr><th>Root CA</th><td>{name}{org ? `, ${org}` : ""} · {keyLabels[kt]} · {years} years</td></tr>
              <tr><th>Intermediate</th><td>{withSub ? `${sub} · ${keyLabels[kt === "rsa-4096" ? "rsa-3072" : kt]} · ${subYears} years` : "none (the root signs certificates)"}</td></tr>
              <tr><th>Allowed names</th><td>{domainList.length ? domainList.join(", ") : "any"}</td></tr>
              <tr><th>CRL address</th><td>{crl ? `${info.base}/pki/ca/…crl` : "not published"}</td></tr>
            </tbody>
          </table>
          <div className="banner info-banner"><Icon name="lock" size={16} /><span>The private keys are generated on the NCC server and go straight into the vault. NCC never shows, exports or downloads them; everything is in the audit log.</span></div>
          {err && <div className="error block">{err}</div>}
        </>
      )}

      {step === "certs" && made && (
        <>
          {err && <div className="warn-text block">{err}</div>}
          <div className="ok block"><Icon name="check" size={15} /> {made.cas.map((c) => c.name).join(" and ")} created.</div>
          <p className="muted small">Now issue certificates for your servers. Tick the names from your DNS, or type them. You can always add more later with New Certificate.</p>
          <IssuePanel info={made} onIssued={(r) => setIssued([...issued, ...r])} />
        </>
      )}

      {step === "trust" && root && (
        <>
          <p>Last step: make your devices trust <b>{root.name}</b>, then install the certificates.</p>
          <ol className="ca-howto">
            <li>Download the root: <Downloads c={root} /></li>
            <li>Install it on each device. The <b>Trust {root.name}</b> card on this page has instructions for Windows, Mac, iPhone, Android and Linux, and a link to share with others.</li>
            <li>For servers NCC can log in to, push it: <a href={`#/deploy?cert=${root.inventory_id}`} onClick={onClose}>add a Linux or Windows trust store server</a>.</li>
            {issued.length > 0 && <li>Deploy the new certificates: {issued.map((r) => <a key={r.cert.id} className="button small-btn" href={`#/deploy?cert=${r.cert.id}`} onClick={onClose}>{r.cert.name}</a>)}</li>}
          </ol>
        </>
      )}

      <div className="modal-actions">
        {(step === "intermediate" || step === "review") && <button onClick={() => setStep(wizSteps[idx - 1][0])} disabled={busy}>Back</button>}
        {step === "root" && <button className="primary" disabled={!name.trim() || years < 1} onClick={() => setStep("intermediate")}>Next</button>}
        {step === "intermediate" && <button className="primary" onClick={() => setStep("review")}>Next</button>}
        {step === "review" && <button className="primary" disabled={busy} onClick={create}>{busy ? "Creating keys…" : "Create CA"}</button>}
        {step === "certs" && <button className="primary" onClick={() => setStep("trust")}>{issued.length ? "Next" : "Skip for now"}</button>}
        {step === "trust" && <button className="primary" onClick={onClose}>Done</button>}
      </div>
    </Modal>
  );
}

// ---- renew and revoke ----

function RenewDialog({ cert, onClose }: { cert: IssuedCert; onClose: (msg?: string) => void }) {
  const [revoke, setRevoke] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try {
      const r = await api<IssueResult>("POST", `/api/ca/issued/${cert.id}/renew`, { revoke_old: revoke });
      onClose(`${r.cert.name} renewed until ${date(r.issued.not_after)}. Deploy it again to the servers that use it. ${r.notes.join(" ")}`);
    } catch (e) { setErr((e as Error).message); setBusy(false); }
  };
  return (
    <Modal title={`Renew ${cert.cert_name}`} onClose={() => onClose()}>
      <p>Signs a new certificate for <span className="mono">{cert.sans.join(", ")}</span>, valid {cert.days} days, with a new key. It replaces the old one in the certificate list, so servers set up for it get the new one on their next deploy.</p>
      <label className="check block"><input type="checkbox" checked={revoke} onChange={(e) => setRevoke(e.target.checked)} /> Also revoke the old certificate now</label>
      <p className="field-help">Leave this off until the new one is deployed everywhere.</p>
      {err && <div className="error block">{err}</div>}
      <div className="modal-actions"><button onClick={() => onClose()}>Cancel</button><button className="primary" disabled={busy} onClick={go}>{busy ? "Renewing…" : "Renew"}</button></div>
    </Modal>
  );
}

function RevokeDialog({ cert, reasons, onClose }: { cert: IssuedCert; reasons: Record<string, string>; onClose: (msg?: string) => void }) {
  const [reason, setReason] = useState(0);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try {
      await api("POST", `/api/ca/issued/${cert.id}/revoke`, { reason });
      onClose(`${cert.cert_name} (serial ${cert.serial.slice(0, 12)}…) is revoked and on ${cert.ca_name}'s CRL.`);
    } catch (e) { setErr((e as Error).message); setBusy(false); }
  };
  return (
    <Modal title={`Revoke ${cert.cert_name}`} onClose={() => onClose()}>
      <p>Adds this certificate to {cert.ca_name}'s revocation list. This cannot be undone. Clients that check the CRL will refuse it; servers still using it should get a renewed certificate first.</p>
      <label>Reason<select value={reason} onChange={(e) => setReason(Number(e.target.value))}>
        {Object.entries(reasons).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
      </select></label>
      {err && <div className="error block">{err}</div>}
      <div className="modal-actions"><button onClick={() => onClose()}>Cancel</button><button className="primary danger-fill" disabled={busy} onClick={go}>{busy ? "Revoking…" : "Revoke"}</button></div>
    </Modal>
  );
}
