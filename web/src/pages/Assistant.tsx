// AI assistant page: ask a model (through the person's own Claude, Copilot, Gemini or ChatGPT
// subscription, or a local Ollama model) for a plan for the whole network: which IoT devices
// to move to which VLAN, which DNS zones to create and which VLAN each serves. Every step is
// checked by NCC and shown with why; nothing changes until an admin picks steps and confirms.
// The providers section connects the accounts: NCC runs the vendor's own sign-in on the
// server and shows it here, and keeps the result in the vault. No API keys. An admin can also
// have NCC install a tool itself (from the official npm registry, into NCC's own data folder).
import { useCallback, useEffect, useMemo, useState } from "react";
import { AIInstall, AIInstallPlan, AIPlan, AIProvider, AISignIn, AIStep, api, User } from "../api";
import { ago } from "../format";
import { Icon, IconName } from "../icons";
import { Modal, PageHeader, PageLoading } from "../ui";
import { typeInfo } from "./IoT";

const TITLE = "AI Assistant";

interface Home { providers: AIProvider[]; plans: AIPlan[] }

const stepIcon: Record<AIStep["kind"], IconName> = { create_vlan: "vlan", move_clients: "client", create_zone: "dns", assign_zone: "link" };
const statusText: Record<AIPlan["status"], [string, "" | "good" | "warn" | "bad"]> = {
  proposed: ["Waiting for approval", "warn"], deploying: ["Deploying…", ""], deployed: ["Deployed", "good"],
  partial: ["Partly deployed", "warn"], failed: ["Deploy failed", "bad"], discarded: ["Discarded", ""],
};

export function Assistant({ tick, user }: { tick: number; user: User }) {
  const [home, setHome] = useState<Home | null>(null);
  const [err, setErr] = useState("");
  const [plan, setPlan] = useState<AIPlan | null>(null);
  const isAdmin = user.role === "admin";
  const canPlan = user.role !== "viewer";

  const refetch = useCallback(() => api<Home>("GET", "/api/assistant").then((h) => { setHome(h); setErr(""); }).catch((e) => setErr((e as Error).message)), []);
  useEffect(() => { refetch(); }, [tick, refetch]);
  // open the newest plan the first time
  useEffect(() => { if (home && !plan && home.plans[0]) setPlan(home.plans[0]); }, [home, plan]);

  // follow a deployment
  useEffect(() => {
    if (plan?.status !== "deploying") return;
    const t = setInterval(() => api<AIPlan>("GET", `/api/assistant/plans/${plan.id}`).then((p) => {
      setPlan(p);
      if (p.status !== "deploying") refetch();
    }).catch(() => {}), 1500);
    return () => clearInterval(t);
  }, [plan?.id, plan?.status, refetch]);

  if (!home) return <PageLoading title={TITLE} err={err} />;
  const ready = home.providers.filter((p) => p.enabled && p.connected && p.installed);

  return (
    <>
      <PageHeader title={TITLE} />
      <p className="muted lede ai-lede">
        The assistant looks at your whole network (VLANs, every client, the IoT inventory, port forwards and DNS zones) and proposes
        what to change. NCC checks each step against the network, and nothing is changed until an admin picks the steps and confirms.
      </p>
      {err && <div className="error block">{err}</div>}
      <div className="ai-layout">
        <div className="ai-main">
          {canPlan && <Ask ready={ready} onPlan={(p) => { setPlan(p); refetch(); }} />}
          {plan ? <PlanView key={plan.id} plan={plan} providers={home.providers} isAdmin={isAdmin} onChange={(p) => { setPlan(p); refetch(); }} />
            : <div className="card empty"><Icon name="sparkle" size={22} /><p>No plans yet. Ask for one above.</p></div>}
        </div>
        <div className="ai-side">
          <Providers providers={home.providers} isAdmin={isAdmin} onChange={refetch} />
          {home.plans.length > 0 && (
            <div className="card">
              <div className="card-head"><h2>Recent plans</h2></div>
              <ul className="plain ai-history">
                {home.plans.map((p) => (
                  <li key={p.id}>
                    <button className={`link ${plan?.id === p.id ? "on" : ""}`} onClick={() => setPlan(p)}>
                      {ago(p.created_at)} · {providerLabel(home.providers, p)}
                    </button>
                    <span className={`pill ${statusText[p.status][1]}`}>{statusText[p.status][0]}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </>
  );
}

function providerLabel(ps: AIProvider[], p: AIPlan) {
  if (p.source === "rules") return "NCC rules";
  return ps.find((x) => x.id === p.provider)?.label.replace(/ \(.*\)$/, "") ?? p.provider;
}

function Ask({ ready, onPlan }: { ready: AIProvider[]; onPlan: (p: AIPlan) => void }) {
  const [provider, setProvider] = useState(() => ready[0]?.id ?? "");
  const [goal, setGoal] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [showSent, setShowSent] = useState(false);
  useEffect(() => { if (provider && !ready.some((p) => p.id === provider)) setProvider(ready[0]?.id ?? ""); }, [ready, provider]);
  const label = ready.find((p) => p.id === provider)?.label ?? "NCC's rules";

  const ask = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      onPlan(await api<AIPlan>("POST", "/api/assistant/plans", { provider, goal }));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="card ai-ask" onSubmit={ask}>
      <div className="card-head"><h2><Icon name="sparkle" size={17} /> Ask for a plan</h2>
        <button type="button" className="link" onClick={() => setShowSent(true)}>What is sent?</button></div>
      <textarea rows={3} value={goal} onChange={(e) => setGoal(e.target.value)} maxLength={2000}
        placeholder="Optional: what you want, e.g. “Cameras and door controllers on their own VLAN, everything else IoT together, and DNS zones for each”. Leave empty for the usual: IoT devices on their own VLAN, internet-facing devices in a DMZ, a DNS zone per network." />
      <div className="row ai-ask-row">
        <label>Model
          <select value={provider} onChange={(e) => setProvider(e.target.value)}>
            {ready.map((p) => <option key={p.id} value={p.id}>{p.label}{p.model ? ` · ${p.model}` : ""}</option>)}
            <option value="">NCC's rules only (no AI)</option>
          </select>
        </label>
        <div className="grow" />
        <button className="primary" disabled={busy}>{busy ? <><span className="spin" /> Asking {label.replace(/ \(.*\)$/, "")}…</> : <><Icon name="sparkle" size={15} /> Make a plan</>}</button>
      </div>
      {ready.length === 0 && <p className="muted small">No AI provider is connected yet, so NCC's own rules make the plan. Connect one under AI providers.</p>}
      {busy && provider && <p className="muted small">Models can take a minute or two to think through a whole network.</p>}
      {err && <div className="error">{err}</div>}
      {showSent && <SentModal onClose={() => setShowSent(false)} />}
    </form>
  );
}

function SentModal({ onClose }: { onClose: () => void }) {
  const [data, setData] = useState<{ picture: unknown; size: string } | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => { api<{ picture: unknown; size: string }>("GET", "/api/assistant/picture").then(setData).catch((e) => setErr((e as Error).message)); }, []);
  return (
    <Modal title="What the model sees" onClose={onClose} wide>
      <p className="muted">With a plan request, NCC sends the model this summary of your network ({data?.size ?? "…"}), its rules and NCC's own
        rule-based plan. No passwords, keys or certificates are ever included. With "NCC's rules only", nothing leaves NCC.</p>
      {err && <div className="error">{err}</div>}
      {data && <pre className="step-out ai-json">{JSON.stringify(data.picture, null, 2)}</pre>}
    </Modal>
  );
}

function PlanView({ plan, providers, isAdmin, onChange }: { plan: AIPlan; providers: AIProvider[]; isAdmin: boolean; onChange: (p: AIPlan) => void }) {
  const open = plan.status === "proposed";
  const [picked, setPicked] = useState<Set<string>>(() => new Set(plan.steps.filter((s) => s.recommended && !s.problem).map((s) => s.id)));
  const [confirm, setConfirm] = useState(false);
  const [err, setErr] = useState("");
  const toggle = (id: string) => setPicked((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  // a step that needs a network created by another step can't go without it
  const needs = useMemo(() => {
    const m = new Map<string, string>();
    for (const s of plan.steps) {
      if (s.kind !== "create_vlan" && s.network_id?.startsWith("new:")) {
        const creator = plan.steps.find((c) => c.kind === "create_vlan" && c.network_id === s.network_id);
        if (creator) m.set(s.id, creator.id);
      }
    }
    return m;
  }, [plan.steps]);
  const missing = [...picked].filter((id) => needs.has(id) && !picked.has(needs.get(id)!));
  const chosen = plan.steps.filter((s) => picked.has(s.id));
  const [st, tone] = statusText[plan.status];

  const discard = async () => {
    try { onChange(await api<AIPlan>("POST", `/api/assistant/plans/${plan.id}/discard`)); } catch (e) { setErr((e as Error).message); }
  };
  return (
    <div className="card ai-plan">
      <div className="card-head">
        <h2>Plan</h2>
        <div className="row" style={{ margin: 0 }}>
          <span className="pill">{plan.source === "ai" ? <><Icon name="sparkle" size={12} /> {providerLabel(providers, plan)}{plan.model ? ` · ${plan.model}` : ""}</> : "NCC rules"}</span>
          <span className={`pill ${tone}`}>{st}</span>
        </div>
      </div>
      <p className="ai-summary">{plan.summary}</p>
      <p className="muted small">Made {ago(plan.created_at)} by {plan.created_by}{plan.goal ? <> for “{plan.goal}”</> : null}
        {plan.deployed_by && plan.status !== "proposed" ? <> · deployed by {plan.deployed_by}</> : null}</p>
      {plan.ai_error && (
        <div className="banner warn"><Icon name="alert" size={16} /><span>The model's answer could not be used, so this plan comes from NCC's rules. {plan.ai_error}</span></div>
      )}
      {plan.notes.length > 0 && <ul className="notes ai-notes">{plan.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>}

      {plan.steps.length === 0 ? (
        <div className="empty"><Icon name="check" size={22} /><p>Nothing to change.</p></div>
      ) : (
        <ol className="ai-steps">
          {plan.steps.map((s, i) => (
            <StepRow key={s.id} n={i + 1} step={s} open={open && isAdmin} picked={picked.has(s.id)} onToggle={() => toggle(s.id)}
              needsMissing={missing.includes(s.id)} />
          ))}
        </ol>
      )}

      {open && (
        <div className="ai-actions">
          {!isAdmin ? <span className="muted small">An admin approves and deploys plans.</span> : (
            <>
              {missing.length > 0 && <span className="error">Pick the steps that create the networks the other picked steps need.</span>}
              <div className="grow" />
              <button className="link" onClick={discard}>Discard plan</button>
              <button className="primary" disabled={chosen.length === 0 || missing.length > 0} onClick={() => setConfirm(true)}>
                <Icon name="upload" size={15} /> Review and deploy {chosen.length} step{chosen.length === 1 ? "" : "s"}
              </button>
            </>
          )}
        </div>
      )}
      {err && <div className="error">{err}</div>}
      {confirm && <ConfirmDeploy plan={plan} steps={chosen} onClose={() => setConfirm(false)} onDone={(p) => { setConfirm(false); onChange(p); }} />}
    </div>
  );
}

function StepRow({ n, step, open, picked, onToggle, needsMissing }: { n: number; step: AIStep; open: boolean; picked: boolean; onToggle: () => void; needsMissing: boolean }) {
  const r = step.result;
  const cls = r ? (r.state === "ok" ? "ok" : r.state) : step.problem ? "blocked" : picked || !open ? "" : "unpicked";
  return (
    <li className={`ai-step ${cls} ${needsMissing ? "needs" : ""}`}>
      <div className="ai-step-pick">
        {open ? (
          <input type="checkbox" checked={picked} disabled={!!step.problem} onChange={onToggle} aria-label={`Pick step ${n}: ${step.title}`} />
        ) : (
          <span className="step-mark">{r ? (r.state === "ok" ? "✓" : r.state === "failed" ? "!" : "–") : n}</span>
        )}
      </div>
      <div className="ai-step-body">
        <div className="ai-step-title"><Icon name={stepIcon[step.kind]} size={15} /> {step.title}
          {!step.recommended && !step.problem && !r && <span className="pill">Think first</span>}
        </div>
        <div className="ai-why">{step.why}</div>
        {step.network && (
          <div className="ai-facts small">
            <span>VLAN {step.network.vlan}</span><span>Gateway {step.network.gateway}</span>
            {step.network.dhcp_start && <span>DHCP {step.network.dhcp_start} – {step.network.dhcp_stop}</span>}
            <span>{step.network.isolated ? "Isolated from other networks" : "Can reach other networks"}</span>
            <span>{step.network.internet_access ? "Internet" : "No internet"}</span>
          </div>
        )}
        {step.clients && step.clients.length > 0 && (
          <div className="ai-clients">
            {step.clients.map((c) => (
              <span key={c.mac} className={`ai-client ${c.blocked ? "blocked" : ""}`} title={[c.mac, c.ip, c.via, c.blocked].filter(Boolean).join(" · ")}>
                <Icon name={(c.type && typeInfo[c.type]?.icon) || "client"} size={13} />
                <b>{c.name}</b>
                {c.from && <span className="muted">from {c.from}</span>}
                {c.along_with && <span className="muted">(shares its port)</span>}
                {c.blocked && <span className="danger">can't move</span>}
              </span>
            ))}
          </div>
        )}
        {step.clients?.some((c) => c.blocked) && (
          <ul className="notes small">{step.clients.filter((c) => c.blocked).map((c) => <li key={c.mac}><b>{c.name}</b>: {c.blocked}</li>)}</ul>
        )}
        {step.warnings.length > 0 && !r && <ul className="notes small warn-text">{step.warnings.map((w, i) => <li key={i}>{w}</li>)}</ul>}
        {step.problem && <div className="error small"><Icon name="alert" size={13} /> Can't be applied: {step.problem}</div>}
        {r && <div className={`small ${r.state === "ok" ? "ok" : r.state === "failed" ? "error" : "muted"}`}>{r.message}</div>}
      </div>
    </li>
  );
}

function ConfirmDeploy({ plan, steps, onClose, onDone }: { plan: AIPlan; steps: AIStep[]; onClose: () => void; onDone: (p: AIPlan) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const moves = steps.filter((s) => s.kind === "move_clients").reduce((n, s) => n + (s.clients?.filter((c) => !c.blocked).length ?? 0), 0);
  const deploy = async () => {
    setBusy(true);
    setErr("");
    try {
      onDone(await api<AIPlan>("POST", `/api/assistant/plans/${plan.id}/deploy`, { steps: steps.map((s) => s.id), confirm: true }));
    } catch (e) {
      setErr((e as Error).message);
      setBusy(false);
    }
  };
  return (
    <Modal title={`Deploy ${steps.length} step${steps.length === 1 ? "" : "s"}?`} onClose={onClose}>
      <p>NCC will make these changes now, in this order:</p>
      <ol className="ai-confirm">{steps.map((s) => <li key={s.id}>{s.title}</li>)}</ol>
      {moves > 0 && (
        <div className="banner warn"><Icon name="alert" size={16} />
          <span>{moves} device{moves === 1 ? "" : "s"} will drop off the network for a few seconds and come back with an address in the new network. Port forwards and firewall rules that name the old addresses are not changed.</span>
        </div>
      )}
      <p className="muted small">Every change is recorded in the audit log.</p>
      {err && <div className="error">{err}</div>}
      <div className="modal-actions">
        <button onClick={onClose}>Cancel</button>
        <button className="primary" disabled={busy} onClick={deploy}>{busy ? "Starting…" : "Deploy now"}</button>
      </div>
    </Modal>
  );
}

// ---- providers ----

function Providers({ providers, isAdmin, onChange }: { providers: AIProvider[]; isAdmin: boolean; onChange: () => void }) {
  const [signIn, setSignIn] = useState<AIProvider | null>(null);
  const [paste, setPaste] = useState<AIProvider | null>(null);
  const [install, setInstall] = useState<AIProvider | null>(null);
  return (
    <div className="card">
      <div className="card-head"><h2>AI providers</h2></div>
      <p className="muted small ai-prov-lede">Sign in with the subscription you already have. NCC runs each vendor's own tool on the NCC server and keeps the sign-in in the vault; no API keys.</p>
      <div className="ai-providers">
        {providers.map((p) => <ProviderCard key={p.id} p={p} isAdmin={isAdmin} onChange={onChange} onSignIn={() => setSignIn(p)} onPaste={() => setPaste(p)} onInstall={() => setInstall(p)} />)}
      </div>
      {signIn && <SignInModal p={signIn} onClose={() => { setSignIn(null); onChange(); }} />}
      {install && <InstallModal p={install} onClose={() => { setInstall(null); onChange(); }} />}
      {paste && <PasteModal p={paste} onClose={() => { setPaste(null); onChange(); }} />}
    </div>
  );
}

function ProviderCard({ p, isAdmin, onChange, onSignIn, onPaste, onInstall }: { p: AIProvider; isAdmin: boolean; onChange: () => void; onSignIn: () => void; onPaste: () => void; onInstall: () => void }) {
  const [model, setModel] = useState(p.model);
  const [address, setAddress] = useState(p.address);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [more, setMore] = useState(false);
  useEffect(() => { setModel(p.model); setAddress(p.address); }, [p.model, p.address]);
  const save = async (body: Record<string, unknown>) => {
    try { await api("PUT", `/api/assistant/providers/${p.id}`, body); onChange(); } catch (e) { setMsg({ ok: false, text: (e as Error).message }); }
  };
  const test = async () => {
    setBusy(true);
    setMsg(null);
    type TestResult = { ok: boolean; answer?: string; error?: string; seconds?: number };
    const r = await api<TestResult>("POST", `/api/assistant/providers/${p.id}/test`).catch((e): TestResult => ({ ok: false, error: (e as Error).message }));
    setMsg(r.ok ? { ok: true, text: `Answered “${r.answer}”${r.seconds ? ` in ${r.seconds.toFixed(1)} s` : ""}` } : { ok: false, text: r.error ?? "failed" });
    setBusy(false);
    onChange();
  };
  const signOut = async () => { await api("DELETE", `/api/assistant/providers/${p.id}/credentials`).catch(() => {}); onChange(); };
  const state = !p.installed ? ["Not installed", ""] : p.connected ? (p.http ? ["No sign-in needed", "good"] : ["Signed in", "good"]) : ["Not signed in", "warn"];
  return (
    <div className={`ai-prov ${p.enabled && p.connected && p.installed ? "on" : ""}`}>
      <div className="ai-prov-top">
        <div>
          <div className="ai-prov-name">{p.label}</div>
          <div className="muted small">{p.account}</div>
        </div>
        {isAdmin && (
          <label className="ai-switch" title={p.enabled ? "Switched on" : "Switched off"}>
            <input type="checkbox" checked={p.enabled} onChange={(e) => save({ enabled: e.target.checked })} aria-label={`Use ${p.label}`} />
          </label>
        )}
      </div>
      <div className="row ai-prov-state">
        <span className={`pill ${state[1]}`}>{state[0]}</span>
        {p.ncc_version && p.installed && <span className="muted small" title={p.path}>v{p.ncc_version}, installed by NCC</span>}
        {p.last_used && <span className="muted small">used {ago(p.last_used)}</span>}
      </div>
      {!p.installed && (p.can_install && isAdmin
        ? <div className="small muted">Not on the NCC server yet. NCC can install it for you.</div>
        : <div className="small muted">Install on the NCC server: <code>{p.install}</code></div>)}
      {p.last_error && p.installed && <div className="small error ellipsis" title={p.last_error}>{p.last_error}</div>}
      {isAdmin && (
        <div className="row ai-prov-actions">
          {!p.installed && p.can_install && <button className="small-btn primary" onClick={onInstall}><Icon name="download" size={14} /> Install</button>}
          {!p.http && p.installed && !p.connected && <button className="small-btn primary" onClick={onSignIn}>Sign in</button>}
          {!p.http && p.installed && !p.connected && p.paste && <button className="small-btn" onClick={onPaste}>Paste sign-in</button>}
          {p.connected && p.installed && <button className="small-btn" disabled={busy} onClick={test}>{busy ? <span className="spin" /> : null} Test</button>}
          {!p.http && p.connected && <button className="small-btn link" onClick={signOut}>Sign out</button>}
          <button className="small-btn link" onClick={() => setMore((m) => !m)}>{more ? "Less" : "Settings"}</button>
        </div>
      )}
      {more && isAdmin && (
        <div className="ai-prov-more">
          <label>Model <input value={model} placeholder={p.default_model || "the tool's default"} onChange={(e) => setModel(e.target.value)} onBlur={() => model !== p.model && save({ model })} /></label>
          {p.http && <label>Address <input value={address} onChange={(e) => setAddress(e.target.value)} onBlur={() => address !== p.address && save({ address })} /></label>}
          {p.note && <p className="small muted">{p.note}</p>}
          {p.installed && p.path && <p className="small muted">Using <code>{p.path}</code></p>}
          {p.installed && p.can_install && <button className="small-btn" onClick={onInstall}>{p.ncc_version ? "Update" : "Install NCC's own copy"}</button>}
        </div>
      )}
      {msg && <div className={`small ${msg.ok ? "ok" : "error"}`}>{msg.text}</div>}
    </div>
  );
}

function SignInModal({ p, onClose }: { p: AIProvider; onClose: () => void }) {
  const [s, setS] = useState<AISignIn | null>(null);
  const [err, setErr] = useState("");
  const [line, setLine] = useState("");
  useEffect(() => {
    let id = "";
    api<AISignIn>("POST", `/api/assistant/providers/${p.id}/signin`).then((v) => { id = v.id; setS(v); }).catch((e) => setErr((e as Error).message));
    return () => { if (id) api("DELETE", `/api/assistant/signin/${id}`).catch(() => {}); };
  }, [p.id]);
  useEffect(() => {
    if (!s || s.state !== "running") return;
    const t = setInterval(() => api<AISignIn>("GET", `/api/assistant/signin/${s.id}`).then(setS).catch(() => {}), 1000);
    return () => clearInterval(t);
  }, [s?.id, s?.state]);
  const send = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!s) return;
    try { setS(await api<AISignIn>("POST", `/api/assistant/signin/${s.id}/input`, { text: line })); setLine(""); } catch (e) { setErr((e as Error).message); }
  };
  const links = useMemo(() => [...new Set((s?.output ?? "").match(/https:\/\/[^\s"'<>]+/g) ?? [])], [s?.output]);
  return (
    <Modal title={`Sign in to ${p.label}`} onClose={onClose} wide>
      <p className="muted">{p.sign_in_help}</p>
      {p.note && <p className="small muted">{p.note}</p>}
      {err && <div className="error block">{err}</div>}
      {links.length > 0 && s?.state === "running" && (
        <div className="ai-links">{links.map((l) => <a key={l} className="button" href={l} target="_blank" rel="noreferrer noopener"><Icon name="link" size={14} /> Open {new URL(l).host}</a>)}</div>
      )}
      <pre className="ai-terminal" aria-live="polite">{s ? s.output || "Starting…" : "Starting…"}</pre>
      {s?.state === "running" && (
        <form className="row" onSubmit={send}>
          <input className="grow" value={line} onChange={(e) => setLine(e.target.value)} placeholder="Paste the code here, or type an answer" autoFocus autoComplete="off" />
          <button className="primary">Send</button>
        </form>
      )}
      {s?.state === "connected" && <div className="banner good"><Icon name="check" size={16} /> Signed in. The sign-in is in the vault.</div>}
      {s?.state === "failed" && <div className="banner bad"><Icon name="alert" size={16} /> {s.error}</div>}
      <div className="modal-actions"><button onClick={onClose}>{s?.state === "connected" ? "Done" : "Close"}</button></div>
    </Modal>
  );
}

// InstallModal shows exactly what NCC will run to install a tool, asks for confirmation, then
// shows the install as it runs and the version it checked at the end.
function InstallModal({ p, onClose }: { p: AIProvider; onClose: () => void }) {
  const [plan, setPlan] = useState<AIInstallPlan | null>(null);
  const [job, setJob] = useState<AIInstall | null>(null);
  const [err, setErr] = useState("");
  const [starting, setStarting] = useState(false);
  useEffect(() => {
    api<AIInstallPlan>("GET", `/api/assistant/providers/${p.id}/install`).then(setPlan).catch((e) => setErr((e as Error).message));
  }, [p.id]);
  useEffect(() => {
    if (!job || job.state !== "running") return;
    const t = setInterval(() => api<AIInstall>("GET", `/api/assistant/install/${job.id}`).then(setJob).catch(() => {}), 1000);
    return () => clearInterval(t);
  }, [job?.id, job?.state]);
  const start = async () => {
    setStarting(true);
    setErr("");
    try { setJob(await api<AIInstall>("POST", `/api/assistant/providers/${p.id}/install`, { confirm: true })); } catch (e) { setErr((e as Error).message); }
    setStarting(false);
  };
  const verb = plan?.installed ? "Update" : "Install";
  return (
    <Modal title={`${verb} ${p.label}`} onClose={onClose} wide>
      {!plan && !err && <p className="muted"><span className="spin" /> Checking the server…</p>}
      {err && <div className="error block">{err}</div>}
      {plan && !job && (plan.can_install ? (
        <>
          <p>
            NCC will install <code>{plan.package}</code> from the official npm registry into its own folder, <code>{plan.location}</code>,
            as the NCC service user. It needs no administrator rights and changes nothing else on the server.
            {plan.installed && <> Version {plan.installed} is installed now; this gets the latest.</>}
          </p>
          <p className="small muted">{plan.download_node ? "There is no Node.js 20 or newer on the server, so NCC first gets one: " : "Uses "}{plan.node}.</p>
          <div className="small muted">NCC will run exactly this:</div>
          <pre className="ai-terminal ai-commands">{plan.commands.map((c) => `$ ${c}`).join("\n")}</pre>
          {p.note && <p className="small muted">{p.note}</p>}
          <div className="modal-actions">
            <button onClick={onClose}>Cancel</button>
            <button className="primary" disabled={starting} onClick={start}>{starting ? <span className="spin" /> : null} {verb}</button>
          </div>
        </>
      ) : (
        <>
          <div className="banner warn"><Icon name="alert" size={16} /> {plan.problem}</div>
          <div className="modal-actions"><button onClick={onClose}>Close</button></div>
        </>
      ))}
      {job && (
        <>
          <pre className="ai-terminal" aria-live="polite">{job.output || "Starting…"}</pre>
          {job.state === "running" && <p className="small muted"><span className="spin" /> Installing. This can take a minute or two; you can close this and come back.</p>}
          {job.state === "done" && <div className="banner good"><Icon name="check" size={16} /> Installed and checked: {p.binary} {job.version}. Next, sign in.</div>}
          {job.state === "failed" && <div className="banner bad"><Icon name="alert" size={16} /> {job.error}</div>}
          <div className="modal-actions"><button onClick={onClose}>{job.state === "done" ? "Done" : "Close"}</button></div>
        </>
      )}
    </Modal>
  );
}

function PasteModal({ p, onClose }: { p: AIProvider; onClose: () => void }) {
  const [value, setValue] = useState("");
  const [err, setErr] = useState("");
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    try { await api("POST", `/api/assistant/providers/${p.id}/paste`, { value }); onClose(); } catch (e) { setErr((e as Error).message); }
  };
  return (
    <Modal title={`Paste a ${p.label} sign-in`} onClose={onClose}>
      <form onSubmit={save}>
        <p className="muted">{p.paste} It goes straight into the vault.</p>
        <textarea rows={4} value={value} onChange={(e) => setValue(e.target.value)} autoComplete="off" spellCheck={false} style={{ width: "100%" }} />
        {err && <div className="error">{err}</div>}
        <div className="modal-actions"><button type="button" onClick={onClose}>Cancel</button><button className="primary">Save</button></div>
      </form>
    </Modal>
  );
}
