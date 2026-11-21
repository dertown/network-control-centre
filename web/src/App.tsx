import { useCallback, useEffect, useState } from "react";
import { api, ApiError, setCSRF, User, VaultStatus } from "./api";
import { Dashboard } from "./pages/Dashboard";
import { Topology } from "./pages/Topology";
import { Devices } from "./pages/Devices";
import { VLANs } from "./pages/VLANs";
import { VirtualMachines } from "./pages/VirtualMachines";
import { DNS } from "./pages/DNS";
import { Traffic } from "./pages/Traffic";
import { Firewall } from "./pages/Firewall";
import { Vault } from "./pages/Vault";
import { Settings } from "./pages/Settings";
import { Audit } from "./pages/Audit";
import { Login, Setup } from "./pages/Auth";
import { useLive } from "./live";
import { Icon, IconName } from "./icons";

const pages = [
  { id: "dashboard", label: "Dashboard", icon: "dashboard", group: "Monitor" },
  { id: "topology", label: "Topology", icon: "topology", group: "Monitor" },
  { id: "devices", label: "Devices", icon: "devices", group: "Monitor" },
  { id: "vms", label: "Virtual machines", icon: "vm", group: "Monitor" },
  { id: "traffic", label: "Traffic", icon: "traffic", group: "Monitor" },
  { id: "firewall", label: "Firewall", icon: "firewall", group: "Monitor" },
  { id: "vlans", label: "VLANs", icon: "vlan", group: "Configure" },
  { id: "dns", label: "DNS", icon: "dns", group: "Services" },
  { id: "vault", label: "Vault & certificates", icon: "vault", group: "Services" },
  { id: "settings", label: "Settings", icon: "settings", group: "Administration" },
  { id: "audit", label: "Audit log", icon: "audit", group: "Administration", admin: true },
] as const;

type Theme = "system" | "light" | "dark";

function loadTheme(): Theme {
  try {
    const t = localStorage.getItem("ncc-theme");
    if (t === "light" || t === "dark") return t;
  } catch { /* storage blocked */ }
  return "system";
}

function applyTheme(t: Theme) {
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
  try { localStorage.setItem("ncc-theme", t); } catch { /* storage blocked */ }
  // let canvas-drawn views (topology) pick up the new colours
  window.dispatchEvent(new Event("ncc-theme"));
}

type PageId = (typeof pages)[number]["id"];

function currentPage(): PageId {
  const h = window.location.hash.replace("#/", "").split("?")[0];
  return (pages.find((p) => p.id === h)?.id ?? "dashboard") as PageId;
}

export default function App() {
  const [state, setState] = useState<"loading" | "setup" | "login" | "ready">("loading");
  const [user, setUser] = useState<User | null>(null);
  const [vault, setVault] = useState<VaultStatus | null>(null);
  const [page, setPage] = useState<PageId>(currentPage());
  const tick = useLive(state === "ready");
  const [theme, setTheme] = useState<Theme>(loadTheme);
  useEffect(() => applyTheme(theme), [theme]);

  const boot = useCallback(async () => {
    try {
      const me = await api<{ user: User; csrf: string }>("GET", "/api/me");
      setCSRF(me.csrf);
      setUser(me.user);
      setState("ready");
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        const s = await api<{ needs_admin: boolean }>("GET", "/api/setup");
        setState(s.needs_admin ? "setup" : "login");
      } else throw e;
    }
  }, []);

  useEffect(() => {
    boot();
    const onHash = () => setPage(currentPage());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [boot]);

  useEffect(() => {
    if (state === "ready") api<VaultStatus>("GET", "/api/vault/status").then(setVault).catch(() => {});
  }, [state, tick]);

  if (state === "loading") return <div className="center muted">Loading…</div>;
  if (state === "setup") return <Setup onDone={() => setState("login")} />;
  if (state === "login" || !user) return <Login onDone={boot} />;

  const logout = async () => {
    await api("POST", "/api/logout");
    setUser(null);
    setState("login");
  };

  const visible = pages.filter((p) => !("admin" in p) || user.role === "admin");
  const groups = [...new Set(visible.map((p) => p.group))];
  const current = pages.find((p) => p.id === page)!;

  return (
    <div className="shell">
      <nav className="side">
        <div className="brand">
          <span className="brand-mark"><Icon name="topology" size={19} /></span>
          <span><div className="brand-name">NCC</div><div className="brand-sub">Network Control Centre</div></span>
        </div>
        {groups.map((g) => (
          <div key={g}>
            <div className="nav-group">{g}</div>
            {visible.filter((p) => p.group === g).map((p) => (
              <a key={p.id} href={`#/${p.id}`} className={page === p.id ? "active" : ""} aria-current={page === p.id ? "page" : undefined}>
                <Icon name={p.icon as IconName} size={17} />{p.label}
              </a>
            ))}
          </div>
        ))}
        <div className="grow" />
        <div className="me">
          <span className="avatar" aria-hidden>{user.username.slice(0, 2)}</span>
          <div>
            <div className="me-name">{user.username}</div>
            <div className="muted small">{user.role}{user.mfa ? " · MFA on" : ""}</div>
          </div>
          <button className="iconbtn" onClick={logout} title="Log out" aria-label="Log out"><Icon name="logout" size={17} /></button>
        </div>
      </nav>
      <div className="content">
        <header className="topbar">
          <div className="crumbs"><Icon name={current.icon as IconName} size={15} /> {current.group} / <b>{current.label}</b></div>
          <div className="grow" />
          <span className="live" title="Updates arrive live from the server"><span className="live-dot" />Live</span>
          <div className="theme-switch" role="group" aria-label="Colour theme">
            {([["light", "sun"], ["system", "monitor"], ["dark", "moon"]] as const).map(([t, ic]) => (
              <button key={t} className={theme === t ? "on" : ""} onClick={() => setTheme(t)} title={`${t[0].toUpperCase()}${t.slice(1)} theme`} aria-pressed={theme === t}>
                <Icon name={ic} size={14} />
              </button>
            ))}
          </div>
        </header>
        <main>
          {vault && (vault.sealed || !vault.initialized) && (
            <SealedBanner status={vault} isAdmin={user.role === "admin"} onUnsealed={setVault} />
          )}
          {page === "dashboard" && <Dashboard tick={tick} />}
          {page === "topology" && <Topology tick={tick} />}
          {page === "devices" && <Devices tick={tick} />}
          {page === "vms" && <VirtualMachines tick={tick} user={user} />}
          {page === "traffic" && <Traffic tick={tick} />}
          {page === "firewall" && <Firewall tick={tick} />}
          {page === "vlans" && <VLANs tick={tick} user={user} />}
          {page === "dns" && <DNS user={user} />}
          {page === "vault" && <Vault user={user} vault={vault} onVault={setVault} />}
          {page === "settings" && <Settings user={user} tick={tick} />}
          {page === "audit" && <Audit />}
        </main>
      </div>
    </div>
  );
}

function SealedBanner({ status, isAdmin, onUnsealed }: { status: VaultStatus; isAdmin: boolean; onUnsealed: (v: VaultStatus) => void }) {
  const [pass, setPass] = useState("");
  const [err, setErr] = useState("");
  if (status.backend !== "local") {
    return <div className="banner warn">HashiCorp Vault is unavailable: {status.detail || "sealed"}. Device polling and DNS changes are paused.</div>;
  }
  const unseal = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      onUnsealed(await api<VaultStatus>("POST", "/api/vault/unseal", { passphrase: pass }));
      setPass("");
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <div className="banner warn">
      <Icon name="vault" size={16} /> <strong>The vault is sealed.</strong> Device polling and DNS changes need credentials from it.
      {isAdmin ? (
        <form className="inline" onSubmit={unseal}>
          <input type="password" placeholder="Vault passphrase" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" />
          <button>Unseal</button>
          {err && <span className="error">{err}</span>}
        </form>
      ) : (
        <span> Ask an admin to unseal it.</span>
      )}
    </div>
  );
}
