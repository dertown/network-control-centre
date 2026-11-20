import { useCallback, useEffect, useState } from "react";
import { api, ApiError, setCSRF, User, VaultStatus } from "./api";
import { Dashboard } from "./pages/Dashboard";
import { Topology } from "./pages/Topology";
import { Devices } from "./pages/Devices";
import { DNS } from "./pages/DNS";
import { Traffic } from "./pages/Traffic";
import { Vault } from "./pages/Vault";
import { Settings } from "./pages/Settings";
import { Audit } from "./pages/Audit";
import { Login, Setup } from "./pages/Auth";
import { useLive } from "./live";

const pages = [
  { id: "dashboard", label: "Dashboard" },
  { id: "topology", label: "Topology" },
  { id: "devices", label: "Devices" },
  { id: "traffic", label: "Traffic" },
  { id: "dns", label: "DNS" },
  { id: "vault", label: "Vault & certificates" },
  { id: "settings", label: "Settings" },
  { id: "audit", label: "Audit log", admin: true },
] as const;

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

  return (
    <div className="shell">
      <nav className="side">
        <div className="brand">
          <span className="logo" aria-hidden>◎</span> NCC
        </div>
        {pages
          .filter((p) => !("admin" in p) || user.role === "admin")
          .map((p) => (
            <a key={p.id} href={`#/${p.id}`} className={page === p.id ? "active" : ""}>
              {p.label}
            </a>
          ))}
        <div className="grow" />
        <div className="me">
          <div>{user.username}</div>
          <div className="muted small">{user.role}{user.mfa ? " · MFA on" : ""}</div>
          <button className="link" onClick={logout}>Log out</button>
        </div>
      </nav>
      <main>
        {vault && (vault.sealed || !vault.initialized) && (
          <SealedBanner status={vault} isAdmin={user.role === "admin"} onUnsealed={setVault} />
        )}
        {page === "dashboard" && <Dashboard tick={tick} />}
        {page === "topology" && <Topology tick={tick} />}
        {page === "devices" && <Devices tick={tick} />}
        {page === "traffic" && <Traffic tick={tick} />}
        {page === "dns" && <DNS user={user} />}
        {page === "vault" && <Vault user={user} vault={vault} onVault={setVault} />}
        {page === "settings" && <Settings user={user} tick={tick} />}
        {page === "audit" && <Audit />}
      </main>
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
      <strong>The vault is sealed.</strong> Device polling and DNS changes need credentials from it.
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
