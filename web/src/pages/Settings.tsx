import { Fragment, useEffect, useState } from "react";
import { api, Target, User } from "../api";
import { ago } from "../live";

export type Kind = "unifi" | "powerdns" | "proxmox" | "vmware" | "homeassistant" | StorageKind;
export type StorageKind = "qnap" | "synology" | "smb" | "nfs" | "snmp";
const storageKinds: string[] = ["qnap", "synology", "smb", "nfs", "snmp"];
const snmpBlank = { snmp: "off", snmp_version: "2c", snmp_community: "", snmp_user: "", snmp_auth_proto: "SHA", snmp_auth_pass: "", snmp_priv_proto: "AES", snmp_priv_pass: "" };

const blank = {
  unifi: { name: "dream-router", address: "https://192.168.1.1", site: "default", auth: "password", username: "", password: "", api_key: "", tls: "pin" },
  powerdns: { name: "powerdns", address: "http://192.168.1.10:8081", server_id: "localhost", api_key: "", tls: "verify" },
  proxmox: { name: "proxmox", address: "https://192.168.1.10:8006", auth: "token", token_id: "ncc@pve!monitor", token_secret: "", username: "root@pam", password: "", tls: "pin" },
  vmware: { name: "vcenter", address: "https://vcenter.lan", username: "ncc@vsphere.local", password: "", tls: "pin" },
  qnap: { name: "qnap", address: "https://192.168.1.50", username: "", password: "", tls: "pin", ...snmpBlank },
  synology: { name: "synology", address: "https://192.168.1.60:5001", username: "", password: "", tls: "pin" },
  smb: { name: "fileserver", address: "192.168.1.70", username: "", password: "", domain: "" },
  nfs: { name: "nfs", address: "192.168.1.80" },
  snmp: { name: "nas-snmp", address: "192.168.1.50", ...snmpBlank, snmp: "on" },
  homeassistant: { name: "home-assistant", address: "http://192.168.1.40:8123", token: "", tls: "pin" },
};

const titles: Record<Kind, string> = {
  unifi: "Add UniFi console",
  powerdns: "Add PowerDNS server",
  proxmox: "Add Proxmox VE",
  vmware: "Add VMware vCenter or ESXi",
  qnap: "Add QNAP NAS",
  synology: "Add Synology NAS",
  smb: "Add SMB file server",
  nfs: "Add NFS server",
  snmp: "Add storage over SNMP",
  homeassistant: "Connect Home Assistant",
};

// snmpSecret is the SNMP part of a storage connection's vault secret.
function snmpSecret(f: Record<string, string>): Record<string, string> {
  if (f.snmp !== "on") return {};
  return f.snmp_version === "3"
    ? { snmp_user: f.snmp_user, snmp_auth_proto: f.snmp_auth_proto, snmp_auth_pass: f.snmp_auth_pass, snmp_priv_proto: f.snmp_priv_proto, snmp_priv_pass: f.snmp_priv_pass }
    : { snmp_community: f.snmp_community };
}

function storageSecret(kind: Kind, f: Record<string, string>): Record<string, string> {
  switch (kind) {
    case "qnap": return { username: f.username, password: f.password, ...snmpSecret(f) };
    case "synology": return { username: f.username, password: f.password };
    case "smb": return f.domain ? { username: f.username, password: f.password, domain: f.domain } : { username: f.username, password: f.password };
    case "snmp": return snmpSecret({ ...f, snmp: "on" });
  }
  return {};
}

function SNMPFields({ f, set, optional }: { f: Record<string, string>; set: (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => void; optional?: boolean }) {
  return (
    <>
      {optional && (
        <label className="check block"><input type="checkbox" checked={f.snmp === "on"} onChange={(e) => set("snmp")({ target: { value: e.target.checked ? "on" : "off" } } as React.ChangeEvent<HTMLInputElement>)} />
          Also read volume and RAID state over SNMP (QNAP's API doesn't report a degraded or rebuilding volume). Turn SNMP on in Control Panel → Network &amp; File Services → SNMP.</label>
      )}
      {f.snmp === "on" && (
        <div className="row">
          <label>SNMP version<select value={f.snmp_version} onChange={set("snmp_version")}><option value="2c">v2c (community)</option><option value="3">v3 (user)</option></select></label>
          {f.snmp_version === "3" ? (
            <>
              <label>User<input value={f.snmp_user} onChange={set("snmp_user")} autoComplete="off" /></label>
              <label>Auth<select value={f.snmp_auth_proto} onChange={set("snmp_auth_proto")}><option>SHA</option><option>SHA256</option><option>MD5</option></select></label>
              <label>Auth password<input type="password" value={f.snmp_auth_pass} onChange={set("snmp_auth_pass")} autoComplete="new-password" /></label>
              <label>Privacy<select value={f.snmp_priv_proto} onChange={set("snmp_priv_proto")}><option>AES</option><option>AES256</option><option>DES</option></select></label>
              <label>Privacy password<input type="password" value={f.snmp_priv_pass} onChange={set("snmp_priv_pass")} autoComplete="new-password" /></label>
            </>
          ) : (
            <label>Community<input type="password" value={f.snmp_community} onChange={set("snmp_community")} autoComplete="off" placeholder="not public" /></label>
          )}
        </div>
      )}
    </>
  );
}

export function Settings({ user, tick }: { user: User; tick: number }) {
  const isAdmin = user.role === "admin";
  const [targets, setTargets] = useState<Target[]>([]);
  const [adding, setAdding] = useState<Kind | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<number | null>(null);
  const [editing, setEditing] = useState<number | null>(null);

  const load = () => api<Target[]>("GET", "/api/targets").then(setTargets).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [tick]);

  const poll = async (t: Target) => {
    setErr("");
    setBusy(t.id);
    try {
      await api("POST", `/api/targets/${t.id}/poll`);
    } catch (e) {
      setErr(`${t.name}: ${(e as Error).message}`);
    }
    setBusy(null);
    load();
  };
  const toggle = async (t: Target) => { await api("PATCH", `/api/targets/${t.id}`, { enabled: !t.enabled }); load(); };
  const del = async (t: Target) => {
    if (!window.confirm(`Remove ${t.name} and its stored credentials?`)) return;
    await api("DELETE", `/api/targets/${t.id}`);
    load();
  };

  return (
    <>
      <h1>Settings</h1>
      {err && <div className="error block">{err}</div>}
      <section className="card">
        <h2>Connections</h2>
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Address</th><th>Last poll</th><th>Status</th><th /></tr></thead>
          <tbody>
            {targets.map((t) => (
              <Fragment key={t.id}>
              <tr>
                <td><strong>{t.name}</strong></td>
                <td>{t.kind}</td>
                <td className="mono small">{t.address}{t.options.tls_fingerprint && <div className="muted" title={t.options.tls_fingerprint}>cert pinned {t.options.tls_fingerprint.slice(0, 16)}…</div>}</td>
                <td>{ago(t.last_poll)}</td>
                <td>{!t.enabled ? <span className="pill">disabled</span> : t.last_error ? <span className="pill bad" title={t.last_error}>error</span> : !t.last_poll ? <span className="pill">not checked</span> : <span className="pill good">ok</span>}
                  {t.last_error && <div className="error small">{t.last_error}</div>}</td>
                <td className="actions">
                  {user.role !== "viewer" && <button className="link" disabled={busy === t.id} onClick={() => poll(t)}>{busy === t.id ? (t.category === "dns" ? "Checking…" : "Polling…") : (t.category === "dns" ? "Check now" : t.category === "hypervisor" || t.category === "storage" || t.category === "smarthome" ? "Refresh" : "Poll now")}</button>}
                  {isAdmin && <button className="link" onClick={() => setEditing(editing === t.id ? null : t.id)}>Edit</button>}
                  {isAdmin && <button className="link" onClick={() => toggle(t)}>{t.enabled ? "Disable" : "Enable"}</button>}
                  {isAdmin && <button className="link danger" onClick={() => del(t)}>Remove</button>}
                </td>
              </tr>
              {editing === t.id && (
                <tr className="detail"><td colSpan={6}><EditTarget t={t} onDone={() => { setEditing(null); load(); }} /></td></tr>
              )}
              </Fragment>
            ))}
            {targets.length === 0 && <tr><td colSpan={6} className="muted">No connections yet.</td></tr>}
          </tbody>
        </table>
        {isAdmin && !adding && (
          <div className="row">
            <button onClick={() => setAdding("unifi")}>Add UniFi console</button>
            <button onClick={() => setAdding("powerdns")}>Add PowerDNS server</button>
            <button onClick={() => setAdding("proxmox")}>Add Proxmox VE</button>
            <button onClick={() => setAdding("vmware")}>Add VMware</button>
            <button onClick={() => setAdding("qnap")}>Add QNAP</button>
            <button onClick={() => setAdding("synology")}>Add Synology</button>
            <button onClick={() => setAdding("smb")}>Add SMB server</button>
            <button onClick={() => setAdding("nfs")}>Add NFS server</button>
            <button onClick={() => setAdding("snmp")}>Add SNMP storage</button>
            <button onClick={() => setAdding("homeassistant")}>Add Home Assistant</button>
          </div>
        )}
        {adding && <AddTarget kind={adding} onDone={() => { setAdding(null); load(); }} />}
      </section>
      <ChangePassword />
      <MFA user={user} />
      {isAdmin && <Users me={user} />}
    </>
  );
}

export function AddTarget({ kind, onDone }: { kind: Kind; onDone: () => void }) {
  const [f, setF] = useState<Record<string, string>>({ ...blank[kind] });
  const [err, setErr] = useState("");
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    const body = storageKinds.includes(kind)
      ? {
          kind, category: "storage", name: f.name, address: f.address.trim(),
          options: kind === "qnap" || kind === "synology" ? { tls: f.tls, ...(kind === "qnap" && f.snmp === "on" ? { snmp: "on" } : {}) } : {},
          credentials: storageSecret(kind, f),
        }
      : kind === "homeassistant"
      ? {
          kind, category: "smarthome", name: f.name, address: f.address.trim(), options: { tls: f.tls },
          credentials: { token: f.token.trim() },
        }
      : kind === "unifi"
        ? {
            kind, category: "device", name: f.name, address: f.address,
            options: { site: f.site, tls: f.tls },
            credentials: f.auth === "apikey" ? { api_key: f.api_key } : { username: f.username, password: f.password },
          }
        : kind === "powerdns"
          ? {
              kind, category: "dns", name: f.name, address: f.address,
              options: { server_id: f.server_id, tls: f.tls }, credentials: { api_key: f.api_key },
            }
          : kind === "proxmox"
            ? {
                kind, category: "hypervisor", name: f.name, address: f.address, options: { tls: f.tls },
                credentials: f.auth === "token" ? { token_id: f.token_id, token_secret: f.token_secret } : { username: f.username, password: f.password },
              }
            : {
                kind, category: "hypervisor", name: f.name, address: f.address, options: { tls: f.tls },
                credentials: { username: f.username, password: f.password },
              };
    try {
      await api("POST", "/api/targets", body);
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
  };

  return (
    <form className="subcard" onSubmit={save}>
      <h3>{titles[kind]}</h3>
      {kind === "unifi" && (
        <p className="muted small">
          For a Dream Router 7, use its LAN address and a <strong>local</strong> admin account (UniFi OS → Admins → add a local-access-only
          user with a Network role of View Only). View Only is enough: NCC only reads. Its self-signed certificate is pinned on first connection.
        </p>
      )}
      {kind === "homeassistant" && (
        <p className="muted small">
          Use the address you open Home Assistant at (usually port 8123). In Home Assistant open your profile → <strong>Security</strong> →{" "}
          <strong>Long-lived access tokens</strong> → Create token, and paste it here. Use an administrator's token so NCC can read rooms and
          pair Matter devices. The token is kept in the vault; an HTTPS certificate is pinned on first connection.
        </p>
      )}
      {kind === "powerdns" && (
        <p className="muted small">Use the address of the PowerDNS webserver (<code>webserver-address</code>/<code>webserver-port</code>) and the <code>api-key</code> from pdns.conf.</p>
      )}
      {kind === "proxmox" && (
        <p className="muted small">
          Use any node's address on port 8006; in a cluster one node lists every VM. NCC only reads, so a read-only API token is best. On a
          node shell: <code>pveum user add ncc@pve</code>, <code>pveum acl modify / --users ncc@pve --roles PVEAuditor</code>, then{" "}
          <code>pveum user token add ncc@pve monitor --privsep 0</code> and paste the secret it prints. Guest IP addresses also need the QEMU
          guest agent in each VM. The token is stored in the vault and the node's self-signed certificate is pinned on first connection.
        </p>
      )}
      {kind === "vmware" && (
        <p className="muted small">
          Use your vCenter Server address, or a standalone ESXi host's address. A user with the <strong>Read-only</strong> role is enough
          (vCenter: <code>ncc@vsphere.local</code>; ESXi: a local user). Guest IP addresses come from VMware Tools. The password is stored in
          the vault and the self-signed certificate is pinned on first connection.
        </p>
      )}
      {kind === "qnap" && (
        <p className="muted small">
          Use the NAS address as you open it in a browser (QTS 5 serves HTTPS on 443; older firmware uses http://…:8080). Sign in with an
          <strong> administrator</strong> account without two-step verification; QTS only answers health and SMART calls for admins, so a
          dedicated <code>ncc</code> admin user is best. Works with QTS and QuTS hero. The password goes in the vault and the NAS certificate
          is pinned on first connection.
        </p>
      )}
      {kind === "synology" && (
        <p className="muted small">
          Use the DSM address (HTTPS is port 5001). Make a DSM user for NCC in the <strong>administrators</strong> group without two-factor
          sign-in. NCC reads pools, volumes, disks, shares and Btrfs snapshots, and can create shares and snapshots, and restart or shut
          down the NAS when you ask. The password goes in the vault.
        </p>
      )}
      {kind === "smb" && (
        <p className="muted small">
          Any SMB 2/3 server: Windows, Samba, a NAS without an API driver or a router's USB share. NCC signs in, lists the shares and reads
          each one's size and free space. A read-only account is enough to monitor; creating folders needs write access.
        </p>
      )}
      {kind === "nfs" && (
        <p className="muted small">NCC asks the server's portmapper and mountd for its NFS versions and export list (like <code>showmount -e</code>). No login is needed and nothing is mounted.</p>
      )}
      {kind === "snmp" && (
        <p className="muted small">
          For storage NCC has no API driver for (TrueNAS, Unraid, ASUSTOR…) or when you'd rather not give NCC an admin login. QNAP's and
          Synology's own MIBs give disk temperatures, SMART and RAID state; other devices show their file systems. Read only.
        </p>
      )}
      <div className="row">
        <label>Name<input value={f.name} onChange={set("name")} /></label>
        <label>Address<input value={f.address} onChange={set("address")} /></label>
      </div>
      {(kind === "qnap" || kind === "synology" || kind === "smb") && (
        <div className="row">
          <label>Username<input value={f.username} onChange={set("username")} autoComplete="off" /></label>
          <label>Password<input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" /></label>
          {kind === "smb" && <label>Domain (optional)<input value={f.domain} onChange={set("domain")} autoComplete="off" placeholder="WORKGROUP" /></label>}
          {kind !== "smb" && <label>Certificate<select value={f.tls} onChange={set("tls")}><option value="pin">Pin on first use (self-signed)</option><option value="verify">Verify with trusted CAs</option></select></label>}
        </div>
      )}
      {kind === "qnap" && <SNMPFields f={f} set={set} optional />}
      {kind === "snmp" && <SNMPFields f={f} set={set} />}
      {kind === "unifi" && (
        <>
          <div className="row">
            <label>Site<input value={f.site} onChange={set("site")} /></label>
            <label>Sign in with<select value={f.auth} onChange={set("auth")}><option value="password">Local username + password</option><option value="apikey">API key</option></select></label>
            <label>Certificate<select value={f.tls} onChange={set("tls")}><option value="pin">Pin on first use (self-signed)</option><option value="verify">Verify with trusted CAs</option></select></label>
          </div>
          {f.auth === "apikey" ? (
            <label>API key<input type="password" value={f.api_key} onChange={set("api_key")} autoComplete="off" /></label>
          ) : (
            <div className="row">
              <label>Username<input value={f.username} onChange={set("username")} autoComplete="off" /></label>
              <label>Password<input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" /></label>
            </div>
          )}
        </>
      )}
      {kind === "homeassistant" && (
        <div className="row">
          <label>Access token<input type="password" value={f.token} onChange={set("token")} autoComplete="off" required /></label>
          <label>Certificate (HTTPS only)<select value={f.tls} onChange={set("tls")}><option value="pin">Pin on first use (self-signed)</option><option value="verify">Verify with trusted CAs</option></select></label>
        </div>
      )}
      {kind === "powerdns" && (
        <div className="row">
          <label>Server id<input value={f.server_id} onChange={set("server_id")} /></label>
          <label>API key<input type="password" value={f.api_key} onChange={set("api_key")} autoComplete="off" /></label>
          <label>Certificate (HTTPS only)<select value={f.tls} onChange={set("tls")}><option value="verify">Verify with trusted CAs</option><option value="pin">Pin on first use</option></select></label>
        </div>
      )}
      {kind === "proxmox" && (
        <>
          <div className="row">
            <label>Sign in with<select value={f.auth} onChange={set("auth")}><option value="token">API token (recommended)</option><option value="password">Username + password</option></select></label>
            <label>Certificate<select value={f.tls} onChange={set("tls")}><option value="pin">Pin on first use (self-signed)</option><option value="verify">Verify with trusted CAs</option></select></label>
          </div>
          {f.auth === "token" ? (
            <div className="row">
              <label>Token id<input value={f.token_id} onChange={set("token_id")} autoComplete="off" placeholder="ncc@pve!monitor" /></label>
              <label>Token secret<input type="password" value={f.token_secret} onChange={set("token_secret")} autoComplete="off" /></label>
            </div>
          ) : (
            <div className="row">
              <label>Username<input value={f.username} onChange={set("username")} autoComplete="off" placeholder="root@pam" /></label>
              <label>Password<input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" /></label>
            </div>
          )}
        </>
      )}
      {kind === "vmware" && (
        <div className="row">
          <label>Username<input value={f.username} onChange={set("username")} autoComplete="off" /></label>
          <label>Password<input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" /></label>
          <label>Certificate<select value={f.tls} onChange={set("tls")}><option value="pin">Pin on first use (self-signed)</option><option value="verify">Verify with trusted CAs</option></select></label>
        </div>
      )}
      {err && <div className="error">{err}</div>}
      <div className="row">
        <button className="primary">Save</button>
        <button type="button" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}

// EditTarget changes a saved connection's address, certificate setting and, optionally, its login.
export function EditTarget({ t, onDone }: { t: Target; onDone: () => void }) {
  const kind = t.kind as Kind;
  const [f, setF] = useState<Record<string, string>>({
    address: t.address, tls: t.options.tls || (kind === "powerdns" ? "verify" : "pin"), site: t.options.site ?? "default",
    server_id: t.options.server_id ?? "localhost", auth: kind === "proxmox" ? "token" : "password",
    username: "", password: "", api_key: "", token_id: "", token_secret: "", domain: "", token: "",
    ...snmpBlank, snmp: kind === "snmp" || t.options.snmp === "on" ? "on" : "off",
  });
  const isStorage = storageKinds.includes(kind);
  const hasTLS = !isStorage || kind === "qnap" || kind === "synology";
  const [repin, setRepin] = useState(false);
  const [creds, setCreds] = useState(false);
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);
  const set = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setF({ ...f, [k]: e.target.value });

  const secret = (): Record<string, string> | null => {
    switch (kind) {
      case "unifi": return f.auth === "apikey" ? { api_key: f.api_key } : { username: f.username, password: f.password };
      case "powerdns": return { api_key: f.api_key };
      case "proxmox": return f.auth === "token" ? { token_id: f.token_id.trim(), token_secret: f.token_secret.trim() } : { username: f.username, password: f.password };
      case "vmware": return { username: f.username, password: f.password };
      case "nfs": return null;
      case "homeassistant": return { token: f.token.trim() };
      case "qnap": case "synology": case "smb": case "snmp": return storageSecret(kind, f);
    }
    return null;
  };

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    const options: Record<string, string> = hasTLS ? { ...t.options, tls: f.tls } : { ...t.options };
    if (kind === "qnap" && creds) { if (f.snmp === "on") options.snmp = "on"; else delete options.snmp; }
    if (kind === "unifi") options.site = f.site;
    if (kind === "powerdns") options.server_id = f.server_id;
    if (repin || f.tls !== (t.options.tls || "") || f.address !== t.address) delete options.tls_fingerprint;
    const s = creds ? secret() : null;
    if (s && Object.entries(s).some(([k, v]) => !v && k !== "domain")) {
      setErr("Fill in every login field, or untick \"Change login\" to keep the saved one.");
      return;
    }
    setSaving(true);
    try {
      await api("PATCH", `/api/targets/${t.id}`, { address: f.address.trim(), options });
      if (s) await api("PUT", `/api/targets/${t.id}/credentials`, s);
      await api("POST", `/api/targets/${t.id}/poll`).catch((e) => { throw new Error(`Saved, but the check failed: ${(e as Error).message}`); });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
    setSaving(false);
  };

  return (
    <form className="subcard" onSubmit={save}>
      <h3>Edit {t.name}</h3>
      <div className="row">
        <label>Address<input value={f.address} onChange={set("address")} required /></label>
        {kind === "unifi" && <label>Site<input value={f.site} onChange={set("site")} /></label>}
        {kind === "powerdns" && <label>Server id<input value={f.server_id} onChange={set("server_id")} /></label>}
        {hasTLS && <label>Certificate<select value={f.tls} onChange={set("tls")}><option value="pin">Pin on first use (self-signed)</option><option value="verify">Verify with trusted CAs</option></select></label>}
      </div>
      {t.options.tls_fingerprint && f.tls === "pin" && (
        <label className="check block"><input type="checkbox" checked={repin} onChange={(e) => setRepin(e.target.checked)} />
          Forget the pinned certificate ({t.options.tls_fingerprint.slice(0, 16)}…) and pin the one the server shows next. Use this after replacing its certificate.</label>
      )}
      {kind !== "nfs" && <label className="check block"><input type="checkbox" checked={creds} onChange={(e) => setCreds(e.target.checked)} /> Change login (the saved one stays in the vault until you save)</label>}
      {creds && isStorage && (
        <>
          {kind !== "snmp" && (
            <div className="row">
              <label>Username<input value={f.username} onChange={set("username")} autoComplete="off" /></label>
              <label>Password<input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" /></label>
              {kind === "smb" && <label>Domain (optional)<input value={f.domain} onChange={set("domain")} autoComplete="off" /></label>}
            </div>
          )}
          {kind === "qnap" && <SNMPFields f={f} set={set} optional />}
          {kind === "snmp" && <SNMPFields f={f} set={set} />}
        </>
      )}
      {creds && !isStorage && (
        <>
          {(kind === "unifi" || kind === "proxmox") && (
            <div className="row">
              <label>Sign in with<select value={f.auth} onChange={set("auth")}>
                {kind === "unifi" ? <><option value="password">Local username + password</option><option value="apikey">API key</option></>
                  : <><option value="token">API token</option><option value="password">Username + password</option></>}
              </select></label>
            </div>
          )}
          {kind === "proxmox" && f.auth === "token" ? (
            <div className="row">
              <label>Token id<input value={f.token_id} onChange={set("token_id")} placeholder="root@pam!ncc" autoComplete="off" /></label>
              <label>Token secret<input type="password" value={f.token_secret} onChange={set("token_secret")} autoComplete="off" /></label>
            </div>
          ) : kind === "homeassistant" ? (
            <label>Long-lived access token<input type="password" value={f.token} onChange={set("token")} autoComplete="off" /></label>
          ) : kind === "powerdns" || (kind === "unifi" && f.auth === "apikey") ? (
            <label>API key<input type="password" value={f.api_key} onChange={set("api_key")} autoComplete="off" /></label>
          ) : (
            <div className="row">
              <label>Username<input value={f.username} onChange={set("username")} autoComplete="off" /></label>
              <label>Password<input type="password" value={f.password} onChange={set("password")} autoComplete="new-password" /></label>
            </div>
          )}
        </>
      )}
      {err && <div className="error block">{err}</div>}
      <div className="row">
        <button className="primary" disabled={saving}>{saving ? "Saving and checking…" : "Save and check"}</button>
        <button type="button" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}

function ChangePassword() {
  const empty = { current: "", next: "", confirm: "" };
  const [f, setF] = useState(empty);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const set = (k: keyof typeof empty) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });
  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    setMsg("");
    if (f.next !== f.confirm) {
      setErr("The new passwords do not match.");
      return;
    }
    try {
      await api("POST", "/api/me/password", { current_password: f.current, new_password: f.next });
      setF(empty);
      setMsg("Password changed. Any other browsers signed in as you have been logged out.");
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <section className="card">
      <h2>Change my password</h2>
      <form onSubmit={save}>
        <div className="row">
          <label>Current password<input type="password" value={f.current} onChange={set("current")} autoComplete="current-password" required /></label>
          <label>New password (12+)<input type="password" value={f.next} onChange={set("next")} autoComplete="new-password" minLength={12} required /></label>
          <label>Confirm new password<input type="password" value={f.confirm} onChange={set("confirm")} autoComplete="new-password" minLength={12} required /></label>
        </div>
        <button className="primary">Change password</button>
      </form>
      {err && <div className="error">{err}</div>}
      {msg && <p className="small">{msg}</p>}
    </section>
  );
}

function MFA({ user }: { user: User }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [msg, setMsg] = useState("");
  const start = async () => setSetup(await api("POST", "/api/me/mfa/start"));
  const confirm = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api("POST", "/api/me/mfa/confirm", { secret: setup!.secret, code });
      setSetup(null);
      setMsg("MFA is on. You will need a code from your authenticator app at your next login.");
    } catch (e) {
      setMsg((e as Error).message);
    }
  };
  return (
    <section className="card">
      <h2>Two-factor sign-in</h2>
      {user.mfa && !setup ? (
        <p>MFA is on for your account.</p>
      ) : setup ? (
        <form onSubmit={confirm}>
          <p>Add this key to an authenticator app (1Password, Google Authenticator, Authy…), then enter the 6-digit code it shows.</p>
          <p className="mono">{setup.secret.match(/.{1,4}/g)?.join(" ")}</p>
          <p className="muted small mono wrap">{setup.uri}</p>
          <div className="row"><input inputMode="numeric" placeholder="123456" value={code} onChange={(e) => setCode(e.target.value)} /><button className="primary">Turn on MFA</button></div>
        </form>
      ) : (
        <button onClick={start}>Set up an authenticator app</button>
      )}
      {msg && <p className="small">{msg}</p>}
    </section>
  );
}

function Users({ me }: { me: User }) {
  const [users, setUsers] = useState<User[]>([]);
  const [f, setF] = useState({ username: "", password: "", role: "viewer" });
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [resetting, setResetting] = useState<User | null>(null);
  const [newPw, setNewPw] = useState("");
  const load = () => api<User[]>("GET", "/api/users").then(setUsers).catch(() => {});
  useEffect(() => { load(); }, []);
  const add = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    try {
      await api("POST", "/api/users", f);
      setF({ username: "", password: "", role: "viewer" });
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const reset = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetting) return;
    setErr("");
    setMsg("");
    try {
      await api("PUT", `/api/users/${resetting.id}/password`, { password: newPw });
      setMsg(`Password for ${resetting.username} was reset and they were logged out everywhere.`);
      setResetting(null);
      setNewPw("");
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  const del = async (u: User) => {
    if (!window.confirm(`Delete the user ${u.username}? They will be logged out and cannot sign in again.`)) return;
    setErr("");
    setMsg("");
    try {
      await api("DELETE", `/api/users/${u.id}`);
      setMsg(`Deleted ${u.username}.`);
      load();
    } catch (e) {
      setErr((e as Error).message);
    }
  };
  return (
    <section className="card">
      <h2>Users</h2>
      <table>
        <thead><tr><th>Username</th><th>Role</th><th>MFA</th><th /></tr></thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.id}>
              <td>{u.username}{u.id === me.id && <span className="muted small"> (you)</span>}</td>
              <td>{u.role}</td>
              <td>{u.mfa ? "on" : "off"}</td>
              <td className="actions">
                {u.id !== me.id && <button className="link" onClick={() => { setResetting(u); setNewPw(""); }}>Reset password</button>}
                {u.id !== me.id && <button className="link danger" onClick={() => del(u)}>Delete</button>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {resetting && (
        <form className="subcard" onSubmit={reset}>
          <h3>Reset password for {resetting.username}</h3>
          <p className="muted small">They will be logged out of every browser and must sign in with the new password.</p>
          <div className="row">
            <input type="password" placeholder="new password (12+)" value={newPw} onChange={(e) => setNewPw(e.target.value)} autoComplete="new-password" minLength={12} required />
            <button className="primary">Set password</button>
            <button type="button" onClick={() => setResetting(null)}>Cancel</button>
          </div>
        </form>
      )}
      <form className="row" onSubmit={add}>
        <input placeholder="username" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} />
        <input type="password" placeholder="password (12+)" value={f.password} onChange={(e) => setF({ ...f, password: e.target.value })} autoComplete="new-password" />
        <select value={f.role} onChange={(e) => setF({ ...f, role: e.target.value })}>
          <option value="viewer">viewer: read only</option>
          <option value="operator">operator: DNS changes</option>
          <option value="admin">admin: everything</option>
        </select>
        <button>Add user</button>
      </form>
      {err && <div className="error">{err}</div>}
      {msg && <p className="small">{msg}</p>}
    </section>
  );
}
