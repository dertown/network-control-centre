// The Add connection wizard and the connection forms. Every kind of connection (UniFi, PowerDNS,
// BIND, Active Directory DNS, Proxmox, Hyper-V, QNAP...) is described by the server's catalog
// (GET /api/catalog, internal/catalog): which group it belongs to, its setup help and its form
// fields. The wizard asks for the group first (Virtualization, DNS, Routers, Firewalls,
// Switches, SIEM...), then the vendor, then shows that vendor's form, so adding a vendor on the server
// needs no change here.
import { Fragment, ReactNode, useEffect, useState } from "react";
import { api, Catalog, CatalogField, CatalogVendor, Target } from "./api";
import { Icon, IconName } from "./icons";

const groupIcons: Record<string, IconName> = {
  virtualization: "vm", dns: "dns", router: "gateway", firewall: "firewall", switch: "switch", storage: "nas", smarthome: "home", siem: "shield",
};

/** platformWord is a group's label for "Which … platform?": lower case, but acronyms (DNS, SIEM) kept. */
export function platformWord(label: string): string {
  return label.replace(/ & .*/, "").split(" ").map((w) => (w === w.toUpperCase() ? w : w.toLowerCase())).join(" ");
}

let catalogLoad: Promise<Catalog> | null = null;

/** useCatalog loads the connection catalog once per page load and shares it between forms. */
export function useCatalog(): { catalog: Catalog | null; err: string } {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [err, setErr] = useState("");
  useEffect(() => {
    if (!catalogLoad) catalogLoad = api<Catalog>("GET", "/api/catalog");
    let live = true;
    catalogLoad.then((c) => live && setCatalog(c)).catch((e) => {
      catalogLoad = null; // try again next time
      if (live) setErr((e as Error).message);
    });
    return () => { live = false; };
  }, []);
  return { catalog, err };
}

/** vendorFor finds the catalog entry a saved connection was made from. */
export function vendorFor(catalog: Catalog | null, t: Pick<Target, "kind" | "options">): CatalogVendor | undefined {
  if (!catalog) return undefined;
  const v = t.options?.vendor;
  return (v && catalog.vendors.find((x) => x.id === v && x.kind === t.kind)) || catalog.vendors.find((x) => x.id === t.kind);
}

/** vendorsIn lists a group's vendors in catalog order. */
export function vendorsIn(catalog: Catalog, group: string): CatalogVendor[] {
  return catalog.vendors.filter((v) => v.groups.includes(group));
}

type Vals = Record<string, string>;

const shown = (f: CatalogField, vals: Vals) => !f.show_if || Object.entries(f.show_if).every(([k, v]) => (vals[k] ?? "") === v);

function defaults(fields: CatalogField[]): Vals {
  const out: Vals = {};
  for (const f of fields) out[f.key] = f.default ?? (f.type === "checkbox" ? "off" : f.type === "select" ? f.choices?.[0]?.value ?? "" : "");
  return out;
}

const clean = (f: CatalogField, v: string) => (f.type === "password" ? v : v.trim());

/** missing names the first required field that is shown and empty, or "". */
function missing(fields: CatalogField[], vals: Vals): string {
  const f = fields.find((f) => f.required && shown(f, vals) && !clean(f, vals[f.key] ?? ""));
  return f ? f.label : "";
}

/** split turns the form's values into the connection's options and vault secret. Hidden and
 *  empty optional fields are left out; an option checkbox that is off is not stored. */
function split(fields: CatalogField[], vals: Vals, store: "option" | "secret"): Vals {
  const out: Vals = {};
  for (const f of fields) {
    if (f.store !== store || !shown(f, vals)) continue;
    const v = clean(f, vals[f.key] ?? "");
    if (!v || (f.type === "checkbox" && store === "option" && v !== "on")) continue;
    out[f.key] = v;
  }
  return out;
}

/** FieldInput is one input of a connection form. */
function FieldInput({ f, value, onChange }: { f: CatalogField; value: string; onChange: (v: string) => void }) {
  if (f.type === "checkbox") {
    return (
      <label className="check block"><input type="checkbox" checked={value === "on"} onChange={(e) => onChange(e.target.checked ? "on" : "off")} /> {f.label}</label>
    );
  }
  const input = f.type === "select"
    ? <select value={value} onChange={(e) => onChange(e.target.value)}>{f.choices?.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}</select>
    : <input type={f.type === "password" || f.type === "token" ? "password" : "text"} value={value} placeholder={f.placeholder}
        onChange={(e) => onChange(e.target.value)} autoComplete={f.type === "password" ? "new-password" : "off"} required={f.required} />;
  return <label>{f.label}{input}</label>;
}

/** Fields lays out the shown fields: inputs side by side, checkboxes on lines of their own, and a
 *  heading with its help where a field starts a section. */
function Fields({ fields, vals, set }: { fields: CatalogField[]; vals: Vals; set: (k: string, v: string) => void }) {
  const parts: ReactNode[] = [];
  let row: ReactNode[] = [];
  const flush = () => { if (row.length) parts.push(<div className="row" key={`r${parts.length}`}>{row}</div>); row = []; };
  for (const f of fields) {
    if (!shown(f, vals)) continue;
    if (f.section) {
      flush();
      parts.push(<p className="muted small" key={`s${f.key}`}><strong>{f.section}</strong>{f.help ? <>. {f.help}</> : null}</p>);
    }
    const el = <FieldInput key={f.key} f={f} value={vals[f.key] ?? ""} onChange={(v) => set(f.key, v)} />;
    if (f.type === "checkbox") {
      flush();
      parts.push(el);
    } else row.push(el);
  }
  flush();
  return <>{parts}</>;
}

/** ConnectionForm adds one connection of the given vendor. */
export function ConnectionForm({ vendor, onDone, onBack }: { vendor: CatalogVendor; onDone: () => void; onBack?: () => void }) {
  const [vals, setVals] = useState<Vals>(() => ({ name: vendor.name_default, address: vendor.address_default ?? "", ...defaults(vendor.fields) }));
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);
  const set = (k: string, v: string) => setVals((cur) => ({ ...cur, [k]: v }));

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    const miss = missing(vendor.fields, vals);
    if (miss) { setErr(`Fill in ${miss}.`); return; }
    setSaving(true);
    try {
      await api("POST", "/api/targets", {
        vendor: vendor.id, name: vals.name.trim(), address: vals.address.trim(),
        options: split(vendor.fields, vals, "option"), credentials: split(vendor.fields, vals, "secret"),
      });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
    setSaving(false);
  };

  return (
    <form className="subcard" onSubmit={save}>
      <h3>Add {vendor.label}</h3>
      {vendor.help && <p className="muted small">{vendor.help}</p>}
      <div className="row">
        <label>Name<input value={vals.name} onChange={(e) => set("name", e.target.value)} required /></label>
        <label>{vendor.address_label || "Address"}<input value={vals.address} onChange={(e) => set("address", e.target.value)}
          placeholder={vendor.address_placeholder} required /></label>
      </div>
      <Fields fields={vendor.fields} vals={vals} set={set} />
      {err && <div className="error block">{err}</div>}
      <div className="row">
        <button className="primary" disabled={saving}>{saving ? "Saving…" : "Save"}</button>
        {onBack && <button type="button" onClick={onBack}>Back</button>}
        <button type="button" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}

/**
 * AddConnection is the wizard: pick a group (skipped when only one is allowed), pick a vendor
 * (skipped when the group has only one), fill in its form.
 */
export function AddConnection({ groups, onDone }: { groups?: string[]; onDone: () => void }) {
  const { catalog, err } = useCatalog();
  const allowed = (catalog?.groups ?? []).filter((g) => (!groups || groups.includes(g.id)) && catalog && vendorsIn(catalog, g.id).length > 0);
  const [group, setGroup] = useState<string | null>(groups?.length === 1 ? groups[0] : null);
  const [vendor, setVendor] = useState<CatalogVendor | null>(null);

  if (!catalog) return <div className="subcard">{err ? <span className="error">{err}</span> : <span className="muted">Loading…</span>}</div>;
  const g = allowed.find((x) => x.id === group);
  const vendors = g ? vendorsIn(catalog, g.id) : [];
  const single = vendors.length === 1 ? vendors[0] : null;
  const canPickGroup = allowed.length > 1;

  if (vendor || single) {
    const back = vendor && !single ? () => setVendor(null) : canPickGroup ? () => { setVendor(null); setGroup(null); } : undefined;
    return <ConnectionForm vendor={(vendor ?? single)!} onDone={onDone} onBack={back} />;
  }
  return (
    <div className="subcard">
      <div className="wizard-crumbs small muted">
        <span>Add connection</span>{g && <><span aria-hidden> › </span><b>{g.label}</b></>}
      </div>
      {!g ? (
        <>
          <h3>What are you connecting?</h3>
          <div className="choices">
            {allowed.map((x) => (
              <button type="button" key={x.id} className="choice" onClick={() => setGroup(x.id)}>
                <span className="tile-icon"><Icon name={groupIcons[x.id] ?? "devices"} size={17} /></span>
                <span><b>{x.label}</b><span className="muted small">{x.summary}</span></span>
              </button>
            ))}
          </div>
        </>
      ) : (
        <>
          <h3>Which {platformWord(g.label)} platform?</h3>
          <div className="choices">
            {vendors.map((v) => (
              <button type="button" key={v.id} className="choice" onClick={() => setVendor(v)}>
                <span><b>{v.label}</b><span className="muted small">{v.summary}</span></span>
              </button>
            ))}
          </div>
        </>
      )}
      <div className="row">
        {g && canPickGroup && <button type="button" onClick={() => setGroup(null)}>Back</button>}
        <button type="button" onClick={onDone}>Cancel</button>
      </div>
    </div>
  );
}

/** EditConnection changes a saved connection's address and settings and, optionally, its login. */
export function EditConnection({ t, onDone }: { t: Target; onDone: () => void }) {
  const { catalog, err: loadErr } = useCatalog();
  const vendor = vendorFor(catalog, t);
  if (!catalog) return <div className="subcard">{loadErr ? <span className="error">{loadErr}</span> : <span className="muted">Loading…</span>}</div>;
  if (!vendor) return <div className="subcard"><span className="error">NCC has no form for {t.kind} connections.</span> <button onClick={onDone}>Close</button></div>;
  return <EditForm t={t} vendor={vendor} onDone={onDone} />;
}

function EditForm({ t, vendor, onDone }: { t: Target; vendor: CatalogVendor; onDone: () => void }) {
  // Options that steer which login fields are shown (QNAP's "also read over SNMP") are edited
  // together with the login, like the form-only fields ("sign in with").
  const gates = new Set(vendor.fields.filter((f) => f.store === "secret").flatMap((f) => Object.keys(f.show_if ?? {})));
  const isLogin = (f: CatalogField) => f.store !== "option" || gates.has(f.key);
  const settings = vendor.fields.filter((f) => !isLogin(f));
  const login = vendor.fields.filter(isLogin);

  const [vals, setVals] = useState<Vals>(() => {
    const v: Vals = { ...defaults(vendor.fields), address: t.address };
    for (const f of vendor.fields) {
      if (f.store !== "option") continue;
      v[f.key] = f.type === "checkbox" ? (t.options[f.key] === "on" ? "on" : "off") : t.options[f.key] ?? f.default ?? "";
    }
    return v;
  });
  const [repin, setRepin] = useState(false);
  const [creds, setCreds] = useState(false);
  const [err, setErr] = useState("");
  const [saving, setSaving] = useState(false);
  const set = (k: string, v: string) => setVals((cur) => ({ ...cur, [k]: v }));
  const hasTLS = vendor.fields.some((f) => f.key === "tls");
  const hasLogin = !vendor.no_login && login.some((f) => f.store === "secret");

  const save = async (e: React.FormEvent) => {
    e.preventDefault();
    setErr("");
    const options: Vals = { ...t.options };
    for (const f of vendor.fields) {
      if (f.store !== "option" || (isLogin(f) && !creds) || !shown(f, vals)) continue;
      const v = clean(f, vals[f.key] ?? "");
      if (!v || (f.type === "checkbox" && v !== "on")) delete options[f.key];
      else options[f.key] = v;
    }
    const tlsBefore = t.options.tls ?? vendor.fields.find((f) => f.key === "tls")?.default ?? "";
    if (repin || (hasTLS && vals.tls !== tlsBefore) || vals.address.trim() !== t.address) delete options.tls_fingerprint;
    if (creds) {
      const miss = missing(login, vals);
      if (miss) { setErr(`Fill in ${miss}, or untick "Change login" to keep the saved one.`); return; }
    }
    const secret = creds ? split(login, vals, "secret") : null;
    setSaving(true);
    try {
      await api("PATCH", `/api/targets/${t.id}`, { address: vals.address.trim(), options });
      if (secret) await api("PUT", `/api/targets/${t.id}/credentials`, secret);
      await api("POST", `/api/targets/${t.id}/poll`).catch((e) => { throw new Error(`Saved, but the check failed: ${(e as Error).message}`); });
      onDone();
    } catch (e) {
      setErr((e as Error).message);
    }
    setSaving(false);
  };

  return (
    <form className="subcard" onSubmit={save}>
      <h3>Edit {t.name} <span className="muted small">({vendor.label})</span></h3>
      <div className="row">
        <label>{vendor.address_label || "Address"}<input value={vals.address} onChange={(e) => set("address", e.target.value)} required /></label>
      </div>
      <Fields fields={settings} vals={vals} set={set} />
      {t.options.tls_fingerprint && vals.tls === "pin" && (
        <label className="check block"><input type="checkbox" checked={repin} onChange={(e) => setRepin(e.target.checked)} />
          Forget the pinned certificate ({t.options.tls_fingerprint.slice(0, 16)}…) and pin the one the server shows next. Use this after replacing its certificate.</label>
      )}
      {hasLogin && <label className="check block"><input type="checkbox" checked={creds} onChange={(e) => setCreds(e.target.checked)} /> Change login (the saved one stays in the vault until you save)</label>}
      {creds && <Fields fields={login} vals={vals} set={set} />}
      {err && <div className="error block">{err}</div>}
      <div className="row">
        <button className="primary" disabled={saving}>{saving ? "Saving and checking…" : "Save and check"}</button>
        <button type="button" onClick={onDone}>Cancel</button>
      </div>
    </form>
  );
}

/** VendorLabel shows a connection's product name from the catalog (the raw kind until it loads). */
export function VendorLabel({ t }: { t: Pick<Target, "kind" | "options"> }) {
  const { catalog } = useCatalog();
  return <Fragment>{vendorFor(catalog, t)?.label ?? t.kind}</Fragment>;
}
