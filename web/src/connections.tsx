// Shared plumbing for the pages built around polled connections (Virtual machines, Storage,
// Smart home): fetching the page's data on every live tick, "Refresh now" (poll every
// connection immediately), and adding a connection without leaving the page.
//
// The full list of connections, with edit, disable and remove, lives only in Settings;
// these pages link there instead of repeating it.
import { ReactNode, useEffect, useState } from "react";
import { api, User } from "./api";
import { Icon } from "./icons";
import { AddConnection, ConnectionForm, useCatalog, vendorsIn } from "./connectionWizard";
import { SourceStatus } from "./ui";

/**
 * useSourceData fetches path now and again whenever tick changes, and offers refresh(),
 * which asks the server to poll each enabled connection right away and then refetches.
 * sourcesOf picks the connections out of the response; map (optional) tidies the response
 * before it is stored.
 */
export function useSourceData<R, T = R>(path: string, tick: number, sourcesOf: (d: T) => SourceStatus[], map?: (r: R) => T) {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const refetch = () => api<R>("GET", path)
    .then((r) => { setData(map ? map(r) : (r as unknown as T)); setErr(""); })
    .catch((e) => setErr((e as Error).message));
  useEffect(() => { refetch(); }, [path, tick]);

  const refresh = async () => {
    if (!data) return;
    setBusy(true);
    setErr(await pollNow(sourcesOf(data)));
    setBusy(false);
    refetch();
  };

  return { data, err, setErr, busy, refetch, refresh };
}

/**
 * pollNow asks the server to poll every enabled connection in sources at once. It resolves
 * to the failures joined with " · ", or "" when every poll succeeded.
 */
export async function pollNow(sources: SourceStatus[]): Promise<string> {
  const fails: string[] = [];
  await Promise.all(sources.filter((s) => s.enabled).map((s) =>
    api("POST", `/api/targets/${s.id}/poll`).catch((e) => fails.push(`${s.name}: ${(e as Error).message}`))));
  return fails.join(" · ");
}

/** RefreshButton is "Refresh now" for operators and admins; viewers can't trigger polls. */
export function RefreshButton({ user, busy, onClick }: { user: User; busy: boolean; onClick: () => void }) {
  if (user.role === "viewer") return null;
  return <button onClick={onClick} disabled={busy}>{busy ? "Refreshing…" : "Refresh now"}</button>;
}

/**
 * ConnectionPicker offers one button per vendor of a wizard group (e.g. "storage"); picking one
 * opens its form. primary highlights the first button (used on empty pages, where adding is the
 * next step).
 */
export function ConnectionPicker({ group, onDone, primary, footer }: {
  group: string; onDone: () => void; primary?: boolean; footer?: ReactNode;
}) {
  const { catalog, err } = useCatalog();
  const [id, setId] = useState<string | null>(null);
  const vendors = catalog ? vendorsIn(catalog, group) : [];
  const picked = vendors.find((v) => v.id === id);
  if (picked) return <ConnectionForm vendor={picked} onDone={() => { setId(null); onDone(); }} onBack={vendors.length > 1 ? () => setId(null) : undefined} />;
  return (
    <div className="row">
      {err && <span className="error">{err}</span>}
      {vendors.map((v, i) => <button key={v.id} className={primary && i === 0 ? "primary" : ""} onClick={() => setId(v.id)}>Add {v.label}</button>)}
      {footer}
    </div>
  );
}

/**
 * useConnectionAdder gives a page an admin-only "Add connection" button for its header and
 * the panel it opens (place it under the header): the Add connection wizard for the page's
 * group, starting at the vendor question. onAdded runs after the wizard closes, saved or
 * cancelled.
 */
export function useConnectionAdder(group: string, user: User, onAdded: () => void): { button: ReactNode; panel: ReactNode } {
  const [open, setOpen] = useState(false);
  if (user.role !== "admin") return { button: null, panel: null };
  const done = () => { setOpen(false); onAdded(); };
  const button = (
    <button onClick={() => setOpen(!open)} aria-expanded={open}><Icon name="plus" size={15} />Add connection</button>
  );
  const panel = open && (
    <>
      <AddConnection groups={[group]} onDone={done} />
      <p className="small"><a href="#/settings">Edit or remove connections in Settings →</a></p>
    </>
  );
  return { button, panel };
}
