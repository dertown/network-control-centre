// Small building blocks shared by the pages: summary tiles, dialogs, loading states and
// the banners and alert lists that every "connections" page (VMs, Storage, Smart home) shows.
import { ReactNode, useEffect } from "react";
import { Icon, IconName } from "./icons";
import { ago } from "./format";

export type Tone = "good" | "warn" | "bad";

/**
 * Tile is one of the summary cards in the row at the top of a page: a label and icon,
 * a big value and an optional line underneath. With href the whole tile is a link.
 * iconTone colours just the icon (c1..c4 or a tone); tone colours the tile itself.
 */
export function Tile({ label, value, sub, tone, icon, iconTone, valueClass, subClass, href, children }: {
  label: string; value: ReactNode; sub?: ReactNode; tone?: Tone; icon: IconName; iconTone?: string;
  valueClass?: string; subClass?: string; href?: string;
  /** Drawn at the bottom of the tile: a sparkline or a meter. */
  children?: ReactNode;
}) {
  const body = (
    <>
      <div className="tile-top">
        <span className="tile-label">{label}</span>
        <span className={`tile-icon ${iconTone ?? tone ?? ""}`}><Icon name={icon} size={17} /></span>
      </div>
      <div className={`tile-value ${valueClass ?? ""}`}>{value}</div>
      {sub && <div className={`muted small ${subClass ?? ""}`}>{sub}</div>}
      {children}
    </>
  );
  return href
    ? <a className={`tile ${tone ?? ""}`} href={href}>{body}</a>
    : <div className={`tile ${tone ?? ""}`}>{body}</div>;
}

/**
 * Modal is a centred dialog over a dimmed page. It closes on Escape, on the ✕ button and
 * on a click on the backdrop (but not on a drag that merely ends there).
 */
export function Modal({ title, children, onClose, wide }: { title: string; children: ReactNode; onClose: () => void; wide?: boolean }) {
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className={`modal ${wide ? "wide" : ""}`} role="dialog" aria-modal="true" aria-label={title}>
        <div className="modal-head"><h2>{title}</h2><button className="iconbtn" onClick={onClose} aria-label="Close">✕</button></div>
        {children}
      </div>
    </div>
  );
}

/** PageLoading is what a page shows before its first fetch answers: the title and "Loading…" or the error. */
export function PageLoading({ title, err }: { title: string; err?: string }) {
  return <><h1>{title}</h1>{err ? <div className="error block">{err}</div> : <p className="muted">Loading…</p>}</>;
}

/** PageHeader is a page title with action buttons on the right. */
export function PageHeader({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="card-head" style={{ marginBottom: 4 }}>
      <h1 style={{ margin: 0 }}>{title}</h1>
      {children && <div className="row" style={{ margin: 0 }}>{children}</div>}
    </div>
  );
}

/** The fields every polled connection (a "source") reports, whatever its kind. */
export interface SourceStatus { id: number; name: string; enabled: boolean; last_error?: string; taken_at?: string }

/**
 * SourceBanners shows a red banner for each enabled connection whose last poll failed (with
 * the age of the data still on screen) and an amber banner for each warning a connection
 * reported. noun is what the stale data is called on this page ("read", "list").
 */
export function SourceBanners<S extends SourceStatus>({ sources, warnings, noun = "read" }: {
  sources: S[]; warnings?: (s: S) => string[] | undefined; noun?: string;
}) {
  return (
    <>
      {sources.filter((s) => s.enabled && s.last_error).map((s) => (
        <div key={s.id} className="banner bad" role="alert">
          <Icon name="alert" size={16} /><strong>{s.name}</strong><span>{s.last_error}</span>
          {s.taken_at && <span className="muted small">Showing the {noun} from {ago(s.taken_at)}.</span>}
        </div>
      ))}
      {warnings && sources.flatMap((s) => (warnings(s) ?? []).map((w) => (
        <div key={s.id + w} className="banner warn"><Icon name="alert" size={16} /><strong>{s.name}</strong><span>{w}</span></div>
      )))}
    </>
  );
}

/** An alert raised by a NAS or the smart home hub, tagged with the connection it came from. */
export interface SourcedAlert { level: "warning" | "critical"; subject: string; message: string; source: { name: string } }

/** AlertList is the "Alerts" / "Needs attention" card: one row per alert, worst marked red. */
export function AlertList({ title, alerts, showSource = true }: { title: string; alerts: SourcedAlert[]; showSource?: boolean }) {
  if (alerts.length === 0) return null;
  return (
    <section className="card">
      <h2><Icon name="alert" size={16} /> {title}</h2>
      <ul className="list st-alerts">
        {alerts.map((a, i) => (
          <li key={i}>
            <span className={`dot ${a.level === "critical" ? "bad" : "warn"}`} />
            <span className="grow-col"><strong>{a.subject}</strong> <span>{a.message}</span></span>
            {showSource && <span className="muted small">{a.source.name}</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}
