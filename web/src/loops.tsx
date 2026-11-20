import { Loop } from "./api";
import { ago } from "./live";
import { Icon } from "./icons";

export const loopKindLabel: Record<Loop["kind"], string> = {
  self: "Ports looped together",
  parallel: "Duplicate links",
  cycle: "Ring of cables",
  stp: "Blocked by spanning tree",
  event: "Reported by UniFi",
};

export function loopTone(l: Loop) {
  return l.severity === "critical" ? "bad" : "warn";
}

// worstLoop returns "critical", "warning" or undefined for a set of loop ids.
export function worstLoop(ids: string[] | undefined, byID: Map<string, Loop>): Loop["severity"] | undefined {
  if (!ids?.length) return undefined;
  return ids.some((id) => byID.get(id)?.severity === "critical") ? "critical" : "warning";
}

// LoopList shows each loop with the exact switch and ports involved.
export function LoopList({ loops, focus, onFocus, compact }: {
  loops: Loop[]; focus?: string | null; onFocus?: (id: string | null) => void; compact?: boolean;
}) {
  return (
    <ul className="loop-list">
      {loops.map((l) => (
        <li key={l.id} className={`loop-item ${loopTone(l)}${focus === l.id ? " on" : ""}`}>
          <div className="loop-head">
            <span className={`pill ${loopTone(l)}`}>{l.severity === "critical" ? "Loop" : "Contained"}</span>
            <strong className="loop-summary">{l.summary}</strong>
            {onFocus && (
              <button className="small" aria-pressed={focus === l.id} onClick={() => onFocus(focus === l.id ? null : l.id)}>
                {focus === l.id ? "Show all" : "Show on map"}
              </button>
            )}
          </div>
          <div className="loop-ports">
            {l.ports.map((p) => (
              <span key={`${p.device}#${p.port ?? 0}`} className="loop-port" title={p.device}>
                <Icon name="switch" size={12} /> {p.device_name}
                {p.port_name && <b> {p.port_name}</b>}
                {p.stp && p.stp !== "forwarding" && <span className="muted"> ({p.stp})</span>}
              </span>
            ))}
          </div>
          {!compact && l.detail && <p className="muted small loop-detail">{l.detail}</p>}
          <div className="muted small">
            {loopKindLabel[l.kind]}
            {l.count && l.count > 1 ? ` · logged ${l.count} times` : ""}
            {l.seen_at ? ` · last ${ago(l.seen_at)}` : ""}
          </div>
        </li>
      ))}
    </ul>
  );
}
