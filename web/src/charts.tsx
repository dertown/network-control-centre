// Dependency-free SVG charts for the dashboard and tiles.

export interface Segment { label: string; value: number; color: string }

// Donut draws a ring split into segments, with a big number in the middle and a legend beside it.
export function Donut({ segments, center, sub, size = 132 }: { segments: Segment[]; center: string | number; sub?: string; size?: number }) {
  const total = segments.reduce((s, x) => s + x.value, 0);
  const r = 15.9155; // circumference of 100 so dash lengths are percentages
  let offset = 25; // start at 12 o'clock
  return (
    <div className="donut">
      <svg width={size} height={size} viewBox="0 0 42 42" role="img" aria-label={segments.map((s) => `${s.label}: ${s.value}`).join(", ")}>
        <circle cx="21" cy="21" r={r} fill="none" className="donut-track" strokeWidth="5" />
        {total > 0 &&
          segments.filter((s) => s.value > 0).map((s) => {
            const pct = (s.value / total) * 100;
            // a 0.6 gap between segments reads better than touching arcs, except for a full ring
            const gap = pct < 100 ? 0.6 : 0;
            const el = (
              <circle key={s.label} cx="21" cy="21" r={r} fill="none" stroke={s.color} strokeWidth="5"
                strokeDasharray={`${Math.max(pct - gap, 0.01)} ${100 - pct + gap}`} strokeDashoffset={offset} />
            );
            offset -= pct;
            return el;
          })}
        <text x="21" y={sub ? 21.5 : 23} textAnchor="middle" className="donut-value">{center}</text>
        {sub && <text x="21" y="27" textAnchor="middle" className="donut-sub">{sub}</text>}
      </svg>
      <ul className="legend">
        {segments.map((s) => (
          <li key={s.label}><i style={{ background: s.color }} />{s.label}<b>{s.value}</b></li>
        ))}
      </ul>
    </div>
  );
}

// Sparkline is a small area chart of recent values; it renders nothing until there are two points.
export function Sparkline({ values, color = "var(--accent)", height = 34, width = 120 }: { values: number[]; color?: string; height?: number; width?: number }) {
  if (values.length < 2) return <div className="spark-empty" style={{ height }} />;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const span = max - min || 1;
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => [i * step, height - 2 - ((v - min) / span) * (height - 6)]);
  const line = pts.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const id = `sg${Math.abs(hash(color))}`;
  return (
    <svg className="spark" width="100%" height={height} viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" aria-hidden>
      <defs>
        <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.28" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${line} L${width},${height} L0,${height} Z`} fill={`url(#${id})`} />
      <path d={line} fill="none" stroke={color} strokeWidth="1.6" vectorEffect="non-scaling-stroke" strokeLinejoin="round" />
    </svg>
  );
}

// Meter is a thin horizontal gauge, 0..1.
export function Meter({ value, tone }: { value: number; tone?: "good" | "warn" | "bad" }) {
  return <div className={`meter ${tone ?? ""}`} aria-hidden><span style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }} /></div>;
}

function hash(s: string) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}
