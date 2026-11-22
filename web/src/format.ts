// Formatting helpers shared by every page: sizes, rates, percentages and durations.
// Keep these pure (no React) so they can be used anywhere, including in useMemo bodies.

/** bytes formats a byte count with binary units: 0 B, 512 B, 1.5 KB, 120 MB, 2.0 TB. */
export function bytes(n: number): string {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const v = n / 1024 ** i;
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${u[i]}`;
}

/** rate formats a throughput given in bytes per second as bits per second (what ISPs quote). */
export function rate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8;
  if (bits < 1e3) return `${bits.toFixed(0)} bit/s`;
  if (bits < 1e6) return `${(bits / 1e3).toFixed(0)} kbit/s`;
  if (bits < 1e9) return `${(bits / 1e6).toFixed(1)} Mbit/s`;
  return `${(bits / 1e9).toFixed(2)} Gbit/s`;
}

/** pct formats a 0..1 fraction as a whole percentage, clamped to 0–100%. */
export function pct(n: number): string {
  return `${Math.round(Math.max(0, Math.min(1, n)) * 100)}%`;
}

/** ago says how long ago an ISO timestamp was ("42s ago", "5m ago", "3h ago", "2d ago"), or "never". */
export function ago(iso?: string): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

/** uptime formats a duration in seconds as "3d 4h" or "4h 12m"; empty for zero or missing. */
export function uptime(s?: number): string {
  if (!s) return "";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return d > 0 ? `${d}d ${h}h` : `${h}h ${Math.floor((s % 3600) / 60)}m`;
}
