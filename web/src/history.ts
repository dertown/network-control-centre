// A tiny in-memory store of recent values (client counts, throughput) so tiles can draw
// sparklines. It lives for the browser tab; nothing is persisted.
const series = new Map<string, number[]>();
const keep = 40;

export function record(key: string, value: number): number[] {
  const s = series.get(key) ?? [];
  s.push(value);
  if (s.length > keep) s.splice(0, s.length - keep);
  series.set(key, s);
  return [...s];
}

export function recent(key: string): number[] {
  return [...(series.get(key) ?? [])];
}
