import { useEffect, useState } from "react";

// useLive subscribes to server-sent events and returns a counter that bumps on every
// snapshot, poll error or DNS change, so pages can refetch.
export function useLive(enabled: boolean): number {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    const es = new EventSource("/api/events");
    es.onmessage = () => setTick((t) => t + 1);
    return () => es.close();
  }, [enabled]);
  return tick;
}

export function ago(iso?: string): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function uptime(s?: number): string {
  if (!s) return "";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  return d > 0 ? `${d}d ${h}h` : `${h}h ${Math.floor((s % 3600) / 60)}m`;
}

export const kindLabel: Record<string, string> = {
  gateway: "Gateway",
  switch: "Switch",
  ap: "Access point",
  "unmanaged-switch": "Unmanaged switch",
  unknown: "Unknown",
  client: "Client",
  internet: "Internet connection",
};

export const discoveryLabel: Record<string, string> = {
  controller: "Adopted (controller)",
  lldp: "LLDP neighbour",
  inferred: "Inferred from shared port",
};
