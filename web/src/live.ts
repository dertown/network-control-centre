// Live updates from the server, plus the device labels used across pages.
//
// The server pushes a Server-Sent Event every time it finishes polling one connection
// (a UniFi snapshot, a NAS read, a DNS check...). Pages don't care which one: they take
// the counter returned by useLive as a dependency and refetch what they show when it changes.
import { useEffect, useState } from "react";

// ago and uptime moved to format.ts; they are re-exported here so existing imports keep working.
export { ago, uptime } from "./format";

/**
 * How long to wait for more events before bumping the counter. The poller polls every
 * connection at once, so one cycle arrives as a burst of N events within a second or two;
 * coalescing them means each page refetches once per cycle instead of N times.
 */
const SETTLE_MS = 750;

/**
 * useLive subscribes to /api/events and returns a counter that bumps after each burst of
 * snapshots, poll errors or DNS changes, so pages can refetch.
 *
 * While the browser tab is hidden nothing is refetched; if anything arrived meanwhile the
 * counter bumps once when the tab becomes visible again.
 */
export function useLive(enabled: boolean): number {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    if (!enabled) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let missed = false; // an event arrived while the tab was hidden
    const bump = () => setTick((t) => t + 1);
    const es = new EventSource("/api/events");
    es.onmessage = () => {
      if (document.hidden) {
        missed = true;
        return;
      }
      if (timer === undefined) timer = setTimeout(() => { timer = undefined; bump(); }, SETTLE_MS);
    };
    const onVisible = () => {
      if (!document.hidden && missed) {
        missed = false;
        bump();
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      es.close();
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [enabled]);
  return tick;
}

/** Human names for inventory device kinds (gateway, switch, ap...). */
export const kindLabel: Record<string, string> = {
  gateway: "Gateway",
  switch: "Switch",
  ap: "Access point",
  "unmanaged-switch": "Unmanaged switch",
  unknown: "Unknown",
  client: "Client",
  internet: "Internet connection",
};

/** How NCC found a device: adopted by the controller, seen over LLDP, or inferred. */
export const discoveryLabel: Record<string, string> = {
  controller: "Adopted (controller)",
  lldp: "LLDP neighbour",
  inferred: "Inferred from shared port",
};
