// Data loading and summarising for the Dashboard.
//
// The Dashboard is a read-only overview: it pulls the latest snapshot from every area of NCC
// (network devices, clients, traffic, loops, certificates, firewall, storage, VMs, smart home)
// and boils it down to two things:
//
//   1. one list of everything that needs attention, worst first (`buildAttention`), and
//   2. one status summary per area (`summarise`), shown as a tile.
//
// Keeping this out of the component makes the page itself a plain layout and keeps each
// problem reported in exactly one place.

import { useEffect, useRef, useState } from "react";
import {
  api, Cert, Client, Device, Firewall, Loop, PortForward, SmartSource, StorageSource, Target, TrafficView, VMView,
} from "../api";
import { record, recent } from "../history";
import { IconName } from "../icons";
import { kindLabel } from "../live";

/** Everything the Dashboard shows. A field is undefined until its first successful load. */
export interface DashData {
  devices?: Device[];
  clients?: Client[];
  targets?: Target[];
  certs?: Cert[];
  loops?: Loop[];
  traffic?: TrafficView;
  firewall?: Firewall[];
  storage?: StorageSource[];
  vms?: VMView;
  smart?: SmartSource[];
  /** Recent samples for the sparklines (kept per browser tab by history.ts). */
  hist: { clients: number[]; down: number[]; up: number[] };
}

// Each area is fetched independently so a failing endpoint (say, no hypervisor configured
// or a permissions error) never blanks the rest of the page; it simply keeps its last value.
async function loadAll(): Promise<Partial<DashData>> {
  const get = <T>(path: string) => api<T>("GET", path).catch(() => undefined);
  const [devices, clients, targets, certs, loops, traffic, firewall, storage, vms, smart] = await Promise.all([
    get<Device[]>("/api/devices"),
    get<Client[]>("/api/clients"),
    get<Target[]>("/api/targets"),
    get<Cert[]>("/api/certs"),
    get<Loop[]>("/api/loops"),
    get<TrafficView>("/api/traffic?window=session"),
    get<Firewall[]>("/api/firewall"),
    get<{ sources: StorageSource[] | null }>("/api/storage"),
    get<VMView>("/api/vms"),
    get<{ sources: SmartSource[] | null }>("/api/smarthome"),
  ]);
  const out: Partial<DashData> = { devices, clients, targets, certs, loops, traffic, firewall, vms };
  if (storage) out.storage = storage.sources ?? [];
  if (smart) out.smart = smart.sources ?? [];
  // drop failed loads so the merge below keeps the previous value
  (Object.keys(out) as (keyof DashData)[]).forEach((k) => out[k] === undefined && delete out[k]);
  return out;
}

/**
 * useDashboardData reloads every area when `tick` changes (a server-sent event: new snapshot,
 * poll error, DNS change). Ticks can arrive in bursts, one per polled target, so loads are
 * coalesced: while a load is running, further ticks only queue a single follow-up load
 * instead of starting ten overlapping rounds of requests.
 */
export function useDashboardData(tick: number): DashData {
  const [data, setData] = useState<DashData>(() => ({ hist: { clients: recent("clients"), down: recent("down"), up: recent("up") } }));
  const running = useRef(false);
  const queued = useRef(false);
  const mounted = useRef(true);
  useEffect(() => () => { mounted.current = false; }, []);

  useEffect(() => {
    if (running.current) {
      queued.current = true;
      return;
    }
    running.current = true;
    (async () => {
      do {
        queued.current = false;
        const next = await loadAll();
        if (!mounted.current) break;
        setData((prev) => {
          const hist = { ...prev.hist };
          if (next.clients) hist.clients = record("clients", next.clients.length);
          if (next.traffic) {
            const online = next.traffic.clients.filter((c) => c.online);
            hist.down = record("down", online.reduce((s, c) => s + c.down_rate, 0));
            hist.up = record("up", online.reduce((s, c) => s + c.up_rate, 0));
          }
          return { ...prev, ...next, hist };
        });
      } while (queued.current);
      running.current = false;
    })();
  }, [tick]);

  return data;
}

// ---------------------------------------------------------------------------------------
// Attention list

export type Level = "critical" | "warning";

/** One problem, phrased for a person, with a link to the page where it can be fixed. */
export interface Attention {
  key: string;
  level: Level;
  icon: IconName;
  title: string;
  detail?: string;
  href: string;
  /** Short name of the area, shown as the link text ("Topology", "Storage"...). */
  area: string;
}

/** InternetState is derived from the gateway: online, and its WAN (uplink) port up. */
export interface InternetState {
  state: "up" | "down" | "unknown";
  gateway?: Device;
  /** WAN link speed in Mbit/s, when the gateway reports it. */
  speed?: number;
}

export function internetState(devices: Device[] = []): InternetState {
  const gws = devices.filter((d) => d.kind === "gateway" && d.discovery === "controller");
  if (gws.length === 0) return { state: "unknown" };
  // with several gateways, the internet is up if any of them has a working WAN
  for (const gw of gws) {
    const wan = gw.ports?.find((p) => p.uplink);
    if (gw.online && (!wan || wan.up)) return { state: "up", gateway: gw, speed: wan?.speed_mbps };
  }
  return { state: "down", gateway: gws[0] };
}

/** Port forwards that are switched on, across every router. */
export function openForwards(fw: Firewall[] = []): PortForward[] {
  return fw.flatMap((f) => f.forwards ?? []).filter((p) => p.enabled);
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * buildAttention gathers every problem from every area into one list, critical first.
 * Each problem appears once; the area tiles only count them, they don't list them again.
 */
export function buildAttention(d: DashData): Attention[] {
  const out: Attention[] = [];
  const net = internetState(d.devices);

  if (net.state === "down") {
    out.push({
      key: "internet", level: "critical", icon: "internet", area: "Devices", href: "#/devices",
      title: "Internet is down",
      detail: net.gateway?.online ? `${net.gateway.name} is up but its WAN port has no link.` : `${net.gateway?.name ?? "The gateway"} is not responding.`,
    });
  }

  for (const l of d.loops ?? []) {
    out.push({
      key: `loop-${l.id}`, level: l.severity, icon: "alert", area: "Topology", href: "#/topology",
      title: l.severity === "critical" ? `Switching loop: ${l.summary}` : `Loop contained by spanning tree: ${l.summary}`,
      detail: l.ports.map((p) => `${p.device_name}${p.port_name ? ` ${p.port_name}` : ""}`).join(", "),
    });
  }

  // the gateway is already reported as "internet down", so don't repeat it as an offline device
  for (const dev of (d.devices ?? []).filter((x) => x.discovery === "controller" && !x.online)) {
    if (net.state === "down" && dev.id === net.gateway?.id) continue;
    out.push({
      key: `dev-${dev.id}`, level: dev.kind === "gateway" || dev.kind === "switch" ? "critical" : "warning",
      icon: "devices", area: "Devices", href: "#/devices",
      title: `${dev.name} is offline`,
      detail: [kindLabel[dev.kind] ?? dev.kind, dev.model, dev.ip].filter(Boolean).join(" · "),
    });
  }

  for (const h of (d.vms?.hosts ?? []).filter((x) => !x.online)) {
    out.push({
      key: `host-${h.target}-${h.name}`, level: "critical", icon: "server", area: "Virtual machines", href: "#/vms",
      title: `VM host ${h.name} is offline`, detail: "Virtual machines on it are unreachable.",
    });
  }

  for (const s of d.storage ?? []) {
    for (const [i, a] of (s.inventory?.alerts ?? []).entries()) {
      out.push({
        key: `st-${s.id}-${i}`, level: a.level, icon: "nas", area: "Storage", href: "#/storage",
        title: `${s.name}: ${a.subject}`, detail: a.message,
      });
    }
  }

  for (const s of d.smart ?? []) {
    for (const [i, a] of (s.inventory?.alerts ?? []).entries()) {
      out.push({
        key: `sh-${s.id}-${i}`, level: a.level, icon: "home", area: "Smart home", href: "#/iot",
        title: a.subject, detail: a.message,
      });
    }
  }

  for (const c of d.certs ?? []) {
    if (c.status === "ok") continue;
    out.push({
      key: `cert-${c.id}`, level: c.status === "expiring" ? "warning" : "critical", icon: "cert", area: "Vault", href: "#/vault",
      title: c.days_left < 0 ? `Certificate ${c.name} has expired` : `Certificate ${c.name} expires in ${plural(c.days_left, "day")}`,
      detail: new Date(c.not_after).toLocaleDateString(undefined, { dateStyle: "medium" }),
    });
  }

  for (const t of (d.targets ?? []).filter((x) => x.enabled && x.last_error)) {
    out.push({
      key: `tgt-${t.id}`, level: "warning", icon: "link", area: "Settings", href: "#/settings",
      title: `Can't read ${t.name}`, detail: t.last_error,
    });
  }

  // stable sort: critical first, otherwise keep the order above (internet, loops, devices...)
  return out.sort((a, b) => (a.level === b.level ? 0 : a.level === "critical" ? -1 : 1));
}

export { plural };
