// Tiered layout for the topology map, in the style of auto-discovery network maps: the
// Internet at the top, then the gateway, then each tier of switches and access points, with
// every device's clients packed into a tidy block right under it. Positions are worked out
// here (a small "tidy tree") and handed to Cytoscape as a preset layout, so the map comes out
// the same every time instead of wherever a force layout happens to settle.
import cytoscape from "cytoscape";
import { GEdge, GNode } from "../api";

export const INTERNET = "internet";
export const clusterID = (device: string) => `clients:${device}`;
export const clusterLinkID = (device: string) => `clients-link:${device}`;
export const wanLinkID = (gw: string) => `wan:${gw}`;

// sizes in model pixels
const DEVICE_W = 184, DEVICE_H = 108, NODE_HALF = 30;
const GAP_X = 28, GAP_Y = 76;
const CELL_W = 86, CELL_H = 54, CLUSTER_PAD = 16;
// how far below a parent's tile the right-angle links turn sideways: just under its label
export const TAXI_TURN = 60;

// Edge preference when deciding which link is a device's way "up" to the gateway. UniFi's
// uplink is the truth; LLDP neighbours and inferred dumb switches come next.
const weight: Record<string, number> = { uplink: 1, inferred: 1, lldp: 3 };

const kindOrder: Record<string, number> = { gateway: 0, switch: 1, "unmanaged-switch": 2, ap: 3, unknown: 4 };

interface Item {
  id: string; kind: "device" | "cluster" | "group"; w: number; h: number; children: Item[];
  members?: string[]; cols?: number; span?: number; x?: number; depth?: number;
}

export interface Plan {
  positions: Map<string, cytoscape.Position>;
  treeEdges: Set<string>;       // API edges that are a device's link up the tree (drawn as right angles)
  flipped: Set<string>;         // tree edges whose API source is the lower device
  clusters: { device: string; members: string[]; wireless: boolean }[];
  internet: string[];           // gateways the Internet node connects to
}

function gridSize(n: number) {
  const cols = Math.max(1, Math.min(n, Math.ceil(Math.sqrt(n) * 1.4), 6));
  return { cols, rows: Math.ceil(n / cols) };
}

function clusterItem(id: string, members: string[], kind: "cluster" | "group"): Item {
  const { cols, rows } = gridSize(members.length);
  return { id, kind, members, cols, w: cols * CELL_W + CLUSTER_PAD, h: rows * CELL_H + 40, children: [] };
}

// planLayout places every node. withClusters packs each device's clients under it;
// groups (Group by VLAN) instead lays one box per network in a row under the devices.
export function planLayout(nodes: GNode[], edges: GEdge[], opts: { withClusters: boolean; groups?: { id: string; members: string[] }[] }): Plan {
  const infra = nodes.filter((n) => n.kind !== "client");
  const byID = new Map(nodes.map((n) => [n.id, n]));
  const isInfra = (id: string) => { const k = byID.get(id)?.kind; return !!k && k !== "client"; };

  // shortest weighted path from the gateways gives each device one parent
  const adj = new Map<string, { to: string; e: GEdge; w: number }[]>();
  for (const e of edges) {
    if (e.source === e.target || e.origin === "loop" || e.origin === "client") continue;
    if (!isInfra(e.source) || !isInfra(e.target)) continue;
    const w = weight[e.origin] ?? 2;
    (adj.get(e.source) ?? adj.set(e.source, []).get(e.source)!).push({ to: e.target, e, w });
    (adj.get(e.target) ?? adj.set(e.target, []).get(e.target)!).push({ to: e.source, e, w });
  }
  const sorted = [...infra].sort((a, b) => (kindOrder[a.kind] ?? 9) - (kindOrder[b.kind] ?? 9) || a.label.localeCompare(b.label));
  const gateways = sorted.filter((n) => n.kind === "gateway").map((n) => n.id);
  const dist = new Map<string, number>();
  const parent = new Map<string, { id: string; e: GEdge }>();
  const roots: string[] = [];
  const settle = (start: string) => {
    roots.push(start);
    dist.set(start, 0);
    const queue = [start];
    while (queue.length) {
      queue.sort((a, b) => dist.get(a)! - dist.get(b)!);
      const cur = queue.shift()!;
      for (const { to, e, w } of adj.get(cur) ?? []) {
        const d = dist.get(cur)! + w;
        if (!dist.has(to) || d < dist.get(to)!) {
          if (roots.includes(to)) continue;
          dist.set(to, d);
          parent.set(to, { id: cur, e });
          if (!queue.includes(to)) queue.push(to);
        }
      }
    }
  };
  for (const g of gateways) if (!dist.has(g)) settle(g);
  // devices the gateways cannot reach start trees of their own, best-connected first
  const rest = sorted.filter((n) => !dist.has(n.id)).sort((a, b) => (adj.get(b.id)?.length ?? 0) - (adj.get(a.id)?.length ?? 0));
  for (const n of rest) if (!dist.has(n.id)) settle(n.id);

  const treeEdges = new Set<string>(), flipped = new Set<string>();
  const kids = new Map<string, string[]>();
  for (const n of sorted) {
    const p = parent.get(n.id);
    if (!p) continue;
    treeEdges.add(p.e.id);
    if (p.e.source !== p.id) flipped.add(p.e.id);
    (kids.get(p.id) ?? kids.set(p.id, []).get(p.id)!).push(n.id);
  }

  // clients, by the device they hang off
  const clientsOf = new Map<string, string[]>();
  const wireless = new Map<string, boolean>();
  const clientEdge = new Map(edges.filter((e) => e.origin === "client").map((e) => [e.target, e]));
  for (const c of nodes.filter((n) => n.kind === "client").sort((a, b) => a.label.localeCompare(b.label))) {
    let dev = c.parent && isInfra(c.parent) ? c.parent : clientEdge.get(c.id)?.source;
    if (!dev || !isInfra(dev)) dev = roots[0];
    if (!dev) continue;
    (clientsOf.get(dev) ?? clientsOf.set(dev, []).get(dev)!).push(c.id);
    const wl = clientEdge.get(c.id)?.medium === "wireless";
    wireless.set(dev, (wireless.get(dev) ?? true) && wl);
  }

  const build = (id: string): Item => {
    const children = (kids.get(id) ?? []).map(build);
    const members = opts.withClusters ? clientsOf.get(id) : undefined;
    if (members?.length) children.splice(Math.floor(children.length / 2), 0, clusterItem(clusterID(id), members, "cluster"));
    return { id, kind: "device", w: DEVICE_W, h: DEVICE_H, children };
  };
  let top: Item[] = roots.map(build);
  const internet = gateways.filter((g) => roots.includes(g));
  if (internet.length) {
    const inet: Item = { id: INTERNET, kind: "device", w: DEVICE_W, h: 84, children: top.filter((t) => internet.includes(t.id)) };
    top = [inet, ...top.filter((t) => !internet.includes(t.id))];
  }

  // widths bottom-up, then x left to right; rows are as tall as their tallest item
  const span = (it: Item): number => {
    const c = it.children.reduce((s, ch) => s + span(ch), 0) + GAP_X * Math.max(0, it.children.length - 1);
    return (it.span = Math.max(it.w, c));
  };
  const rowH: number[] = [];
  const place = (it: Item, left: number, depth: number) => {
    it.depth = depth;
    it.x = left + it.span! / 2;
    rowH[depth] = Math.max(rowH[depth] ?? 0, it.h);
    const c = it.children.reduce((s, ch) => s + ch.span!, 0) + GAP_X * Math.max(0, it.children.length - 1);
    let x = left + (it.span! - c) / 2;
    for (const ch of it.children) { place(ch, x, depth + 1); x += ch.span! + GAP_X; }
  };
  let left = 0;
  for (const t of top) { span(t); place(t, left, 0); left += t.span! + GAP_X * 2; }
  const rowTop: number[] = [0];
  for (let d = 1; d <= rowH.length; d++) rowTop[d] = rowTop[d - 1] + rowH[d - 1] + GAP_Y;

  const positions = new Map<string, cytoscape.Position>();
  const putGrid = (it: Item, cx: number, y0: number) => {
    const cols = it.cols!;
    it.members!.forEach((m, i) => {
      const r = Math.floor(i / cols), c = i % cols;
      const inRow = Math.min(cols, it.members!.length - r * cols);
      positions.set(m, { x: cx + (c - (inRow - 1) / 2) * CELL_W, y: y0 + r * CELL_H });
    });
  };
  const walk = (it: Item) => {
    const y = rowTop[it.depth!];
    if (it.kind === "device") positions.set(it.id, { x: it.x!, y: y + NODE_HALF });
    else putGrid(it, it.x!, y + 26);
    it.children.forEach(walk);
  };
  top.forEach(walk);

  // Group by VLAN: one box per network, in a row under the deepest devices
  if (opts.groups?.length) {
    const boxes = opts.groups.filter((g) => g.members.length).map((g) => clusterItem(g.id, g.members, "group"));
    const total = boxes.reduce((s, b) => s + b.w, 0) + 56 * Math.max(0, boxes.length - 1);
    let x = Math.max(0, left - GAP_X * 2) / 2 - total / 2;
    const y = rowTop[rowH.length] + 24;
    for (const b of boxes) { putGrid(b, x + b.w / 2, y + 12); x += b.w + 56; }
  }

  const clusters = opts.withClusters
    ? [...clientsOf].map(([device, members]) => ({ device, members, wireless: wireless.get(device) ?? false }))
    : [];
  return { positions, treeEdges, flipped, clusters, internet };
}
