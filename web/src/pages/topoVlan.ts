// VLAN and firewall-zone layer for the topology map: network colours, zone labels and the
// Cytoscape selectors that colour clients, client links and VLAN group boxes. Kept apart
// from the base map style so the two can change independently.
import cytoscape from "cytoscape";
import { GEdge, GNetwork, GNode } from "../api";

export const zoneLabel: Record<string, string> = {
  internal: "Internal",
  external: "External",
  gateway: "Gateway",
  vpn: "VPN",
  hotspot: "Guest / hotspot",
  dmz: "DMZ",
  custom: "Custom zone",
};

// zoneText names a network's zone; custom zones use the name the admin gave them.
export function zoneText(n: { zone?: string; zone_name?: string }): string {
  if (!n.zone) return "";
  if (n.zone === "custom") return n.zone_name || "Custom zone";
  return zoneLabel[n.zone] ?? n.zone_name ?? n.zone;
}

// Zones that deserve attention on the map get a pill colour.
export const zonePill: Record<string, string> = { dmz: "bad", hotspot: "warn", external: "" };

// Categorical hues, ordered so neighbours differ strongly. Each pair is light / dark theme.
const palette: [string, string][] = [
  ["#2563eb", "#6b9bff"], // blue
  ["#0d9488", "#2dd4bf"], // teal
  ["#9333ea", "#c084fc"], // violet
  ["#d97706", "#fbbf24"], // amber
  ["#db2777", "#f472b6"], // pink
  ["#4d7c0f", "#a3e635"], // olive
  ["#0369a1", "#38bdf8"], // sky
  ["#a16207", "#facc15"], // ochre
];

export function isDark(): boolean {
  const t = document.documentElement.getAttribute("data-theme");
  if (t) return t === "dark";
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;
}

// networkColors gives every network a stable colour (by VLAN order, as the API sends them).
// WAN networks get the muted ink: they are not part of the LAN map.
export function networkColors(nets: GNetwork[] | undefined, muted: string): Map<string, string> {
  const dark = isDark() ? 1 : 0;
  const out = new Map<string, string>();
  let i = 0;
  for (const n of nets ?? []) {
    if (n.purpose === "wan") {
      out.set(n.id, muted);
      continue;
    }
    out.set(n.id, palette[i % palette.length][dark]);
    i++;
  }
  return out;
}

export function vlanText(n?: GNetwork | null): string {
  if (!n) return "";
  if (n.purpose === "wan") return "WAN";
  return n.vlan ? `VLAN ${n.vlan}` : "untagged";
}

export const groupID = (net: string) => `vlan:${net}`;

// groupNodes builds a compound "box" per network that has members on the map.
export function groupNodes(nodes: GNode[], nets: GNetwork[] | undefined, colors: Map<string, string>) {
  const used = new Set(nodes.filter((n) => n.kind === "client" && n.network).map((n) => n.network!));
  return (nets ?? [])
    .filter((n) => used.has(n.id))
    .map((n) => ({
      data: {
        id: groupID(n.id), kind: "vlan-group", network: n.id, zone: n.zone, netColor: colors.get(n.id),
        display: `${n.name} · ${vlanText(n)}${n.zone ? ` · ${zoneText(n)}` : ""}`,
      },
      classes: "vlan-group",
    }));
}

// trunkLabel appends a VLAN count to links that carry more than one network.
export function trunkLabel(e: GEdge): string | undefined {
  const n = e.networks?.length ?? 0;
  if (e.origin === "client" || n < 2) return e.label;
  return `${e.label ? e.label + " · " : ""}${n} VLANs`;
}

export interface VlanColors { bad: string; warn: string; muted: string; surface: string; ink: string }

export function vlanStyle(c: VlanColors): cytoscape.StylesheetStyle[] {
  return [
    // clients take their network's colour
    { selector: "node[kind = 'client'][netColor]", style: { "background-color": "data(netColor)", "border-color": "data(netColor)" } },
    // DMZ members get a heavy ring in the "bad" colour, so exposed hosts stand out
    { selector: "node[kind = 'client'][zone = 'dmz']", style: { "border-color": c.bad, "border-width": 3, width: 18, height: 18 } },
    { selector: "edge[origin = 'client'][netColor]", style: { "line-color": "data(netColor)", opacity: 0.8 } },
    // VLAN group boxes (Group by VLAN)
    { selector: "node.vlan-group", style: {
      shape: "round-rectangle", "background-color": "data(netColor)", "background-opacity": 0.07,
      "border-color": "data(netColor)", "border-width": 1.5, label: "data(display)", "text-valign": "top",
      "text-halign": "center", "text-margin-y": -4, "font-size": 11, "font-weight": "bold", color: "data(netColor)",
      padding: "18px", "text-wrap": "none",
    } as cytoscape.Css.Node },
    { selector: "node.vlan-group[zone = 'dmz']", style: { "border-color": c.bad, "border-style": "dashed", "border-width": 2.5, color: c.bad } },
    { selector: "node.vlan-group[zone = 'hotspot']", style: { "border-style": "dotted", "border-width": 2 } },
    // focus on one network: everything else fades, links that carry it thicken
    { selector: ".vlan-dim", style: { opacity: 0.15 } },
    { selector: "edge.vlan-hit", style: { "line-color": "data(focusColor)", width: 3, opacity: 1 } },
  ];
}
