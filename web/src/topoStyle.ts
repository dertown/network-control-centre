import cytoscape from "cytoscape";
import { iconURI, kindIcon } from "./icons";
import { vlanStyle } from "./pages/topoVlan";
import { TAXI_TURN } from "./pages/topoLayout";

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// mix blends colour a into colour b (both #rrggbb); t is the share of a.
function mix(a: string, b: string, t: number): string {
  const p = (h: string) => { const v = h.replace("#", ""); const f = v.length === 3 ? v.split("").map((c) => c + c).join("") : v; return [0, 2, 4].map((i) => parseInt(f.slice(i, i + 2), 16)); };
  if (!/^#[0-9a-f]{3,6}$/i.test(a) || !/^#[0-9a-f]{3,6}$/i.test(b)) return b;
  const [x, y] = [p(a), p(b)];
  return "#" + x.map((v, i) => Math.round(v * t + y[i] * (1 - t)).toString(16).padStart(2, "0")).join("");
}

function dotURI(fill: string, ring: string) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><circle cx="8" cy="8" r="6.2" fill="${fill}" stroke="${ring}" stroke-width="2.4"/></svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

// topoStyle builds the Cytoscape stylesheet from the current theme's CSS variables. Call it
// again after a theme change and pass the result to cy.style().
export function topoStyle(): cytoscape.StylesheetStyle[] {
  const ink = cssVar("--ink"), quiet = cssVar("--muted"), lineStrong = cssVar("--line-strong"),
    surface = cssVar("--surface"), surface2 = cssVar("--surface-2"), bad = cssVar("--bad"), warn = cssVar("--warn"), good = cssVar("--good");
  const tone: Record<string, string> = {
    internet: cssVar("--info"),
    gateway: cssVar("--c1"),
    switch: cssVar("--c2"),
    "unmanaged-switch": quiet,
    ap: cssVar("--c3"),
    unknown: cssVar("--c4"),
    client: quiet,
  };
  const cache = new Map<string, string>();
  const memo = (k: string, f: () => string) => { if (!cache.has(k)) cache.set(k, f()); return cache.get(k)!; };
  const offline = (ele: cytoscape.NodeSingular) => ele.data("online") === false;
  const colorOf = (ele: cytoscape.NodeSingular) => (offline(ele) ? bad : tone[ele.data("kind")] ?? quiet);
  const tint = (ele: cytoscape.NodeSingular) => memo(`tint|${colorOf(ele)}`, () => mix(colorOf(ele), surface, 0.1));
  const icon = (ele: cytoscape.NodeSingular) => memo(`icon|${ele.data("kind")}|${colorOf(ele)}`, () => iconURI(kindIcon[ele.data("kind")] ?? "unknown", colorOf(ele), 1.7));
  const dot = (ele: cytoscape.NodeSingular) => memo(`dot|${offline(ele)}`, () => dotURI(offline(ele) ? bad : good, surface));
  const loopColor = (e: cytoscape.SingularElementArgument) => (e.data("loopSev") === "critical" ? bad : warn);

  const sheet: { selector: string; style: Record<string, unknown> }[] = [
    // devices: a tinted tile with the device icon and a status dot in the corner
    { selector: "node", style: {
      shape: "round-rectangle", "corner-radius": 14, width: 58, height: 58,
      "background-color": tint, "background-opacity": 1,
      "border-width": 1.5, "border-color": colorOf,
      "background-image": ((ele: cytoscape.NodeSingular) => [icon(ele), dot(ele)]),
      "background-fit": ["none", "none"], "background-width": ["54%", "15px"], "background-height": ["54%", "15px"],
      "background-position-x": ["50%", "100%"], "background-position-y": ["50%", "0%"],
      "background-offset-x": [0, 5], "background-offset-y": [0, -5],
      "background-clip": ["none", "none"], "background-image-containment": ["inside", "over"], "bounds-expansion": 6,
      label: "data(display)", "text-wrap": "wrap", "text-max-width": "164px", "text-valign": "bottom", "text-margin-y": 8,
      "font-size": 11.5, "font-weight": 600, color: ink, "line-height": 1.3,
      "text-background-color": surface, "text-background-opacity": 0.9, "text-background-padding": "2px", "text-background-shape": "roundrectangle",
      "underlay-color": colorOf, "underlay-opacity": 0, "underlay-padding": 8, "underlay-shape": "round-rectangle", "underlay-corner-radius": 20,
      "transition-property": "opacity", "transition-duration": 150,
    } },
    { selector: "node[kind = 'gateway']", style: { width: 66, height: 66, "border-width": 2, "font-size": 12.5, "corner-radius": 16 } },
    { selector: "node[kind = 'internet']", style: {
      shape: "ellipse", width: 62, height: 62, "border-style": "dashed", "background-image": ((ele: cytoscape.NodeSingular) => [icon(ele)]),
      "background-width": ["58%"], "background-height": ["58%"], "background-position-x": ["50%"], "background-position-y": ["50%"],
      "background-offset-x": [0], "background-offset-y": [0], "background-fit": ["none"], "background-clip": ["none"], "background-image-containment": ["inside"],
      color: quiet,
    } },
    { selector: "node[kind = 'ap']", style: { shape: "ellipse" } },
    { selector: "node[kind = 'unmanaged-switch'], node[kind = 'unknown']", style: { "border-style": "dashed", "font-weight": 500, color: quiet } },
    { selector: "node[kind = 'client']", style: {
      shape: "ellipse", width: 20, height: 20, "border-width": 1.5,
      "background-image": ((ele: cytoscape.NodeSingular) => [icon(ele)]), "background-width": ["64%"], "background-height": ["64%"],
      "background-position-x": ["50%"], "background-position-y": ["50%"], "background-offset-x": [0], "background-offset-y": [0],
      "background-fit": ["none"], "background-clip": ["none"], "background-image-containment": ["inside"],
      "font-size": 9.5, "font-weight": 500, color: quiet, "text-margin-y": 4, "text-max-width": "80px", "text-wrap": "ellipsis",
    } },
    // a device's clients sit together in one soft block under it
    { selector: "node.client-cluster", style: {
      shape: "round-rectangle", "corner-radius": 12, "background-color": surface2, "background-opacity": 0.9, "background-image": "none",
      "border-width": 1, "border-style": "dashed", "border-color": lineStrong, padding: "12px",
      label: "data(display)", "text-valign": "bottom", "text-halign": "center", "text-margin-y": 5, "font-size": 10.5, "font-weight": 600,
      color: quiet, "text-background-opacity": 0, "underlay-opacity": 0,
    } },
    { selector: "node[!online][kind != 'client']", style: { "underlay-opacity": 0.1 } },
    { selector: "node:selected", style: { "border-width": 3, "underlay-opacity": 0.2, "underlay-padding": 9, "overlay-opacity": 0 } },
    { selector: "node.client-cluster:selected", style: { "border-width": 1.5, "underlay-opacity": 0 } },

    // links: right angles down the tree, gentle arcs for extra links that close a ring
    { selector: "edge", style: {
      width: ((e: cytoscape.EdgeSingular) => {
        const s = e.data("speed_mbps") ?? 0;
        return s >= 10000 ? 4 : s >= 2500 ? 3 : 2;
      }),
      "line-color": lineStrong, "curve-style": "bezier", label: "data(label)", "font-size": 9.5, "text-opacity": 0,
      color: quiet, "text-rotation": "none", "text-background-color": surface, "text-background-opacity": 1,
      "text-background-padding": "3px", "text-background-shape": "roundrectangle", "text-border-width": 1,
      "text-border-color": lineStrong, "text-border-opacity": 0.8, "line-cap": "round",
      "transition-property": "opacity", "transition-duration": 150,
    } },
    { selector: "edge.tree", style: {
      "curve-style": "taxi", "taxi-direction": "vertical", "taxi-radius": 10, "taxi-turn-min-distance": 6,
      "taxi-turn": ((e: cytoscape.EdgeSingular) => `${e.data("flip") ? -TAXI_TURN : TAXI_TURN}px`),
    } },
    { selector: "edge.cross", style: { "curve-style": "unbundled-bezier", "control-point-distances": [110], "control-point-weights": [0.5], "text-rotation": "autorotate" } },
    { selector: "edge[origin = 'wan']", style: { "line-color": tone.internet, "line-style": "dashed", "line-dash-pattern": [2, 5], width: 2.5 } },
    { selector: "edge[medium = 'wireless']", style: { "line-style": "dashed", "line-dash-pattern": [6, 5], "line-color": tone.ap, "line-opacity": 0.8 } },
    { selector: "edge[origin = 'cluster']", style: { width: 1.5, "line-color": lineStrong } },
    { selector: "edge.in-cluster", style: { display: "none" } },
    { selector: "edge[origin = 'client']", style: { label: "", width: 1, "line-opacity": 0.45, "curve-style": "straight" } },
    { selector: "edge.show-label, edge.hl, edge:selected", style: { "text-opacity": 1 } },
    { selector: "edge:selected", style: { "line-color": tone.gateway, "overlay-opacity": 0 } },
    // VLAN / DMZ rules from the VLAN view, then the tweaks they need on top of this look
    ...(vlanStyle({ bad, warn, muted: quiet, surface, ink }) as unknown as { selector: string; style: Record<string, unknown> }[]),
    // a client coloured by its VLAN is a solid dot; the icon would be unreadable at that size
    { selector: "node[kind = 'client'][netColor]", style: { "background-opacity": 0.9, "background-image": "none" } },
    { selector: "node[kind = 'client'][zone = 'dmz']", style: { "underlay-color": bad, "underlay-opacity": 0.18, "underlay-padding": 4, "underlay-shape": "ellipse" } },
    // switching loops: red when nothing stops them, amber when spanning tree holds them shut
    { selector: "edge[loopSev]", style: { width: 4, "line-color": loopColor, "line-style": "solid", "line-opacity": 1,
      color: loopColor, "text-border-color": loopColor } },
    { selector: "edge[origin = 'loop']", style: { "text-opacity": 1, "curve-style": "bezier", "line-style": "dashed", "line-dash-pattern": [8, 4], "loop-direction": "-45deg", "loop-sweep": "-70deg", "control-point-step-size": 60 } },
    { selector: "node[loopSev]", style: { "underlay-color": loopColor, "underlay-opacity": 0.22, "underlay-padding": 10 } },
    { selector: ".loop-dim", style: { opacity: 0.15 } },
    { selector: "edge.loop-hit", style: { width: 6, "text-opacity": 1 } },
    // VLAN boxes are containers, not devices: no icon, halo or label plate
    { selector: "node.vlan-group", style: {
      "background-image": "none", "underlay-opacity": 0, "text-background-opacity": 0, "font-size": 11.5,
      "text-valign": "top", "text-margin-y": -6, "corner-radius": 14,
    } },
    // hovering a device lights up what it is connected to
    { selector: ".hover-fade", style: { opacity: 0.18 } },
    { selector: "edge.hl", style: { "line-opacity": 1, opacity: 1, "z-index": 10 } },
  ];
  // @types/cytoscape lags behind the library (no underlay-* yet), so the sheet is typed loosely
  return sheet as unknown as cytoscape.StylesheetStyle[];
}
