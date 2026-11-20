import cytoscape from "cytoscape";
import { iconURI, kindIcon } from "./icons";
import { vlanStyle } from "./pages/topoVlan";

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

const shapes: Record<string, string> = {
  gateway: "round-rectangle",
  switch: "round-rectangle",
  "unmanaged-switch": "round-rectangle",
  ap: "ellipse",
  unknown: "round-diamond",
  client: "ellipse",
};

// topoStyle builds the Cytoscape stylesheet from the current theme's CSS variables. Call it
// again after a theme change and pass the result to cy.style().
export function topoStyle(): cytoscape.StylesheetStyle[] {
  const ink = cssVar("--ink"), quiet = cssVar("--muted"), lineStrong = cssVar("--line-strong"), surface = cssVar("--surface"),
    bad = cssVar("--bad"), warn = cssVar("--warn");
  const tone: Record<string, string> = {
    gateway: cssVar("--c1"),
    switch: cssVar("--c2"),
    "unmanaged-switch": quiet,
    ap: cssVar("--c3"),
    unknown: cssVar("--c4"),
    client: quiet,
  };
  const icons = new Map<string, string>();
  const icon = (kind: string, color: string) => {
    const k = `${kind}|${color}`;
    if (!icons.has(k)) icons.set(k, iconURI(kindIcon[kind] ?? "unknown", color, 1.7));
    return icons.get(k)!;
  };
  const colorOf = (ele: cytoscape.NodeSingular) => (ele.data("online") === false ? bad : tone[ele.data("kind")] ?? quiet);

  const sheet: { selector: string; style: Record<string, unknown> }[] = [
    { selector: "node", style: {
      shape: ((ele: cytoscape.NodeSingular) => shapes[ele.data("kind")] ?? "ellipse"),
      width: 50, height: 50,
      "background-color": colorOf, "background-opacity": 0.1,
      "border-width": 2,
      "border-color": colorOf,
      "background-image": ((ele: cytoscape.NodeSingular) => icon(ele.data("kind"), colorOf(ele))),
      "background-fit": "none", "background-width": "56%", "background-height": "56%", "background-clip": "none",
      label: "data(display)", "text-wrap": "wrap", "text-max-width": "170px", "text-valign": "bottom", "text-margin-y": 8,
      "font-size": 11, "font-weight": 600, color: ink, "line-height": 1.35,
      "text-background-color": surface, "text-background-opacity": 0.85, "text-background-padding": "2px", "text-background-shape": "roundrectangle",
      "underlay-color": colorOf, "underlay-opacity": 0, "underlay-padding": 8, "underlay-shape": "ellipse",
    } },
    { selector: "node[kind = 'gateway']", style: { width: 64, height: 64, "border-width": 3, "font-size": 12.5 } },
    { selector: "node[kind = 'unmanaged-switch'], node[kind = 'unknown']", style: { "border-style": "dashed", "background-opacity": 0.04, "font-weight": 500, color: quiet } },
    { selector: "node[kind = 'client']", style: {
      width: 22, height: 22, "border-width": 1, "background-width": "62%", "background-height": "62%",
      "font-size": 9, "font-weight": 400, color: quiet, "text-margin-y": 4, "background-opacity": 0.06,
    } },
    { selector: "node[!online][kind != 'client']", style: { "underlay-opacity": 0.12, "underlay-padding": 8 } },
    { selector: "node:selected", style: { "border-width": 3, "underlay-opacity": 0.22, "underlay-padding": 10, "overlay-opacity": 0 } },
    { selector: "edge", style: {
      width: ((e: cytoscape.EdgeSingular) => {
        const s = e.data("speed_mbps") ?? 0;
        return s >= 10000 ? 4 : s >= 2500 ? 3 : 2;
      }),
      "line-color": lineStrong, "curve-style": "bezier", label: "data(label)", "font-size": 9.5,
      color: quiet, "text-rotation": "autorotate", "text-background-color": surface, "text-background-opacity": 1,
      "text-background-padding": "3px", "text-background-shape": "roundrectangle", "text-border-width": 1,
      "text-border-color": lineStrong, "text-border-opacity": 0.6,
    } },
    { selector: "edge[medium = 'wireless']", style: { "line-style": "dashed", "line-dash-pattern": [6, 4], "line-color": tone.ap, "line-opacity": 0.7 } },
    { selector: "edge[origin = 'client']", style: { label: "", width: 1, "line-opacity": 0.6 } },
    { selector: "edge:selected", style: { "line-color": tone.gateway } },
  ];
  // @types/cytoscape lags behind the library (no underlay-* yet), so the sheet is typed loosely
  // the VLAN / firewall-zone layer goes last so it overrides the base colours
  return [...(sheet as unknown as cytoscape.StylesheetStyle[]), ...vlanStyle({ bad, warn, muted: quiet, surface, ink })];
}
