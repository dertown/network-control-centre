import { useEffect, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { api, Graph, GNode } from "../api";
import { discoveryLabel, kindLabel } from "../live";

const shapes: Record<string, string> = {
  gateway: "round-hexagon",
  switch: "round-rectangle",
  "unmanaged-switch": "round-rectangle",
  ap: "ellipse",
  unknown: "round-diamond",
  client: "ellipse",
};

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

export function Topology({ tick }: { tick: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [withClients, setWithClients] = useState(false);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [selected, setSelected] = useState<GNode | null>(null);

  useEffect(() => {
    api<Graph>("GET", `/api/topology${withClients ? "?clients=1" : ""}`).then(setGraph).catch(() => {});
  }, [tick, withClients]);

  useEffect(() => {
    if (!ref.current || !graph) return;
    const ink = cssVar("--ink"), quiet = cssVar("--muted"), line = cssVar("--line"), accent = cssVar("--accent"),
      bad = cssVar("--bad"), surface = cssVar("--surface");
    const positions = new Map<string, cytoscape.Position>();
    cy.current?.nodes().forEach((n) => { positions.set(n.id(), { ...n.position() }); });
    cy.current?.destroy();
    const inst = cytoscape({
      container: ref.current,
      elements: [
        // "parent" would make cytoscape draw compound nodes, so the API's parent link is dropped here
        ...graph.nodes.map(({ parent: _parent, ...n }) => ({
          data: { ...n, display: n.kind === "client" || !n.model || n.model === n.label ? n.label : `${n.label}\n${n.model}` },
        })),
        ...graph.edges.map((e) => ({ data: { ...e } })),
      ],
      style: [
        { selector: "node", style: {
          shape: ((ele: cytoscape.NodeSingular) => shapes[ele.data("kind")] ?? "ellipse") as unknown as cytoscape.Css.NodeShape,
          "background-color": surface, "border-width": 2, "border-color": accent,
          label: "data(display)", "text-wrap": "wrap", "text-valign": "bottom", "text-margin-y": 6,
          "font-size": 11, color: ink, width: 44, height: 32,
        } },
        { selector: "node[kind = 'gateway']", style: { width: 60, height: 44, "border-width": 3 } },
        { selector: "node[kind = 'unmanaged-switch'], node[kind = 'unknown']", style: { "border-style": "dashed", "border-color": quiet } },
        { selector: "node[kind = 'client']", style: { width: 14, height: 14, "border-width": 1, "border-color": quiet, "font-size": 9, color: quiet } },
        { selector: "node[?online][kind != 'client']", style: {} },
        { selector: "node[!online]", style: { "border-color": bad, "background-color": surface } },
        { selector: "node:selected", style: { "overlay-opacity": 0.12, "overlay-color": accent } },
        { selector: "edge", style: {
          width: 1.5, "line-color": line, "curve-style": "bezier", label: "data(label)", "font-size": 9,
          color: quiet, "text-rotation": "autorotate", "text-background-color": surface, "text-background-opacity": 1,
        } },
        { selector: "edge[medium = 'wireless']", style: { "line-style": "dashed" } },
        { selector: "edge[origin = 'client']", style: { label: "", width: 1 } },
      ],
      layout: positions.size
        ? { name: "preset", positions: (n: cytoscape.NodeSingular) => positions.get(n.id()) ?? { x: 0, y: 0 } } as cytoscape.LayoutOptions
        : { name: "breadthfirst", directed: true, spacingFactor: 1.15, roots: graph.nodes.filter((n) => n.kind === "gateway").map((n) => n.id) } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.3,
    });
    // brand-new nodes (not in the last layout) get a fresh layout pass
    if (positions.size && graph.nodes.some((n) => !positions.has(n.id))) {
      inst.layout({ name: "breadthfirst", directed: true, spacingFactor: 1.15, roots: graph.nodes.filter((n) => n.kind === "gateway").map((n) => n.id) } as cytoscape.LayoutOptions).run();
    }
    inst.on("tap", "node", (ev) => setSelected(ev.target.data() as GNode));
    inst.on("tap", (ev) => { if (ev.target === inst) setSelected(null); });
    cy.current = inst;
  }, [graph]);

  useEffect(() => () => cy.current?.destroy(), []);

  const relayout = () =>
    cy.current?.layout({ name: "breadthfirst", directed: true, spacingFactor: 1.15, roots: graph?.nodes.filter((n) => n.kind === "gateway").map((n) => n.id) } as cytoscape.LayoutOptions).run();

  return (
    <>
      <h1>Topology</h1>
      <div className="toolbar">
        <label className="check"><input type="checkbox" checked={withClients} onChange={(e) => setWithClients(e.target.checked)} /> Show clients</label>
        <button onClick={relayout}>Re-arrange</button>
        <span className="muted small">Solid lines are cables, dashed lines are wireless. Dashed outlines are switches NCC found but UniFi does not manage. Red outline: offline.</span>
      </div>
      <div className="topo">
        <div ref={ref} className="topo-canvas" />
        {selected && (
          <aside className="card topo-side">
            <h2>{selected.label}</h2>
            <dl className="kv">
              <dt>Kind</dt><dd>{kindLabel[selected.kind] ?? selected.kind}</dd>
              {selected.make && (<><dt>{selected.kind === "client" ? "Vendor" : "Make"}</dt><dd>{selected.make}</dd></>)}
              {selected.model && (<><dt>Model</dt><dd>{selected.model}</dd></>)}
              {selected.ip && (<><dt>IP</dt><dd className="mono">{selected.ip}</dd></>)}
              <dt>MAC / id</dt><dd className="mono small">{selected.id}</dd>
              {selected.discovery && (<><dt>Found by</dt><dd>{discoveryLabel[selected.discovery] ?? selected.discovery}</dd></>)}
              {selected.clients ? (<><dt>Clients</dt><dd>{selected.clients}</dd></>) : null}
            </dl>
            {selected.ip && (
              <a className="button" href={`#/dns?ip=${encodeURIComponent(selected.ip)}&name=${encodeURIComponent(selected.label.toLowerCase().replace(/[^a-z0-9-]+/g, "-"))}`}>
                Add DNS record…
              </a>
            )}
          </aside>
        )}
      </div>
      {graph && graph.nodes.length === 0 && <p className="muted">No topology yet. Add your UniFi console in <a href="#/settings">Settings</a>.</p>}
    </>
  );
}
