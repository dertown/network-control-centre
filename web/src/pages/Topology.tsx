import { useEffect, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { api, Graph, GNode } from "../api";
import { discoveryLabel, kindLabel } from "../live";
import { topoStyle } from "../topoStyle";

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
      style: topoStyle(),
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

  // redraw with the new colours when the theme changes
  useEffect(() => {
    const restyle = () => cy.current?.style(topoStyle());
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    window.addEventListener("ncc-theme", restyle);
    mq.addEventListener("change", restyle);
    return () => { window.removeEventListener("ncc-theme", restyle); mq.removeEventListener("change", restyle); };
  }, []);

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
