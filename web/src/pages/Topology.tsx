import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { api, Graph, GEdge, GNetwork, GNode } from "../api";
import { discoveryLabel, kindLabel } from "../live";
import { topoStyle } from "../topoStyle";
import { groupID, groupNodes, networkColors, trunkLabel, vlanText, zonePill, zoneText } from "./topoVlan";

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

type Selection = { type: "node"; node: GNode } | { type: "edge"; edge: GEdge } | { type: "network"; id: string };

function treeLayout(graph: Graph | null): cytoscape.LayoutOptions {
  return { name: "breadthfirst", directed: true, spacingFactor: 1.15, roots: graph?.nodes.filter((n) => n.kind === "gateway").map((n) => n.id) } as cytoscape.LayoutOptions;
}

// Grouped by VLAN, a force layout keeps each network's clients inside its box.
const groupLayout = { name: "cose", animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, nestingFactor: 0.9, padding: 30, randomize: true } as unknown as cytoscape.LayoutOptions;

function NetName({ id, nets, colors }: { id?: string; nets: Map<string, GNetwork>; colors: Map<string, string> }) {
  const n = id ? nets.get(id) : undefined;
  if (!n) return <span className="muted">unknown</span>;
  return (
    <span className="vlan-name"><i className="vlan-swatch" style={{ background: colors.get(n.id) }} />{n.name} <span className="muted small">{vlanText(n)}</span></span>
  );
}

export function Topology({ tick }: { tick: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const cy = useRef<Core | null>(null);
  const [withClients, setWithClients] = useState(false);
  const [grouped, setGrouped] = useState(false);
  const [focus, setFocus] = useState<string | null>(null);
  const [graph, setGraph] = useState<Graph | null>(null);
  const [selected, setSelected] = useState<Selection | null>(null);
  const lastMode = useRef(grouped);
  const showClients = withClients || grouped;

  useEffect(() => {
    api<Graph>("GET", `/api/topology${showClients ? "?clients=1" : ""}`).then(setGraph).catch(() => {});
  }, [tick, showClients]);

  const nets = useMemo(() => new Map((graph?.networks ?? []).map((n) => [n.id, n])), [graph]);
  const colors = useMemo(() => networkColors(graph?.networks, cssVar("--muted")), [graph]);
  const lanNets = (graph?.networks ?? []).filter((n) => n.purpose !== "wan");

  useEffect(() => {
    if (!ref.current || !graph) return;
    const positions = new Map<string, cytoscape.Position>();
    // switching between tree and VLAN groups starts a fresh layout
    if (lastMode.current === grouped) cy.current?.nodes().forEach((n) => { positions.set(n.id(), { ...n.position() }); });
    lastMode.current = grouped;
    cy.current?.destroy();
    const groups = grouped ? groupNodes(graph.nodes, graph.networks, colors) : [];
    const boxed = new Set(groups.map((g) => g.data.network));
    const layoutFor = () => (grouped ? groupLayout : treeLayout(graph));
    const inst = cytoscape({
      container: ref.current,
      elements: [
        ...groups,
        // The API's "parent" is the device a client hangs off; cytoscape would read it as a
        // compound parent, so it is replaced by the client's VLAN box when grouping.
        ...graph.nodes.map(({ parent: _parent, ...n }) => ({
          data: {
            ...n, netColor: n.network ? colors.get(n.network) : undefined,
            parent: grouped && n.kind === "client" && n.network && boxed.has(n.network) ? groupID(n.network) : undefined,
            display: n.kind === "client" || !n.model || n.model === n.label ? n.label : `${n.label}\n${n.model}`,
          },
        })),
        ...graph.edges.map((e) => ({
          data: { ...e, label: trunkLabel(e), netColor: e.origin === "client" && e.networks?.length === 1 ? colors.get(e.networks[0]) : undefined },
        })),
      ],
      style: topoStyle(),
      layout: positions.size
        ? { name: "preset", positions: (n: cytoscape.NodeSingular) => positions.get(n.id()) ?? { x: 0, y: 0 } } as cytoscape.LayoutOptions
        : layoutFor(),
      wheelSensitivity: 0.3,
    });
    // brand-new nodes (not in the last layout) get a fresh layout pass
    if (positions.size && graph.nodes.some((n) => !positions.has(n.id))) {
      inst.layout(layoutFor()).run();
    }
    inst.on("tap", "node", (ev) => {
      const d = ev.target.data();
      setSelected(d.kind === "vlan-group" ? { type: "network", id: d.network } : { type: "node", node: d as GNode });
    });
    inst.on("tap", "edge", (ev) => setSelected({ type: "edge", edge: ev.target.data() as GEdge }));
    inst.on("tap", (ev) => { if (ev.target === inst) setSelected(null); });
    cy.current = inst;
  }, [graph, grouped, colors]);

  // focus one network: fade what is not on it, thicken the links that carry it
  useEffect(() => {
    const inst = cy.current;
    if (!inst) return;
    inst.elements().removeClass("vlan-dim vlan-hit");
    if (!focus) return;
    const hits = inst.edges().filter((e) => (e.data("networks") as string[] | undefined)?.includes(focus) ?? false);
    hits.addClass("vlan-hit").data("focusColor", colors.get(focus));
    const keep = hits.connectedNodes().union(inst.nodes().filter((n) => n.data("network") === focus || n.id() === groupID(focus)));
    inst.elements().difference(keep.union(hits)).addClass("vlan-dim");
  }, [focus, graph, grouped, colors]);

  useEffect(() => () => cy.current?.destroy(), []);

  // redraw with the new colours when the theme changes
  useEffect(() => {
    const restyle = () => cy.current?.style(topoStyle());
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    window.addEventListener("ncc-theme", restyle);
    mq.addEventListener("change", restyle);
    return () => { window.removeEventListener("ncc-theme", restyle); mq.removeEventListener("change", restyle); };
  }, []);

  const relayout = () => cy.current?.layout(grouped ? groupLayout : treeLayout(graph)).run();
  const sel = selected?.type === "node" ? selected.node : null;

  return (
    <>
      <h1>Topology</h1>
      <div className="toolbar">
        <label className="check"><input type="checkbox" checked={showClients} disabled={grouped} onChange={(e) => setWithClients(e.target.checked)} /> Show clients</label>
        <label className="check" title="Draw a box per VLAN around its clients">
          <input type="checkbox" checked={grouped} disabled={!lanNets.length} onChange={(e) => setGrouped(e.target.checked)} /> Group by VLAN
        </label>
        <button onClick={relayout}>Re-arrange</button>
        <span className="muted small">Solid lines are cables, dashed lines are wireless. Dashed outlines are switches NCC found but UniFi does not manage. Red outline: offline. Clients are coloured by VLAN; a red ring marks a DMZ host.</span>
      </div>
      {lanNets.length > 0 && (
        <div className="vlan-legend" role="group" aria-label="Networks">
          {lanNets.map((n) => (
            <button key={n.id} className={`vlan-chip${focus === n.id ? " on" : ""}`} aria-pressed={focus === n.id}
              title={focus === n.id ? "Show all networks" : `Highlight ${n.name} and the links that carry it`}
              onClick={() => setFocus(focus === n.id ? null : n.id)}>
              <i className="vlan-swatch" style={{ background: colors.get(n.id) }} />
              <span>{n.name}</span>
              <span className="muted small">{vlanText(n)}</span>
              {n.zone && <span className={`pill ${zonePill[n.zone] ?? ""}`}>{zoneText(n)}</span>}
              <span className="muted small">{n.clients} client{n.clients === 1 ? "" : "s"}</span>
            </button>
          ))}
        </div>
      )}
      <div className="topo">
        <div ref={ref} className="topo-canvas" />
        {sel && (
          <aside className="card topo-side">
            <h2>{sel.label}</h2>
            <dl className="kv">
              <dt>Kind</dt><dd>{kindLabel[sel.kind] ?? sel.kind}</dd>
              {sel.make && (<><dt>{sel.kind === "client" ? "Vendor" : "Make"}</dt><dd>{sel.make}</dd></>)}
              {sel.model && (<><dt>Model</dt><dd>{sel.model}</dd></>)}
              {sel.ip && (<><dt>IP</dt><dd className="mono">{sel.ip}</dd></>)}
              <dt>MAC / id</dt><dd className="mono small">{sel.id}</dd>
              {sel.discovery && (<><dt>Found by</dt><dd>{discoveryLabel[sel.discovery] ?? sel.discovery}</dd></>)}
              {sel.clients ? (<><dt>Clients</dt><dd>{sel.clients}</dd></>) : null}
              {sel.network && (<><dt>{sel.kind === "client" ? "Network" : "Mgmt network"}</dt><dd><NetName id={sel.network} nets={nets} colors={colors} /></dd></>)}
              {!sel.network && sel.vlan ? (<><dt>VLAN</dt><dd>{sel.vlan}</dd></>) : null}
              {sel.zone && (<><dt>Zone</dt><dd><span className={`pill ${zonePill[sel.zone] ?? ""}`}>{zoneText(nets.get(sel.network ?? "") ?? { zone: sel.zone })}</span></dd></>)}
              {sel.ssid && (<><dt>SSID</dt><dd>{sel.ssid}</dd></>)}
            </dl>
            {sel.ports && sel.ports.length > 0 && (
              <>
                <h3 className="small">Port VLANs</h3>
                <table className="vlan-ports small">
                  <thead><tr><th>Port</th><th>Untagged</th><th>Tagged</th></tr></thead>
                  <tbody>
                    {sel.ports.map((p) => (
                      <tr key={p.name} className={p.up ? "" : "muted"}>
                        <td>{p.name}{p.profile && <div className="muted">{p.profile}</div>}</td>
                        <td>{p.native ? <NetName id={p.native} nets={nets} colors={colors} /> : <span className="muted">none</span>}</td>
                        <td>{p.tagged?.length ? p.tagged.map((t) => <div key={t}><NetName id={t} nets={nets} colors={colors} /></div>) : <span className="muted">none</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </>
            )}
            {sel.ip && (
              <a className="button" href={`#/dns?ip=${encodeURIComponent(sel.ip)}&name=${encodeURIComponent(sel.label.toLowerCase().replace(/[^a-z0-9-]+/g, "-"))}`}>
                Add DNS record…
              </a>
            )}
          </aside>
        )}
        {selected?.type === "edge" && (
          <aside className="card topo-side">
            <h2>Link</h2>
            <dl className="kv">
              {selected.edge.label && (<><dt>Ports</dt><dd>{selected.edge.label}</dd></>)}
              <dt>Medium</dt><dd>{selected.edge.medium === "wireless" ? "Wireless" : "Cable"}</dd>
              {selected.edge.speed_mbps ? (<><dt>Speed</dt><dd>{selected.edge.speed_mbps} Mbps</dd></>) : null}
            </dl>
            <h3 className="small">Networks carried</h3>
            {selected.edge.networks?.length
              ? <ul className="vlan-list">{selected.edge.networks.map((id) => <li key={id}><NetName id={id} nets={nets} colors={colors} /></li>)}</ul>
              : <p className="muted small">Unknown. UniFi did not report VLAN settings for this port.</p>}
          </aside>
        )}
        {selected?.type === "network" && nets.get(selected.id) && (() => {
          const n = nets.get(selected.id)!;
          return (
            <aside className="card topo-side">
              <h2><NetName id={n.id} nets={nets} colors={colors} /></h2>
              <dl className="kv">
                {n.subnet && (<><dt>Subnet</dt><dd className="mono">{n.subnet}</dd></>)}
                {n.zone && (<><dt>Zone</dt><dd><span className={`pill ${zonePill[n.zone] ?? ""}`}>{zoneText(n)}</span>
                  {n.zone_source === "inferred" && <div className="muted small">Guessed from the network's name and purpose; this console has no zone-based firewall.</div>}</dd></>)}
                {n.purpose && (<><dt>Purpose</dt><dd>{n.purpose}</dd></>)}
                <dt>Isolated</dt><dd>{n.isolated ? "Yes" : "No"}</dd>
                <dt>Internet</dt><dd>{n.internet_access ? "Allowed" : "Blocked"}</dd>
                {n.ssids?.length ? (<><dt>Wi-Fi</dt><dd>{n.ssids.join(", ")}</dd></>) : null}
                <dt>Clients</dt><dd>{n.clients}</dd>
              </dl>
            </aside>
          );
        })()}
      </div>
      {graph && graph.nodes.length === 0 && <p className="muted">No topology yet. Add your UniFi console in <a href="#/settings">Settings</a>.</p>}
    </>
  );
}
