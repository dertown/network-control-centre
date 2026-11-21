import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { Core } from "cytoscape";
import { api, Graph, GEdge, GNetwork, GNode, Loop } from "../api";
import { LoopList, worstLoop } from "../loops";
import { discoveryLabel, kindLabel } from "../live";
import { topoStyle } from "../topoStyle";
import { clusterID, clusterLinkID, INTERNET, planLayout, wanLinkID } from "./topoLayout";
import { Icon } from "../icons";
import { groupID, groupNodes, networkColors, trunkLabel, vlanText, zonePill, zoneText } from "./topoVlan";

function cssVar(name: string) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

type Selection = { type: "node"; node: GNode } | { type: "edge"; edge: GEdge } | { type: "network"; id: string };

function fitView(inst: Core) {
  inst.resize();
  inst.fit(undefined, 48);
  if (inst.zoom() > 1.15) { inst.zoom(1.15); inst.center(); }
}

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
  const [loopFocus, setLoopFocus] = useState<string | null>(null);
  const [portLabels, setPortLabels] = useState(false);
  const [legend, setLegendState] = useState(() => { try { return localStorage.getItem("ncc-topo-key") !== "hidden"; } catch { return true; } });
  const setLegend = (on: boolean) => { setLegendState(on); try { localStorage.setItem("ncc-topo-key", on ? "shown" : "hidden"); } catch { /* storage blocked */ } };
  const [query, setQuery] = useState("");
  const [miss, setMiss] = useState(false);
  const [layoutRun, setLayoutRun] = useState(0);
  const showClients = withClients || grouped;
  const mode = `${grouped}|${showClients}`;
  const lastMode = useRef(mode);
  const lastRun = useRef(0);

  useEffect(() => {
    api<Graph>("GET", `/api/topology${showClients ? "?clients=1" : ""}`).then(setGraph).catch(() => {});
  }, [tick, showClients]);

  const nets = useMemo(() => new Map((graph?.networks ?? []).map((n) => [n.id, n])), [graph]);
  const colors = useMemo(() => networkColors(graph?.networks, cssVar("--muted")), [graph]);
  const lanNets = (graph?.networks ?? []).filter((n) => n.purpose !== "wan");
  const loops = graph?.loops ?? [];
  const loopsByID = useMemo(() => new Map((graph?.loops ?? []).map((l) => [l.id, l])), [graph]);

  useEffect(() => {
    if (!ref.current || !graph) return;
    const positions = new Map<string, cytoscape.Position>();
    // switching between modes, or asking for a tidy-up, starts a fresh layout
    const fresh = lastMode.current !== mode || layoutRun !== lastRun.current;
    if (!fresh) cy.current?.nodes().forEach((n) => { positions.set(n.id(), { ...n.position() }); });
    lastMode.current = mode;
    lastRun.current = layoutRun;
    const zoom = !fresh && cy.current ? { zoom: cy.current.zoom(), pan: { ...cy.current.pan() } } : null;
    cy.current?.destroy();
    const groups = grouped ? groupNodes(graph.nodes, graph.networks, colors) : [];
    const boxed = new Set(groups.map((g) => g.data.network));
    const clients = graph.nodes.filter((n) => n.kind === "client");
    const boxOf = (n: GNode) => (grouped && n.network && boxed.has(n.network) ? groupID(n.network) : undefined);
    const plan = planLayout(graph.nodes, graph.edges, {
      withClusters: showClients && !grouped,
      groups: grouped ? [
        ...groups.map((g) => ({ id: g.data.id, members: clients.filter((c) => boxOf(c) === g.data.id).map((c) => c.id) })),
        { id: "unboxed", members: clients.filter((c) => !boxOf(c)).map((c) => c.id) },
      ] : undefined,
    });
    const clusterOf = new Map(plan.clusters.flatMap((c) => c.members.map((m) => [m, clusterID(c.device)] as const)));
    const infra = new Set(graph.nodes.filter((n) => n.kind !== "client").map((n) => n.id));
    const inst = cytoscape({
      container: ref.current,
      elements: [
        ...groups,
        ...(plan.internet.length ? [{ data: { id: INTERNET, label: "Internet", kind: "internet", online: true, display: "Internet" } }] : []),
        ...plan.internet.map((g) => ({ data: { id: wanLinkID(g), source: INTERNET, target: g, origin: "wan", medium: "wired", label: "WAN" }, classes: "tree" })),
        ...plan.clusters.map((c) => ({
          data: { id: clusterID(c.device), kind: "client-cluster", device: c.device, display: `${c.members.length} client${c.members.length === 1 ? "" : "s"}` },
          classes: "client-cluster",
        })),
        ...plan.clusters.map((c) => ({
          data: { id: clusterLinkID(c.device), source: c.device, target: clusterID(c.device), origin: "cluster", medium: c.wireless ? "wireless" : "wired" },
          classes: "tree",
        })),
        // The API's "parent" is the device a client hangs off; cytoscape would read it as a
        // compound parent, so it is replaced by the client's block or VLAN box.
        ...graph.nodes.map(({ parent: _parent, ...n }) => ({
          data: {
            ...n, netColor: n.network ? colors.get(n.network) : undefined,
            parent: n.kind === "client" ? boxOf(n) ?? clusterOf.get(n.id) : undefined,
            display: n.kind === "client" || n.kind === "unmanaged-switch" || !n.model || n.model === n.label ? n.label : `${n.label}\n${n.model}`,
            loopSev: worstLoop(n.loops, loopsByID),
          },
        })),
        ...graph.edges.map((e) => ({
          data: {
            ...e, label: e.origin === "loop" ? e.label : trunkLabel(e), loopSev: worstLoop(e.loops, loopsByID),
            netColor: e.origin === "client" && e.networks?.length === 1 ? colors.get(e.networks[0]) : undefined,
            flip: plan.flipped.has(e.id) || undefined,
          },
          classes: [
            plan.treeEdges.has(e.id) ? "tree" : infra.has(e.source) && infra.has(e.target) && e.source !== e.target ? "cross" : "",
            e.origin === "client" && clusterOf.has(e.target) ? "in-cluster" : "",
          ].join(" ").trim(),
        })),
      ],
      style: topoStyle(),
      layout: { name: "preset", positions: (n: cytoscape.NodeSingular) => positions.get(n.id()) ?? plan.positions.get(n.id()) ?? { x: 0, y: 0 } } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.3,
      minZoom: 0.15, maxZoom: 3,
    });
    // brand-new devices or clients (not in the last layout) put everything back in its tier
    const relaid = positions.size > 0 && graph.nodes.some((n) => !positions.has(n.id));
    if (relaid) inst.nodes().forEach((n) => { const p = plan.positions.get(n.id()); if (p && !n.isParent()) n.position(p); });
    if (zoom && positions.size && !relaid) inst.viewport(zoom);
    else { fitView(inst); requestAnimationFrame(() => { if (!inst.destroyed()) fitView(inst); }); }
    inst.on("tap", "node", (ev) => {
      const d = ev.target.data();
      if (d.kind === "vlan-group") setSelected({ type: "network", id: d.network });
      else if (d.kind === "client-cluster") setSelected({ type: "node", node: graph.nodes.find((n) => n.id === d.device)! });
      else setSelected({ type: "node", node: d as GNode });
    });
    inst.on("tap", "edge", (ev) => {
      const d = ev.target.data();
      if (d.origin === "cluster" || d.origin === "wan") return;
      setSelected({ type: "edge", edge: d as GEdge });
    });
    inst.on("tap", (ev) => { if (ev.target === inst) setSelected(null); });
    // hover: light up the device, its links and what is on the other end
    inst.on("mouseover", "node", (ev) => {
      const n = ev.target as cytoscape.NodeSingular;
      if (n.isParent() && !n.hasClass("client-cluster")) return;
      let keep = n.closedNeighborhood();
      if (n.isChild()) keep = keep.union(n.parent()).union((n.parent() as cytoscape.NodeCollection).closedNeighborhood());
      keep = keep.union(keep.nodes(".client-cluster").children()).union(n.children());
      keep.edges().addClass("hl");
      inst.elements().difference(keep).not(".vlan-group").addClass("hover-fade");
    });
    inst.on("mouseout", "node", () => { inst.elements().removeClass("hover-fade hl"); });
    cy.current = inst;
  }, [graph, grouped, showClients, colors, loopsByID, layoutRun]);

  useEffect(() => { cy.current?.edges().toggleClass("show-label", portLabels); }, [portLabels, graph, grouped, showClients, layoutRun]);

  // focus one loop: fade everything that is not on it
  useEffect(() => {
    const inst = cy.current;
    if (!inst) return;
    inst.elements().removeClass("loop-dim loop-hit");
    if (!loopFocus) return;
    const on = (ele: cytoscape.SingularElementArgument) => ((ele.data("loops") as string[] | undefined) ?? []).includes(loopFocus);
    const hits = inst.elements().filter(on);
    hits.addClass("loop-hit");
    inst.elements().difference(hits.union(hits.connectedNodes())).addClass("loop-dim");
    if (hits.length) {
      // frame the loop, without zooming far in on a loop that sits on one switch
      inst.fit(hits.union(hits.connectedNodes()), 80);
      if (inst.zoom() > 1.3) { inst.zoom(1.3); inst.center(hits); }
    }
  }, [loopFocus, graph, grouped]);

  // focus one network: fade what is not on it, thicken the links that carry it
  useEffect(() => {
    const inst = cy.current;
    if (!inst) return;
    inst.elements().removeClass("vlan-dim vlan-hit");
    if (!focus) return;
    const hits = inst.edges().filter((e) => (e.data("networks") as string[] | undefined)?.includes(focus) ?? false);
    hits.addClass("vlan-hit").data("focusColor", colors.get(focus));
    let keep = hits.connectedNodes().union(inst.nodes().filter((n) => n.data("network") === focus || n.id() === groupID(focus)));
    keep = keep.union(keep.parents()).union(keep.nodes().connectedEdges(`[origin = "cluster"]`)).union(keep.parents().connectedEdges(`[origin = "cluster"]`).connectedNodes());
    inst.elements().difference(keep.union(hits)).addClass("vlan-dim");
  }, [focus, graph, grouped, colors]);

  useEffect(() => () => cy.current?.destroy(), []);

  // the side panel opening or the window changing size resizes the map
  useEffect(() => {
    if (!ref.current || typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => cy.current?.resize());
    ro.observe(ref.current);
    return () => ro.disconnect();
  }, []);

  // redraw with the new colours when the theme changes
  useEffect(() => {
    const restyle = () => cy.current?.style(topoStyle());
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    window.addEventListener("ncc-theme", restyle);
    mq.addEventListener("change", restyle);
    return () => { window.removeEventListener("ncc-theme", restyle); mq.removeEventListener("change", restyle); };
  }, []);

  const relayout = () => setLayoutRun((r) => r + 1);
  const zoomBy = (f: number) => {
    const inst = cy.current;
    if (!inst) return;
    inst.animate({ zoom: { level: inst.zoom() * f, position: { x: inst.width() / 2, y: inst.height() / 2 } } } as cytoscape.AnimationOptions, { duration: 150 });
  };
  const find = (ev: FormEvent) => {
    ev.preventDefault();
    const inst = cy.current, q = query.trim().toLowerCase();
    if (!inst || !q) return;
    const hit = graph?.nodes.find((n) => n.label.toLowerCase().includes(q) || n.ip?.includes(q) || n.id.toLowerCase() === q || n.model?.toLowerCase().includes(q));
    setMiss(!hit);
    if (!hit) return;
    const ele = inst.getElementById(hit.id);
    inst.elements().unselect();
    ele.select();
    setSelected({ type: "node", node: hit });
    inst.animate({ center: { eles: ele }, zoom: Math.max(inst.zoom(), 1.1) } as cytoscape.AnimationOptions, { duration: 250 });
  };
  const sel = selected?.type === "node" ? selected.node : null;

  return (
    <>
      <h1>Topology</h1>
      <div className="toolbar topo-toolbar">
        <label className="check"><input type="checkbox" checked={showClients} disabled={grouped} onChange={(e) => setWithClients(e.target.checked)} /> Show clients</label>
        <label className="check" title="Draw a box per VLAN around its clients">
          <input type="checkbox" checked={grouped} disabled={!lanNets.length} onChange={(e) => setGrouped(e.target.checked)} /> Group by VLAN
        </label>
        <label className="check" title="Show the port numbers on every link (hover a device to see its own)">
          <input type="checkbox" checked={portLabels} onChange={(e) => setPortLabels(e.target.checked)} /> Port labels
        </label>
        <button onClick={relayout} title="Put every device back in its tier">Tidy up</button>
        <form className={`topo-search${miss ? " miss" : ""}`} onSubmit={find} role="search">
          <Icon name="search" size={15} />
          <input type="search" placeholder={showClients ? "Find a device or client" : "Find a device"} aria-label="Find on the map" value={query}
            onChange={(e) => { setQuery(e.target.value); setMiss(false); }} />
        </form>
        {miss && <span className="muted small">Not on the map{showClients ? "" : " (clients are hidden)"}.</span>}
      </div>
      {loops.length > 0 && (
        <section className={`card loop-card ${loops.some((l) => l.severity === "critical") ? "bad" : "warn"}`} aria-label="Switching loops">
          <h2>{loops.length} switching loop{loops.length === 1 ? "" : "s"} found</h2>
          <p className="muted small">Each entry names the switch and the exact ports. Red: nothing is stopping the loop. Amber: spanning tree has shut one port, so the extra path is held closed.</p>
          <LoopList loops={loops} focus={loopFocus} onFocus={setLoopFocus} />
        </section>
      )}
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
        <div className="topo-stage">
          <div ref={ref} className="topo-canvas" />
          <div className="topo-zoom" role="group" aria-label="Zoom">
            <button onClick={() => zoomBy(1.25)} title="Zoom in" aria-label="Zoom in"><Icon name="plus" size={16} /></button>
            <button onClick={() => zoomBy(0.8)} title="Zoom out" aria-label="Zoom out"><Icon name="minus" size={16} /></button>
            <button onClick={() => cy.current && fitView(cy.current)} title="Fit the whole network" aria-label="Fit to screen"><Icon name="fit" size={16} /></button>
          </div>
          {legend ? (
            <div className="topo-legend card" aria-label="Map key">
              <div className="topo-legend-head"><strong>Map key</strong><button className="link" onClick={() => setLegend(false)} aria-label="Hide map key">Hide</button></div>
              <ul>
                <li><svg width="28" height="10"><path d="M2 5h24" className="lg-cable" /></svg>Cable</li>
                <li><svg width="28" height="10"><path d="M2 5h24" className="lg-wifi" /></svg>Wireless</li>
                <li><svg width="28" height="10"><path d="M2 8Q14 -2 26 8" className="lg-cable" fill="none" /></svg>Extra link (closes a ring)</li>
                <li><svg width="28" height="10"><path d="M2 5h24" className="lg-bad" /></svg>Loop, nothing stopping it</li>
                <li><svg width="28" height="10"><path d="M2 5h24" className="lg-warn" /></svg>Loop held shut by spanning tree</li>
                <li><svg width="28" height="12"><circle cx="8" cy="6" r="4.5" className="lg-good" /><circle cx="21" cy="6" r="4.5" className="lg-off" /></svg>Online / offline</li>
                <li><svg width="28" height="14"><rect x="7" y="1.5" width="14" height="11" rx="3" className="lg-dashed" /></svg>Switch NCC found, not managed</li>
                <li><svg width="28" height="14"><circle cx="14" cy="7" r="4" className="lg-dmz" /></svg>DMZ host; client colour = VLAN</li>
              </ul>
            </div>
          ) : (
            <button className="topo-legend-show" onClick={() => setLegend(true)}>Map key</button>
          )}
        </div>
        {sel && (
          <aside className="card topo-side">
            <h2>{sel.label}</h2>
            <dl className="kv">
              <dt>Kind</dt><dd>{kindLabel[sel.kind] ?? sel.kind}</dd>
              {sel.make && (<><dt>{sel.kind === "client" ? "Vendor" : "Make"}</dt><dd>{sel.make}</dd></>)}
              {sel.model && (<><dt>Model</dt><dd>{sel.model}</dd></>)}
              {sel.ip && (<><dt>IP</dt><dd className="mono">{sel.ip}</dd></>)}
              {sel.kind === "internet" ? (<><dt>Reached through</dt><dd>{graph?.nodes.filter((n) => n.kind === "gateway").map((n) => n.label).join(", ")}</dd></>)
                : (<><dt>MAC / id</dt><dd className="mono small">{sel.id}</dd></>)}
              {sel.discovery && (<><dt>Found by</dt><dd>{discoveryLabel[sel.discovery] ?? sel.discovery}</dd></>)}
              {sel.clients ? (<><dt>Clients</dt><dd>{sel.clients}</dd></>) : null}
              {sel.network && (<><dt>{sel.kind === "client" ? "Network" : "Mgmt network"}</dt><dd><NetName id={sel.network} nets={nets} colors={colors} /></dd></>)}
              {!sel.network && sel.vlan ? (<><dt>VLAN</dt><dd>{sel.vlan}</dd></>) : null}
              {sel.zone && (<><dt>Zone</dt><dd><span className={`pill ${zonePill[sel.zone] ?? ""}`}>{zoneText(nets.get(sel.network ?? "") ?? { zone: sel.zone })}</span></dd></>)}
              {sel.ssid && (<><dt>SSID</dt><dd>{sel.ssid}</dd></>)}
            </dl>
            {sel.loops?.length ? (
              <>
                <h3 className="small">Loops on this device</h3>
                <LoopList compact loops={sel.loops.map((id) => loopsByID.get(id)).filter((l): l is Loop => !!l)} focus={loopFocus} onFocus={setLoopFocus} />
              </>
            ) : null}
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
            <h2>{selected.edge.origin === "loop" ? "Looping cable" : "Link"}</h2>
            <dl className="kv">
              {selected.edge.label && (<><dt>Ports</dt><dd>{selected.edge.label}</dd></>)}
              <dt>Medium</dt><dd>{selected.edge.medium === "wireless" ? "Wireless" : "Cable"}</dd>
              {selected.edge.speed_mbps ? (<><dt>Speed</dt><dd>{selected.edge.speed_mbps} Mbps</dd></>) : null}
            </dl>
            {selected.edge.origin !== "loop" && <h3 className="small">Networks carried</h3>}
            {selected.edge.networks?.length
              ? <ul className="vlan-list">{selected.edge.networks.map((id) => <li key={id}><NetName id={id} nets={nets} colors={colors} /></li>)}</ul>
              : selected.edge.origin === "loop" ? null : <p className="muted small">Unknown. UniFi did not report VLAN settings for this port.</p>}
            {selected.edge.loops?.length ? (
              <>
                <h3 className="small">Part of</h3>
                <LoopList compact loops={selected.edge.loops.map((id) => loopsByID.get(id)).filter((l): l is Loop => !!l)} focus={loopFocus} onFocus={setLoopFocus} />
              </>
            ) : null}
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
