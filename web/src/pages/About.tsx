// About page: what this build is (version, commit, Go version from /api/health), the
// project's licence (a plain summary of Apache 2.0 plus the LICENSE and NOTICE files exactly
// as built into the binary) and every third-party component bundled in, with its licence.
import { useEffect, useMemo, useState } from "react";
import { About as AboutInfo, api, ServerHealth, ThirdParty } from "../api";
import { Icon } from "../icons";
import { Modal, PageLoading } from "../ui";

// The plain-language summary of Apache 2.0. The full text below is what governs.
const may = [
  "Use NCC for any purpose, including commercially",
  "Copy, modify and distribute it, in source or binary form",
  "Sublicense it or ship it inside your own product",
  "Rely on the patent licence each contributor grants",
];
const must = [
  "Include a copy of the licence when you distribute it",
  "Keep the NOTICE file and existing copyright notices",
  "Mark files you changed as changed",
];
const cannot = [
  "Use the project's names or trademarks to endorse your product",
  "Hold the authors liable: it comes with no warranty",
];

export function About() {
  const [about, setAbout] = useState<AboutInfo | null>(null);
  const [health, setHealth] = useState<ServerHealth | null>(null);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState<ThirdParty | null>(null);
  const [filter, setFilter] = useState("");

  useEffect(() => {
    api<AboutInfo>("GET", "/api/about").then(setAbout).catch((e) => setErr(e.message));
    api<ServerHealth>("GET", "/api/health").then(setHealth).catch(() => {});
  }, []);

  const counts = useMemo(() => {
    const m = new Map<string, number>();
    for (const p of about?.third_party ?? []) m.set(p.license, (m.get(p.license) ?? 0) + 1);
    return [...m].sort((a, b) => b[1] - a[1]);
  }, [about]);

  if (!about) return <PageLoading title="About" err={err} />;

  const copyright = about.notice.split("\n").find((l) => /^copyright/i.test(l.trim()))?.trim();
  const q = filter.trim().toLowerCase();
  const list = about.third_party.filter((p) => !q || p.name.toLowerCase().includes(q) || p.license.toLowerCase().includes(q));

  return (
    <>
      <h1>About</h1>
      <p className="lede muted">The version you're running, the licence NCC is released under, and the open-source software it's built with.</p>

      <section className="card about-hero">
        <span className="about-mark"><Icon name="topology" size={26} /></span>
        <div className="about-id">
          <div className="about-name">{about.name}</div>
          {copyright && <div className="muted">{copyright}</div>}
          <div className="about-pills">
            <span className="pill">Version <b className="mono">{health?.version || "…"}</b></span>
            <a className="pill pill-link" href="#license">Apache License 2.0</a>
          </div>
        </div>
        <dl className="about-facts">
          <div><dt>Commit</dt><dd className="mono" title={health?.commit}>{health?.commit ? health.commit.slice(0, 12) + (health.modified ? " (modified)" : "") : "not recorded"}</dd></div>
          <div><dt>Committed</dt><dd>{health?.commit_time ? new Date(health.commit_time).toLocaleString() : "—"}</dd></div>
          <div><dt>Built with</dt><dd className="mono">{health?.go_version ?? "—"}</dd></div>
        </dl>
      </section>

      <section className="card" id="license">
        <div className="card-head">
          <h2><Icon name="audit" size={17} />Licence</h2>
          <span className="pill mono">{about.license_id}</span>
        </div>
        <p className="lede">
          NCC is open source under the Apache License, Version 2.0. In short, and not as a substitute for the full text below:
        </p>
        <div className="about-terms">
          <div><h3 className="good-ink"><Icon name="check" size={16} />You may</h3><ul>{may.map((t) => <li key={t}>{t}</li>)}</ul></div>
          <div><h3 className="warn-ink"><Icon name="alert" size={16} />You must</h3><ul>{must.map((t) => <li key={t}>{t}</li>)}</ul></div>
          <div><h3 className="bad-ink"><Icon name="lock" size={16} />You can't</h3><ul>{cannot.map((t) => <li key={t}>{t}</li>)}</ul></div>
        </div>
        <details className="about-text">
          <summary>Full licence text (LICENSE)</summary>
          <pre className="mono">{about.license}</pre>
        </details>
        <details className="about-text" open>
          <summary>NOTICE</summary>
          <pre className="mono">{about.notice}</pre>
        </details>
      </section>

      <section className="card flush">
        <div className="card-head about-tp-head">
          <h2><Icon name="container" size={17} />Third-Party Software</h2>
          <input type="search" placeholder="Filter by name or licence" value={filter} onChange={(e) => setFilter(e.target.value)} aria-label="Filter third-party software" />
        </div>
        <p className="lede about-tp-lede muted">
          {about.third_party.length} components are built into NCC: Go modules in the server and npm packages in this web interface. Select a licence to read its text.{" "}
          {counts.map(([l, n]) => <button key={l} className="pill about-count" onClick={() => setFilter(filter === l ? "" : l)} aria-pressed={filter === l}>{l} · {n}</button>)}
        </p>
        <table className="about-tp">
          <thead><tr><th>Component</th><th>Version</th><th className="hide-phone">Part</th><th>Licence</th></tr></thead>
          <tbody>
            {list.map((p) => (
              <tr key={p.ecosystem + p.name}>
                <td className="wrap-word">{p.url ? <a href={p.url} target="_blank" rel="noreferrer">{p.name}</a> : p.name}</td>
                <td className="mono small">{p.version}</td>
                <td className="hide-phone muted">{p.ecosystem === "go" ? "Server" : "Web UI"}</td>
                <td><button className="pill about-lic" onClick={() => setOpen(p)} title={`Read ${p.name}'s licence`}>{p.license}<Icon name="audit" size={12} /></button></td>
              </tr>
            ))}
            {!list.length && <tr><td colSpan={4} className="muted">Nothing matches “{filter}”.</td></tr>}
          </tbody>
        </table>
      </section>

      {open && (
        <Modal title={`${open.name} ${open.version}`} onClose={() => setOpen(null)} wide>
          <p className="muted small">{open.license} · {open.files.length === 1 ? "1 file" : `${open.files.length} files`} shipped with the {open.ecosystem === "go" ? "Go module" : "npm package"}</p>
          {open.files.map((f) => (
            <details key={f.name} className="about-text" open={open.files.length === 1 || /^licen[cs]e(\.txt|\.md)?$/i.test(f.name)}>
              <summary>{f.name}</summary>
              <pre className="mono">{f.text}</pre>
            </details>
          ))}
        </Modal>
      )}
    </>
  );
}
