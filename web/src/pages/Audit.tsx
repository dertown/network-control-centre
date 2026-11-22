// Audit log page (admins): the newest 500 entries and whether the hash chain is intact.
import { useEffect, useState } from "react";
import { api, AuditEntry } from "../api";

export function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [intact, setIntact] = useState<boolean | null>(null);
  useEffect(() => {
    api<AuditEntry[]>("GET", "/api/audit?limit=500").then(setEntries).catch(() => {});
    api<{ intact: boolean }>("GET", "/api/audit/verify").then((r) => setIntact(r.intact)).catch(() => {});
  }, []);
  return (
    <>
      <h1>Audit log</h1>
      <p>
        Every login, vault access and change is recorded. Each entry includes a hash of the one before it, so edits or deletions are detectable.{" "}
        {intact === true && <span className="pill good">chain intact</span>}
        {intact === false && <span className="pill bad">chain broken: entries were altered</span>}
      </p>
      <div className="card flush">
        <table>
          <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="small">{new Date(e.ts).toLocaleString()}</td>
                <td>{e.actor}</td>
                <td><span className={`pill ${e.action.endsWith("failed") ? "bad" : ""}`}>{e.action}</span></td>
                <td className="mono small">{e.target}</td>
                <td className="mono small wrap">{e.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
