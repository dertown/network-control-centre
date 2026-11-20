// Thin typed client for the NCC API.
let csrf = "";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function setCSRF(token: string) {
  csrf = token;
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, (data && data.error) || res.statusText);
  return data as T;
}

export interface User { id: number; username: string; role: "viewer" | "operator" | "admin"; mfa: boolean }
export interface VaultStatus { backend: string; initialized: boolean; sealed: boolean; detail?: string }
export interface Port { index: number; name: string; up: boolean; speed_mbps?: number; poe?: boolean; poe_watts?: number; uplink?: boolean }
export interface Device {
  id: string; name: string; kind: string; make: string; model: string; model_code: string; mac: string;
  ip?: string; firmware?: string; serial?: string; online: boolean; uptime_s?: number; managed: boolean;
  discovery: string; detail?: string; ports?: Port[]; clients: number; target: string;
}
export interface Client {
  mac: string; name: string; ip?: string; vendor?: string; wired: boolean; parent_id?: string;
  parent_port?: string; network?: string; vlan?: number; ssid?: string;
}
export interface Target {
  id: number; kind: string; category: "device" | "dns"; name: string; address: string;
  options: Record<string, string>; secret_path: string; enabled: boolean; last_poll?: string; last_error: string;
}
export interface GNode { id: string; label: string; kind: string; make?: string; model?: string; ip?: string; online: boolean; discovery?: string; clients?: number; parent?: string }
export interface GEdge { id: string; source: string; target: string; label?: string; medium: string; speed_mbps?: number; origin: string }
export interface Graph { nodes: GNode[]; edges: GEdge[] }
export interface Zone { name: string; kind?: string; serial?: number }
export interface RRSet { name: string; type: string; ttl: number; records: string[] }
export interface Change { op: "REPLACE" | "DELETE"; rrset: RRSet }
export interface ZonePlan { zone: string; changes: Change[] }
export interface Cert {
  id: number; name: string; subject: string; issuer: string; sans: string[]; serial: string;
  not_before: string; not_after: string; fingerprint: string; has_key: boolean; days_left: number;
  status: "ok" | "expiring" | "critical" | "expired"; chain_length: number;
}
export interface AuditEntry { id: number; ts: string; actor: string; action: string; target: string; detail: string }
export interface AppUsage { cat: number; app: number; category: string; name: string; down_bytes: number; up_bytes: number }
export interface SiteCount { site: string; service?: string; count: number }
export interface TrafficClient {
  mac: string; name: string; ip?: string; vendor?: string; wired: boolean; network?: string; ssid?: string;
  down_bytes: number; up_bytes: number; down_rate: number; up_rate: number; uptime_s?: number;
  apps?: AppUsage[]; online: boolean; window_down: number; window_up: number; sites?: SiteCount[];
}
export interface DNSLogStatus { enabled: boolean; listen?: string; received: number; last_message?: string; senders?: string[] }
export interface TrafficView {
  window: string; taken_at?: string; dpi: boolean; dpi_notes?: string[]; categories: AppUsage[];
  clients: TrafficClient[]; sites: SiteCount[]; unmatched_sources?: string[]; dns_log: DNSLogStatus;
}
