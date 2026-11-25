// Thin typed client for the NCC API, and the TypeScript shapes of what it returns.
// The interfaces mirror the Go structs' JSON (internal/inventory, internal/core, ...);
// keep the two in step when a field is added.

// csrf is the token from /api/me (or /api/login); every non-GET request must send it.
let csrf = "";

/** ApiError is a failed API call: the HTTP status and the server's error message. */
export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export function setCSRF(token: string) {
  csrf = token;
}

/**
 * api calls the NCC API with the session cookie and CSRF token and returns the parsed JSON
 * body typed as T. A non-2xx answer throws ApiError with the server's "error" message.
 */
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
export interface Port {
  index: number; name: string; up: boolean; speed_mbps?: number; poe?: boolean; poe_watts?: number; uplink?: boolean;
  profile?: string; native_network?: string; tagged_networks?: string[];
}
export interface Device {
  id: string; name: string; kind: string; make: string; model: string; model_code: string; mac: string;
  ip?: string; firmware?: string; serial?: string; online: boolean; uptime_s?: number; managed: boolean;
  discovery: string; detail?: string; ports?: Port[]; clients: number; target: string;
}
export interface PortClient {
  mac: string; name: string; ip?: string; vendor?: string; network?: string; network_id?: string; vlan?: number; ssid?: string;
  /** The switch the client really hangs off, when it is not this device (an inferred unmanaged switch or LLDP neighbour). */
  behind?: string; behind_id?: string;
}
export interface PortNeighbour { id: string; name: string; kind: string; port?: string; online: boolean; clients: number }
export interface PortView extends Port { stp?: string; clients: PortClient[]; devices: PortNeighbour[] }
/** A device's ports and who is on each; `attached` are clients with no known port (wireless, or behind an unmanaged switch). */
export interface DevicePorts { id: string; name: string; kind: string; ports: PortView[]; attached: PortClient[] }
export interface Client {
  mac: string; name: string; ip?: string; vendor?: string; wired: boolean; parent_id?: string;
  parent_port?: string; network?: string; vlan?: number; network_id?: string; ssid?: string;
}
export interface Target {
  id: number; kind: string; category: "device" | "dns" | "hypervisor" | "storage" | "smarthome" | "siem"; name: string; address: string;
  options: Record<string, string>; secret_path: string; enabled: boolean; last_poll?: string; last_error: string;
}
/** One input of a connection form, described by the server (see internal/catalog). */
export interface CatalogField {
  key: string; label: string; type: "text" | "password" | "token" | "select" | "checkbox"; store: "option" | "secret" | "form";
  default?: string; placeholder?: string; help?: string; choices?: { value: string; label: string }[];
  required?: boolean; show_if?: Record<string, string>; section?: string;
}
/** A product NCC can connect to: one card of the Add connection wizard. */
export interface CatalogVendor {
  id: string; kind: string; category: Target["category"]; groups: string[]; label: string; summary: string; help: string;
  preset?: Record<string, string>; name_default: string; address_kind: "url" | "host"; address_label?: string;
  address_default?: string; address_placeholder?: string; no_login?: boolean; fields: CatalogField[];
}
export interface CatalogGroup { id: string; label: string; summary: string }
/** An event NCC sends to SIEMs: an audit log entry or a network event (see internal/siem). */
export interface SIEMEvent {
  id: number; source: "audit" | "network" | "test"; time: string; type: string; severity: number;
  actor?: string; target?: string; message: string; detail?: string; fields?: Record<string, string>;
}
/** Delivery counters of one SIEM connection. */
export interface SIEMStatus {
  sent: number; failed: number; last_sent_at?: string; last_attempt_at?: string; last_error?: string; info?: string;
  pending: Record<string, number>;
}
/** One SIEM connection on the SIEM Forwarding page. */
export interface SIEMSource {
  id: number; name: string; kind: string; vendor: string; address: string; enabled: boolean; last_poll?: string;
  last_error?: string; options: Record<string, string>; status: SIEMStatus;
}
export interface Catalog { groups: CatalogGroup[]; vendors: CatalogVendor[] }
/** One finding of the DNS chain check (router hands out the internal DNS server, which forwards to the ISP). */
export interface DNSCheck {
  id: string; kind: "dhcp" | "forwarders" | "setup" | "live"; status: "pass" | "skip" | "unknown" | "warn" | "fail";
  subject: string; title: string; expected?: string; actual?: string; detail?: string; fix?: string; fix_url?: string;
  /** A fix NCC can carry out itself (after a preview), for the connection `target`. */
  action?: "recursor-api"; target?: number;
}
export interface RecursorProbe {
  url: string; status?: number; daemon_type?: string; version?: string; recursor: boolean; key_ok: boolean; error?: string;
}
export interface RecursorDiscovery {
  discovery: { hosts: string[]; probes: RecursorProbe[]; found?: RecursorProbe };
  current_url?: string; needs_api_key: boolean; no_resolver: boolean;
  ssh: { host: string; port: number; user: string; sudo: boolean; host_key?: string; has_password: boolean; has_key: boolean };
}
export interface RecursorStep { title: string; command?: string; file?: string; diff?: string[]; note?: string }
export interface RecursorPlan {
  mode: "api" | "install" | "resolver"; host: string; url?: string; new_key: boolean; warnings: string[]; blocked?: string; next?: string; zone?: string;
  steps: RecursorStep[];
  facts: {
    os?: string; version?: string; config_file?: string; style?: string; on_port_53?: string; listening?: string[]; ufw?: boolean;
    auth_config?: string; current: Record<string, string>;
  };
}
export interface RecursorResult {
  ok: boolean; url?: string; error?: string; rolled_back?: boolean; steps: { title: string; ok: boolean; output?: string }[];
}
export interface DNSReport {
  /** Worst check's status; "" when there is no DNS server to check. */
  status: "" | DNSCheck["status"]; summary: string; resolvers: string[]; isp: string[]; isp_source?: "router" | "setting";
  checks: DNSCheck[];
}
export interface NodePort { name: string; up: boolean; uplink?: boolean; profile?: string; native?: string; tagged?: string[] }
export interface GNode {
  id: string; label: string; kind: string; make?: string; model?: string; ip?: string; online: boolean; discovery?: string;
  clients?: number; parent?: string; network?: string; vlan?: number; zone?: string; ssid?: string; ports?: NodePort[];
  loops?: string[];
}
export interface GEdge { id: string; source: string; target: string; label?: string; medium: string; speed_mbps?: number; origin: string; networks?: string[]; loops?: string[] }
export interface GNetwork {
  id: string; name: string; purpose?: string; vlan?: number; subnet?: string; zone?: string; zone_name?: string;
  zone_source?: "firewall" | "inferred"; isolated?: boolean; internet_access: boolean; ssids?: string[]; target: string;
  clients: number; devices: number;
}
export interface Graph { nodes: GNode[]; edges: GEdge[]; networks?: GNetwork[]; loops?: Loop[] }
export interface LoopPort { device: string; device_name: string; port?: number; port_name?: string; stp?: string }
export interface LoopLink { a: string; a_port?: string; b: string; b_port?: string }
export interface Loop {
  id: string; severity: "critical" | "warning"; kind: "self" | "parallel" | "cycle" | "stp" | "event";
  summary: string; detail?: string; ports: LoopPort[]; links?: LoopLink[]; count?: number; seen_at?: string; target: string;
}
export interface FirewallEndpoint { zone?: string; match: string; port?: string; negate?: boolean }
export interface FirewallRule {
  id: string; name: string; description?: string; enabled: boolean; action: "allow" | "block" | "reject" | string; index: number;
  builtin?: boolean; ruleset?: string; source: FirewallEndpoint; destination: FirewallEndpoint; protocol: string;
  ip_version?: string; states?: string[]; schedule?: string; logging?: boolean; target: string;
}
export interface PortForward {
  id: string; name: string; enabled: boolean; interface?: string; protocol: string; external_port: string; source: string;
  destination?: string; forward_ip: string; forward_port: string; forward_client?: string; logging?: boolean; target: string;
}
export interface Firewall { mode?: "zones" | "legacy"; rules: FirewallRule[]; forwards: PortForward[]; notes?: string[]; target: string }
export interface Zone { name: string; kind?: string; serial?: number }
export interface RRSet { name: string; type: string; ttl: number; records: string[] }
export interface Change { op: "REPLACE" | "DELETE"; rrset: RRSet }
export interface ZonePlan { zone: string; changes: Change[] }

// ---- DNS zones and VLANs (internal/dnszones) ----
export type ZoneStatus = "pass" | "skip" | "unknown" | "warn" | "fail";
export interface ZoneIssue { code: string; severity: ZoneStatus; message: string; fix?: string }
/** One router network and the DNS zone its clients live in. */
export interface ZoneRow {
  router_id: number; router: string; can_set_domain: boolean; network_id: string; network: string; vlan: number;
  subnet?: string; purpose?: string; firewall_zone?: string; dhcp: boolean; dhcp_domain?: string;
  assignment_id?: number; zone?: string; server_id?: number; server?: string; zone_found: boolean;
  reverse_zone?: string; reverse_found: boolean; suggested_zone?: string; status: ZoneStatus; issues: ZoneIssue[];
}
export interface ZoneAssignment { id: number; server_id: number; zone: string; router_id: number; network_id: string; network: string; vlan: number; updated_by: string; updated_at: string }
export interface ZoneUse { server_id: number; server: string; zone: string; kind?: string; reverse: boolean; parent?: string; networks: string[] }
export interface ZoneServer { id: number; name: string; kind: string; zones: Zone[]; error?: string; can_create: boolean }
export interface ZoneMap {
  status: "" | ZoneStatus; summary: string; domain?: string; rows: ZoneRow[]; orphans: ZoneAssignment[]; zones: ZoneUse[];
  servers: ZoneServer[]; routers: { id: number; name: string; can_set_domain: boolean }[];
}
export interface NewZone { name: string; server_id?: number; nameservers?: string[]; delegate: boolean }
export interface AssignSpec { zone: string; server_id?: number; router_id: number; network_id: string; set_dhcp_domain: boolean; reverse: boolean }
export interface ZonePlanRequest { server_id: number; zones: NewZone[]; assign: AssignSpec[] }
export interface ZoneStep {
  kind: "create_zone" | "delegate" | "create_reverse" | "assign" | "dhcp_domain"; title: string; server_id?: number; server?: string;
  zone?: string; nameservers?: string[]; change?: Change; router_id?: number; router?: string; network_id?: string; network?: string; vlan?: number; domain?: string;
}
export interface ZoneStepResult extends ZoneStep { ok: boolean; error?: string }
export interface ZonePlanResponse { applied: boolean; plan: { steps: ZoneStep[]; warnings: string[] }; results?: ZoneStepResult[]; error?: string }
export interface Cert {
  id: number; name: string; subject: string; issuer: string; sans: string[]; serial: string;
  not_before: string; not_after: string; fingerprint: string; has_key: boolean; days_left: number;
  status: "ok" | "expiring" | "critical" | "expired"; chain_length: number;
  chain?: string[]; chain_complete?: boolean; dropped?: string[];
}
export interface ServerHealth { status: string; version: string; commit?: string; commit_time?: string; modified?: boolean; go_version: string }
export interface LicenseFile { name: string; text: string }
export interface ThirdParty { name: string; version: string; ecosystem: "go" | "npm"; license: string; url?: string; files: LicenseFile[] }
export interface About { name: string; license_id: string; license: string; notice: string; third_party: ThirdParty[] }
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
  window: string; taken_at?: string; dpi: boolean; dpi_notes?: string[]; dpi_sources?: string[]; categories: AppUsage[];
  clients: TrafficClient[]; sites: SiteCount[]; unmatched_sources?: string[]; dns_log: DNSLogStatus;
}
export interface VM {
  id: string; name: string; type: "qemu" | "lxc" | "vm"; state: "running" | "stopped" | "suspended" | "unknown"; host: string;
  template?: boolean; cpus: number; cpu_usage: number; mem_bytes: number; mem_used: number; disk_bytes: number; disk_used: number;
  ips?: string[]; os?: string; uptime_s: number; tags?: string[]; notes?: string; guest_tools?: string; target: string;
  platform: "proxmox" | "vmware" | "hyperv";
}
export interface VMHost {
  name: string; online: boolean; cpus: number; cpu_usage: number; mem_bytes: number; mem_used: number; uptime_s: number;
  version?: string; model?: string; target: string; platform: "proxmox" | "vmware" | "hyperv";
}
export interface VMSource {
  id: number; name: string; kind: "proxmox" | "vmware" | "hyperv"; address: string; enabled: boolean; version?: string; taken_at?: string;
  last_error?: string; warnings?: string[];
}
export interface VMView { sources: VMSource[]; hosts: VMHost[]; vms: VM[] }
export interface Network {
  id: string; name: string; purpose?: string; vlan?: number; subnet?: string; zone?: string; zone_name?: string;
  zone_source?: "firewall" | "inferred"; isolated?: boolean; internet_access: boolean; ssids?: string[]; target: string;
}
export interface NetClient extends Client { switch_mac?: string; switch_port?: number; ap_mac?: string; stale?: boolean }
export interface NetworkSpec {
  name: string; vlan: number; mode: "gateway" | "vlan-only"; gateway?: string; dhcp: boolean; dhcp_start?: string; dhcp_stop?: string;
  isolated: boolean; internet_access: boolean;
}
export interface VLANTarget {
  id: number; name: string; kind: string; writable: boolean; taken_at?: string; last_error?: string;
  networks: Network[]; clients: NetClient[]; devices: { id: string; name: string; kind: string; online: boolean }[];
  suggestion: NetworkSpec; ports: Record<string, { name: string; profile?: string; infra?: boolean; clients: number }>;
}
export interface MoveStep {
  mac: string; name: string; ip?: string; wired: boolean; method?: "port" | "client"; from?: string; from_name?: string; via?: string;
  switch_mac?: string; switch_port?: number; requested: boolean; already?: boolean; blocked?: string; note?: string;
}
export interface PortChange {
  switch_mac: string; switch_name: string; port: number; port_name: string; from?: string; from_name?: string; profile?: string;
  clients: string[]; offline?: boolean;
}
export interface MovePlan { target: string; network: Network; steps: MoveStep[]; ports: PortChange[]; warnings?: string[] }
export interface MoveResult { mac: string; name: string; ok: boolean; error?: string; notes?: string[]; warning?: string }
export interface DeployField { key: string; label: string; default?: string; help?: string; type?: "text" | "select" | "bool"; choices?: string[] }
export interface DeployKind {
  id: string; label: string; description: string; transport: "ssh" | "winrm"; default_port: number;
  fields: DeployField[]; secrets?: DeployField[]; verify_wait_s: number;
}
export interface DeployStepResult { title: string; op: string; path?: string; status: "pending" | "running" | "ok" | "unchanged" | "failed" | "skipped"; output?: string }
export interface Deployment {
  id: number; target_id: number; target_name: string; cert_id: number; cert_name: string; fingerprint: string; actor: string;
  started: string; finished?: string; status: "running" | "ok" | "failed"; verified: string; steps: DeployStepResult[]; error?: string;
}
export interface DeployTarget {
  id: number; name: string; kind: string; host: string; port: number; options: Record<string, string>; secret_path: string;
  cert_id: number; credentials: Record<string, boolean>; last_deploy?: Deployment;
}
export interface DeployStep { op: "write" | "edit" | "run"; title: string; path?: string; detail?: string }
export interface DeployPlan {
  target: DeployTarget; cert: Cert; steps: DeployStep[]; notes: string[]; warnings: string[]; blocked?: string;
  connection?: { ok: boolean; error?: string; fingerprint?: string; trust?: boolean; detail?: string };
}
export interface ServedCert { subject?: string; issuer?: string; not_after?: string; fingerprint?: string; sans?: string[]; cert_name?: string; port?: string; error?: string }
export type Health = "good" | "warning" | "critical" | "unknown";
export interface StorageSystem {
  name: string; vendor: string; model?: string; serial?: string; firmware?: string; os?: string; health: Health; uptime_s?: number;
  cpu_usage: number; mem_bytes?: number; mem_used?: number; temp_c?: number; cpu_temp_c?: number;
  fans?: { name: string; rpm: number; ok: boolean }[]; nics?: { name: string; up: boolean; speed_mbps?: number; ip?: string; mac?: string }[]; update?: string;
}
export interface StoragePool { id: string; name: string; raid?: string; status: string; health: Health; total: number; used: number; disks?: string[] }
export interface StorageVolume { id: string; name: string; pool?: string; fs?: string; status: string; health: Health; total: number; used: number }
export interface StorageDisk {
  id: string; slot: string; model?: string; serial?: string; type?: "hdd" | "ssd"; size?: number; temp_c?: number; status?: string; smart?: string;
  health: Health; pool?: string;
}
export interface StorageShare {
  name: string; path?: string; volume?: string; protocols?: string[]; comment?: string; used?: number; total?: number; free?: number;
  clients?: string[]; snapshots?: number; hidden?: boolean; encrypted?: boolean;
}
export interface StorageSnapshot { id: string; share: string; name: string; created: string; comment?: string; locked?: boolean }
export interface StorageAlert { level: "warning" | "critical"; subject: string; message: string }
export interface StorageInventory {
  target: string; kind: string; taken_at: string; system: StorageSystem; pools: StoragePool[]; volumes: StorageVolume[]; disks: StorageDisk[];
  shares: StorageShare[]; snapshots: StorageSnapshot[]; alerts: StorageAlert[]; capabilities: string[]; warnings?: string[];
}
export interface StorageSource {
  id: number; name: string; kind: "qnap" | "synology" | "smb" | "nfs" | "snmp"; address: string; enabled: boolean; last_error?: string;
  taken_at?: string; inventory?: StorageInventory; snmp?: boolean;
}
export interface CapacityHistory { volume: string; points: { t: number; used: number; total: number }[]; per_day: number; full_in_days?: number }

// ---- smart home (Home Assistant) ----
export interface SmartHub {
  name: string; version: string; matter: boolean; nest: boolean; cast: boolean; alexa: boolean; time_zone?: string; unit?: string; sources: string[];
}
export interface SmartArea { id: string; name: string }
export interface SmartDevice { id: string; name: string; manufacturer?: string; model?: string; firmware?: string; area?: string; source?: string; online: boolean }
export interface SmartEntity {
  id: string; domain: string; name: string; state: string; device?: string; area?: string; source?: string; device_class?: string; unit?: string;
  changed: string; brightness?: number; dimmable?: boolean; current_temp?: number; target_temp?: number; min_temp?: number; max_temp?: number;
  temp_step?: number; hvac_modes?: string[]; hvac_action?: string; humidity?: number; media_title?: string; battery?: number; actions?: string[];
}
export interface SmartAlert { level: "warning" | "critical"; subject: string; message: string; entity?: string }
export interface SmartInventory {
  target: string; kind: string; taken_at: string; hub: SmartHub; areas: SmartArea[]; devices: SmartDevice[]; entities: SmartEntity[];
  alerts: SmartAlert[]; warnings?: string[];
}
export interface SmartSource {
  id: number; name: string; kind: "homeassistant"; address: string; enabled: boolean; last_error?: string; taken_at?: string; inventory?: SmartInventory;
}
export interface SmartPlan { entity: string; name: string; description: string; sensitive: boolean; call: { domain: string; service: string; data: Record<string, unknown> } }
export interface MatterCheck { code: { kind: "manual" | "qr"; formatted: string; discriminator: number; vendor_present?: boolean }; hub: string; matter_ready: boolean; devices: number }

export interface IoTDevice {
  mac: string; name: string; label: string; hostname?: string; ip?: string; vendor?: string; type: string; auto_type: string;
  network_id?: string; network?: string; vlan?: number; wired: boolean; ssid?: string; switch_mac?: string; switch_port?: number; ap_mac?: string;
  uplink?: string; target_id?: number; target?: string; first_seen: string; last_seen: string; online: boolean;
  owner: string; site: string; building: string; floor: string; room: string; notes: string; ignored: boolean;
  network_ok: boolean; network_ok_reason?: string; updated_at?: string; updated_by?: string; model?: string; firmware?: string;
  issues: ("wrong_network" | "offline" | "no_location" | "no_owner")[];
}
export interface IoTNetwork { id: string; name: string; vlan?: number; subnet?: string; zone?: string; target: string; iot: boolean; suggested: boolean; devices: number }
export interface IoTCandidate { mac: string; name: string; ip?: string; vendor?: string; network?: string; guess?: string; ignored: boolean }
export interface IoTView { devices: IoTDevice[]; networks: IoTNetwork[]; networks_chosen: boolean; types: string[]; candidates: IoTCandidate[]; sources: number }
export type IoTPatch = Partial<Pick<IoTDevice, "type" | "label" | "owner" | "site" | "building" | "floor" | "room" | "notes" | "ignored" | "network_ok" | "network_ok_reason">>;

// ---- AI assistant (internal/assistant) ----
/** One way of reaching a model: a vendor's own tool signed in with the person's subscription, or a local model server. */
export interface AIProvider {
  id: string; label: string; account: string; binary?: string; install?: string; sign_in?: string[]; sign_in_help?: string;
  paste?: string; note?: string; default_model?: string; http?: boolean;
  kind: string; enabled: boolean; model: string; address: string; connected_at?: string; last_used?: string; last_error?: string;
  installed: boolean; connected: boolean; problem?: string; path?: string; ncc_version?: string; can_install: boolean;
}
export interface AIInstallPlan {
  kind: string; package?: string; location?: string; node?: string; download_node?: boolean; commands: string[];
  installed?: string; can_install: boolean; problem?: string;
}
export interface AIInstall { id: string; kind: string; state: "running" | "done" | "failed"; output: string; version?: string; error?: string }
export interface AISignIn { id: string; kind: string; state: "running" | "connected" | "failed"; output: string; error?: string }
export interface AIStepClient { mac: string; name: string; ip?: string; from?: string; type?: string; via?: string; blocked?: string; along_with?: boolean }
export interface AIStep {
  id: string; kind: "create_vlan" | "move_clients" | "create_zone" | "assign_zone"; title: string; why: string;
  router_id?: number; router_name?: string; dns_server_id?: number; dns_server?: string;
  network?: { name: string; vlan: number; gateway?: string; dhcp_start?: string; dhcp_stop?: string; isolated: boolean; internet_access: boolean };
  network_id?: string; network_name?: string; clients?: AIStepClient[]; zone?: string;
  warnings: string[]; problem?: string; recommended: boolean;
  result?: { state: "ok" | "failed" | "skipped"; message: string; at: string };
}
export interface AIPlan {
  id: string; created_at: string; created_by: string; provider: string; model?: string; goal?: string; summary: string; notes: string[];
  steps: AIStep[]; source: "ai" | "rules"; ai_error?: string;
  status: "proposed" | "deploying" | "deployed" | "partial" | "failed" | "discarded"; deployed_at?: string; deployed_by?: string;
}

// ---- Wi-Fi ----
export type WiFiSecurity = "open" | "wep" | "wpa1" | "wpa1-wpa2" | "wpa2" | "wpa2-wpa3" | "wpa3" | "enterprise" | "owe";
export interface SSID {
  id: string; name: string; enabled: boolean; hidden?: boolean; security: WiFiSecurity; tkip?: boolean; pmf?: string;
  bands?: string[]; network_id?: string; network?: string; vlan?: number; guest?: boolean; client_isolation?: boolean;
  short_passphrase?: boolean; clients: number; target: string;
}
export interface Radio {
  device_id: string; device_name: string; online: boolean; band: string; channel?: number; channel_auto?: boolean;
  width_mhz?: number; tx_power?: number; tx_power_mode?: string; clients: number; utilization?: number;
  /** Wi-Fi networks (SSID ids) this access point leaves off on this band. */
  ssids_off?: string[];
}
/** The quietest channel NCC finds for one radio. */
export interface ChannelSuggestion {
  device_id: string; device: string; band: string; current: number; channel: number; width_mhz: number; better: boolean; reason: string;
  options: { channel: number; score: number; own?: string[]; neighbors: number; dfs?: boolean }[];
}
export interface RadioSetting { band: string; channel?: number; width_mhz?: number; tx_power_mode?: string; tx_power?: number }
export interface APRequest { radios: RadioSetting[]; ssids: { ssid_id: string; band: string; on: boolean }[] }
export interface APPlan {
  device_id: string; device: string; changes: { setting: string; from: string; to: string }[]; warnings: string[];
  resolves: WiFiFinding[]; remaining: WiFiFinding[];
}
export interface WiFiFinding {
  severity: "critical" | "warning" | "info"; kind: string; ssid_id?: string; ssid?: string; device_id?: string; device?: string;
  summary: string; fix?: string; target: string;
}
export interface WiFiClient {
  mac: string; name: string; ip?: string; ssid?: string; ap_id?: string; ap?: string; band?: string; channel?: number; signal?: number; network?: string;
}
export interface WiFiTarget {
  id: number; name: string; kind: string; writable: boolean; taken_at?: string; last_error?: string;
  ssids: SSID[]; radios: Radio[]; clients: WiFiClient[]; findings: WiFiFinding[]; saved: string[];
  radios_writable: boolean; suggestions: ChannelSuggestion[]; neighbors: number;
  networks: { id: string; name: string; vlan?: number; purpose?: string; zone?: string; isolated?: boolean }[];
}
/** An SSID edit. Only set fields change; passphrase is sent to the router and the vault, never shown back. */
export interface WiFiChange {
  name?: string; enabled?: boolean; hidden?: boolean; network_id?: string; security?: "wpa2" | "wpa2-wpa3" | "wpa3"; passphrase?: string;
  bands?: string[];
}
export interface WiFiPlan {
  ssid: SSID; changes: { setting: string; from: string; to: string }[]; warnings: string[];
  resolves: WiFiFinding[]; remaining: WiFiFinding[];
}
