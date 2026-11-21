package mocklab

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Proxmox emulates the parts of the Proxmox VE API that NCC reads: version, nodes,
// cluster resources, VM config, the QEMU guest agent and container interfaces.
//
// It accepts the API token "ncc@pve!monitor" with secret tokenSecret, or the user
// root@pam with password.
func Proxmox(tokenSecret, password string) http.Handler {
	const ticket = "PVE:root@pam:MOCKTICKET"
	data := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": v})
	}
	type vm struct {
		vmid             int
		typ, name, node  string
		status, tags     string
		cpus             int
		cpu              float64
		mem, maxmem      int64
		disk, maxdisk    int64
		uptime           int64
		template         int
		ostype, agent    string
		description      string
		ips              []string
		agentUnavailable bool
	}
	const gib = int64(1) << 30
	vms := []vm{
		{vmid: 100, typ: "qemu", name: "ncc", node: "pve1", status: "running", tags: "network;ncc", cpus: 2, cpu: 0.04, mem: 1 * gib, maxmem: 2 * gib, maxdisk: 16 * gib, uptime: 412_000, ostype: "l26", agent: "1", description: "Network Control Centre", ips: []string{"192.168.1.247"}},
		{vmid: 101, typ: "qemu", name: "home-assistant", node: "pve1", status: "running", tags: "iot", cpus: 2, cpu: 0.11, mem: 3 * gib, maxmem: 4 * gib, maxdisk: 32 * gib, uptime: 1_204_000, ostype: "l26", agent: "enabled=1", ips: []string{"192.168.30.10", "fd00:30::10"}},
		{vmid: 102, typ: "qemu", name: "win11-desktop", node: "pve2", status: "running", cpus: 8, cpu: 0.37, mem: 12 * gib, maxmem: 16 * gib, maxdisk: 256 * gib, uptime: 86_400, ostype: "win11", agent: "1", agentUnavailable: true},
		{vmid: 103, typ: "qemu", name: "plex", node: "pve2", status: "stopped", tags: "media", cpus: 4, maxmem: 8 * gib, maxdisk: 64 * gib, ostype: "l26"},
		{vmid: 9000, typ: "qemu", name: "ubuntu-2404-template", node: "pve1", status: "stopped", cpus: 2, maxmem: 2 * gib, maxdisk: 10 * gib, template: 1, ostype: "l26", agent: "1"},
		{vmid: 200, typ: "lxc", name: "pihole", node: "pve1", status: "running", tags: "dns", cpus: 1, cpu: 0.02, mem: 180 << 20, maxmem: 512 << 20, disk: 2 * gib, maxdisk: 8 * gib, uptime: 1_204_100, ostype: "debian", ips: []string{"192.168.1.53/24"}},
		{vmid: 201, typ: "lxc", name: "unifi-backup", node: "pve2", status: "running", cpus: 1, cpu: 0.01, mem: 90 << 20, maxmem: 256 << 20, disk: 1 * gib, maxdisk: 4 * gib, uptime: 300_000, ostype: "alpine", ips: []string{"192.168.1.60/24"}},
	}
	find := func(node, typ, id string) *vm {
		for i := range vms {
			v := &vms[i]
			if v.node == node && v.typ == typ && itoa(v.vmid) == id {
				return v
			}
		}
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api2/json/access/ticket", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("username") != "root@pam" || r.FormValue("password") != password {
			http.Error(w, "authentication failure", 401)
			return
		}
		data(w, map[string]any{"ticket": ticket, "CSRFPreventionToken": "x", "username": "root@pam"})
	})
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ok := r.Header.Get("Authorization") == "PVEAPIToken=ncc@pve!monitor="+tokenSecret
			if c, err := r.Cookie("PVEAuthCookie"); err == nil && c.Value == ticket {
				ok = true
			}
			if !ok {
				http.Error(w, "authentication failure", 401)
				return
			}
			h(w, r)
		}
	}
	mux.HandleFunc("GET /api2/json/version", authed(func(w http.ResponseWriter, r *http.Request) {
		data(w, map[string]any{"version": "8.2.4", "release": "8.2", "repoid": "faa83925c9641325"})
	}))
	mux.HandleFunc("GET /api2/json/nodes", authed(func(w http.ResponseWriter, r *http.Request) {
		data(w, []map[string]any{
			{"node": "pve1", "status": "online", "cpu": 0.08, "maxcpu": 8, "mem": 9 * gib, "maxmem": 32 * gib, "uptime": 1_300_000},
			{"node": "pve2", "status": "online", "cpu": 0.31, "maxcpu": 16, "mem": 21 * gib, "maxmem": 64 * gib, "uptime": 900_000},
		})
	}))
	mux.HandleFunc("GET /api2/json/cluster/resources", authed(func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]any{}
		for _, v := range vms {
			out = append(out, map[string]any{
				"id": v.typ + "/" + itoa(v.vmid), "type": v.typ, "vmid": v.vmid, "name": v.name, "node": v.node,
				"status": v.status, "cpu": v.cpu, "maxcpu": v.cpus, "mem": v.mem, "maxmem": v.maxmem,
				"disk": v.disk, "maxdisk": v.maxdisk, "uptime": v.uptime, "template": v.template, "tags": v.tags,
			})
		}
		data(w, out)
	}))
	mux.HandleFunc("GET /api2/json/nodes/{node}/{typ}/{id}/config", authed(func(w http.ResponseWriter, r *http.Request) {
		v := find(r.PathValue("node"), r.PathValue("typ"), r.PathValue("id"))
		if v == nil {
			http.Error(w, "no such VM", 500)
			return
		}
		cfg := map[string]any{"ostype": v.ostype, "description": v.description, "name": v.name}
		if v.agent != "" {
			cfg["agent"] = v.agent
		}
		data(w, cfg)
	}))
	mux.HandleFunc("GET /api2/json/nodes/{node}/qemu/{id}/agent/network-get-interfaces", authed(func(w http.ResponseWriter, r *http.Request) {
		v := find(r.PathValue("node"), "qemu", r.PathValue("id"))
		if v == nil || v.agent == "" || v.status != "running" || v.agentUnavailable {
			w.WriteHeader(500) // Proxmox: "500 QEMU guest agent is not running"
			return
		}
		ifs := []map[string]any{{"name": "lo", "ip-addresses": []map[string]any{{"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8}}}}
		addrs := []map[string]any{{"ip-address": "fe80::be24:11ff:fe00:1", "ip-address-type": "ipv6", "prefix": 64}}
		for _, ip := range v.ips {
			t := "ipv4"
			if strings.Contains(ip, ":") {
				t = "ipv6"
			}
			addrs = append(addrs, map[string]any{"ip-address": ip, "ip-address-type": t, "prefix": 24})
		}
		ifs = append(ifs, map[string]any{"name": "eth0", "hardware-address": "bc:24:11:00:00:01", "ip-addresses": addrs})
		data(w, map[string]any{"result": ifs})
	}))
	mux.HandleFunc("GET /api2/json/nodes/{node}/lxc/{id}/interfaces", authed(func(w http.ResponseWriter, r *http.Request) {
		v := find(r.PathValue("node"), "lxc", r.PathValue("id"))
		if v == nil || v.status != "running" {
			http.Error(w, "CT is not running", 500)
			return
		}
		out := []map[string]any{{"name": "lo", "inet": "127.0.0.1/8", "inet6": "::1/128"}}
		for _, ip := range v.ips {
			out = append(out, map[string]any{"name": "eth0", "inet": ip, "hwaddr": "bc:24:11:00:02:01"})
		}
		data(w, out)
	}))
	return mux
}
