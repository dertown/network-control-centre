package mocklab

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// QNAP emulates the QTS CGI endpoints NCC reads: login, system information and health,
// volume use, disk SMART, firmware update, the File Station share tree, folder creation
// and power management. It accepts the user "admin" with password.
func QNAP(password string) http.Handler {
	const sid = "mocksid42"
	var lock sync.Mutex
	shares := []struct {
		name string
		vol  string
		used int64
	}{
		{"Public", "1", 182 << 30}, {"Multimedia", "1", 3_100 << 30}, {"homes", "1", 640 << 30}, {"Container", "1", 96 << 30},
		{"Backups", "2", 2_480 << 30}, {"Web", "1", 2 << 30},
	}
	folders := map[string]bool{}
	restarts := 0
	xmlOut := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" ?><QDocRoot version="1.0"><authPassed><![CDATA[1]]></authPassed>%s</QDocRoot>`, body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/cgi-bin/authLogin.cgi", func(w http.ResponseWriter, r *http.Request) {
		pwd, _ := base64.StdEncoding.DecodeString(r.FormValue("pwd"))
		if r.FormValue("user") != "admin" || string(pwd) != password {
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8" ?><QDocRoot version="1.0"><authPassed><![CDATA[0]]></authPassed><errorValue><![CDATA[-1]]></errorValue></QDocRoot>`)
			return
		}
		xmlOut(w, `<authSid><![CDATA[`+sid+`]]></authSid><username><![CDATA[admin]]></username><isAdmin><![CDATA[1]]></isAdmin>`)
	})
	mux.HandleFunc("/cgi-bin/authLogout.cgi", func(w http.ResponseWriter, r *http.Request) { xmlOut(w, "") })
	authed := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.FormValue("sid") != sid {
				w.Header().Set("Content-Type", "text/xml")
				fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8" ?><QDocRoot version="1.0"><authPassed><![CDATA[0]]></authPassed></QDocRoot>`)
				return
			}
			lock.Lock()
			defer lock.Unlock()
			h(w, r)
		}
	}
	mux.HandleFunc("/cgi-bin/management/manaRequest.cgi", authed(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("sysHealth") == "1" {
			xmlOut(w, `<func><name><![CDATA[sysinfo]]></name><ownContent><sysHealth><status><![CDATA[good]]></status></sysHealth></ownContent></func>`)
			return
		}
		xmlOut(w, `<model><modelName><![CDATA[TS-X64]]></modelName><displayModelName><![CDATA[TS-464]]></displayModelName></model>
<firmware><version><![CDATA[5.2.1]]></version><build><![CDATA[20241008]]></build><patch><![CDATA[0]]></patch><buildTime><![CDATA[2024/10/08]]></buildTime></firmware>
<func><name><![CDATA[sysinfo]]></name><ownContent><root>
<server_name><![CDATA[nas]]></server_name><serial_number><![CDATA[Q23BI12345]]></serial_number>
<sys_tempc><![CDATA[41]]></sys_tempc><sys_tempf><![CDATA[105]]></sys_tempf><cpu_tempc><![CDATA[49]]></cpu_tempc>
<cpu_model><![CDATA[Intel Celeron N5105]]></cpu_model><cpu_usage><![CDATA[7.4 %]]></cpu_usage>
<total_memory><![CDATA[7820.2]]></total_memory><free_memory><![CDATA[2911.6]]></free_memory>
<uptime_day><![CDATA[23]]></uptime_day><uptime_hour><![CDATA[4]]></uptime_hour><uptime_min><![CDATA[17]]></uptime_min><uptime_sec><![CDATA[9]]></uptime_sec>
<timezone><![CDATA[(GMT+00:00) London]]></timezone>
<nic_cnt><![CDATA[2]]></nic_cnt>
<eth_status1><![CDATA[1]]></eth_status1><eth_max_speed1><![CDATA[2500]]></eth_max_speed1><eth_ip1><![CDATA[192.168.1.50]]></eth_ip1><eth_mask1><![CDATA[255.255.255.0]]></eth_mask1><eth_mac1><![CDATA[24:5E:BE:11:22:33]]></eth_mac1><eth_usage1><![CDATA[0]]></eth_usage1><rx_packet1><![CDATA[1]]></rx_packet1><tx_packet1><![CDATA[1]]></tx_packet1><err_packet1><![CDATA[0]]></err_packet1><dname1><![CDATA[Adapter 1]]></dname1>
<eth_status2><![CDATA[0]]></eth_status2><eth_max_speed2><![CDATA[2500]]></eth_max_speed2><eth_ip2><![CDATA[]]></eth_ip2><eth_mask2><![CDATA[]]></eth_mask2><eth_mac2><![CDATA[24:5E:BE:11:22:34]]></eth_mac2><eth_usage2><![CDATA[0]]></eth_usage2><rx_packet2><![CDATA[0]]></rx_packet2><tx_packet2><![CDATA[0]]></tx_packet2><err_packet2><![CDATA[0]]></err_packet2><dname2><![CDATA[Adapter 2]]></dname2>
<sysfan_count><![CDATA[1]]></sysfan_count><sysfan1><![CDATA[1045]]></sysfan1><sysfan1_stat><![CDATA[0]]></sysfan1_stat>
</root></ownContent></func>`)
	}))
	mux.HandleFunc("/cgi-bin/management/chartReq.cgi", authed(func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString(`<volumeList><volume><volumeValue><![CDATA[1]]></volumeValue><volumeLabel><![CDATA[DataVol1]]></volumeLabel></volume>` +
			`<volume><volumeValue><![CDATA[2]]></volumeValue><volumeLabel><![CDATA[Backup]]></volumeLabel></volume></volumeList><volumeUseList>`)
		for _, vol := range []struct {
			id    string
			total int64
		}{{"1", 5_340 << 30}, {"2", 3_580 << 30}} {
			var used int64
			var folders strings.Builder
			for _, s := range shares {
				if s.vol == vol.id {
					used += s.used
					fmt.Fprintf(&folders, `<folder_element><sharename><![CDATA[%s]]></sharename><used_size><![CDATA[%d]]></used_size></folder_element>`, s.name, s.used)
				}
			}
			used += 60 << 30 // system and snapshot reserve
			fmt.Fprintf(&b, `<volumeUse><volumeValue><![CDATA[%s]]></volumeValue><total_size><![CDATA[%d]]></total_size><free_size><![CDATA[%d]]></free_size>%s</volumeUse>`,
				vol.id, vol.total, vol.total-used, folders.String())
		}
		b.WriteString(`</volumeUseList>`)
		xmlOut(w, b.String())
	}))
	mux.HandleFunc("/cgi-bin/disk/qsmart.cgi", authed(func(w http.ResponseWriter, r *http.Request) {
		disks := []struct{ no, health, temp, capa, model, serial, ssd string }{
			{"1", "Good", "38", "3.64 TB", "WDC WD40EFPX-68C6CN0", "WD-WX12A3456789", "0"},
			{"2", "Good", "40", "3.64 TB", "WDC WD40EFPX-68C6CN0", "WD-WX12A3456790", "0"},
			{"3", "Good", "52", "3.64 TB", "ST4000VN006-3CW104", "ZW60ABCD", "0"},
			{"4", "Warning", "41", "3.64 TB", "ST4000VN006-3CW104", "ZW60ABCE", "0"},
			{"5", "", "", "", "", "", "0"}, // empty bay
		}
		var b strings.Builder
		b.WriteString("<Disk_Info>")
		for _, d := range disks {
			fmt.Fprintf(&b, `<entry><HDNo><![CDATA[%s]]></HDNo><Health><![CDATA[%s]]></Health><Temperature><oC><![CDATA[%s]]></oC><oF><![CDATA[]]></oF></Temperature><Capacity><![CDATA[%s]]></Capacity><Model><![CDATA[%s]]></Model><Serial><![CDATA[%s]]></Serial><hd_is_ssd><![CDATA[%s]]></hd_is_ssd></entry>`,
				d.no, d.health, d.temp, d.capa, d.model, d.serial, d.ssd)
		}
		b.WriteString("</Disk_Info>")
		xmlOut(w, b.String())
	}))
	mux.HandleFunc("/cgi-bin/sys/sysRequest.cgi", authed(func(w http.ResponseWriter, r *http.Request) {
		switch r.FormValue("subfunc") {
		case "firm_update":
			xmlOut(w, `<func><ownContent><newVersion><![CDATA[5.2.2.2950 build 20241114]]></newVersion></ownContent></func>`)
		case "power_mgmt":
			if a := r.FormValue("apply"); a == "restart" || a == "shutdown" {
				restarts++
				xmlOut(w, `<result><![CDATA[0]]></result>`)
				return
			}
			http.Error(w, "bad apply", 400)
		default:
			xmlOut(w, "")
		}
	}))
	mux.HandleFunc("/cgi-bin/filemanager/utilRequest.cgi", authed(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.FormValue("func") {
		case "get_tree":
			var out []map[string]any
			for _, s := range shares {
				out = append(out, map[string]any{"text": s.name, "id": "/" + s.name, "cls": "r", "iconCls": "folder"})
			}
			out = append(out, map[string]any{"text": "USBDisk1", "id": "/USBDisk1", "cls": "r", "iconCls": "usb"})
			_ = json.NewEncoder(w).Encode(out)
		case "createdir":
			p := r.FormValue("dest_path") + "/" + r.FormValue("dest_folder")
			if folders[p] {
				_ = json.NewEncoder(w).Encode(map[string]int{"status": 33})
				return
			}
			folders[p] = true
			_ = json.NewEncoder(w).Encode(map[string]int{"status": 1})
		default:
			_ = json.NewEncoder(w).Encode(map[string]int{"status": 0})
		}
	}))
	return mux
}

// Synology emulates the DSM Web API calls NCC makes: login, system info and utilisation,
// storage, shares, share snapshots (with create and delete), share creation and power.
// It accepts the user "ncc" with password.
func Synology(password string) http.Handler {
	const sid = "mock-dsm-sid"
	var lock sync.Mutex
	type snap struct {
		time, desc string
		lock       bool
	}
	type share struct {
		name, vol, desc string
		usedMB          int64
		snaps           []snap
	}
	now := time.Now().UTC()
	snapName := func(t time.Time) string { return "GMT+00-" + t.Format("2006.01.02-15.04.05") }
	shares := []*share{
		{name: "photo", vol: "/volume1", desc: "Family photos", usedMB: 1_240_000, snaps: []snap{
			{snapName(now.Add(-26 * time.Hour).Truncate(time.Hour)), "Daily", false},
			{snapName(now.Add(-2 * time.Hour).Truncate(time.Hour)), "Daily", false},
			{snapName(now.Add(-24 * 7 * time.Hour).Truncate(time.Hour)), "Weekly (kept)", true},
		}},
		{name: "docker", vol: "/volume1", usedMB: 84_000},
		{name: "homes", vol: "/volume1", desc: "user home", usedMB: 312_000, snaps: []snap{{snapName(now.Add(-5 * time.Hour).Truncate(time.Hour)), "Before upgrade", false}}},
		{name: "video", vol: "/volume1", usedMB: 2_960_000},
	}
	ok := func(w http.ResponseWriter, data any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "data": data})
	}
	fail := func(w http.ResponseWriter, code int) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "error": map[string]int{"code": code}})
	}
	find := func(name string) *share {
		for _, s := range shares {
			if s.name == name {
				return s
			}
		}
		return nil
	}
	unq := func(s string) string {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/webapi/entry.cgi" {
			http.NotFound(w, r)
			return
		}
		_ = r.ParseForm()
		api, method := r.FormValue("api"), r.FormValue("method")
		if api == "SYNO.API.Auth" {
			if method == "logout" {
				ok(w, nil)
				return
			}
			if r.FormValue("account") != "ncc" || r.FormValue("passwd") != password {
				fail(w, 400)
				return
			}
			ok(w, map[string]string{"sid": sid})
			return
		}
		if r.FormValue("_sid") != sid {
			fail(w, 119)
			return
		}
		lock.Lock()
		defer lock.Unlock()
		const gib = int64(1) << 30
		switch api + "." + method {
		case "SYNO.Core.System.info":
			if r.FormValue("type") == "network" {
				ok(w, map[string]string{"server_name": "ds920"})
				return
			}
			ok(w, map[string]any{"model": "DS920+", "serial": "2080QWR123456", "firmware_ver": "DSM 7.2.2-72806 Update 2", "ram_size": 8192,
				"sys_temp": 44, "up_time": "1462:12:40", "cpu_series": "J4125"})
		case "SYNO.Core.System.Utilization.get":
			ok(w, map[string]any{"cpu": map[string]int{"user_load": 9, "system_load": 3, "other_load": 1},
				"memory": map[string]int{"total_real": 8_062_000, "avail_real": 2_400_000, "real_usage": 41}})
		case "SYNO.Storage.CGI.Storage.load_info":
			var used int64
			for _, s := range shares {
				used += s.usedMB << 20
			}
			ok(w, map[string]any{
				"disks": []map[string]any{
					{"id": "sata1", "name": "Drive 1", "model": "HAT5300-8T", "vendor": "Synology", "serial": "21A0A0XXXX01", "size_total": 8001563222016, "temp": 36, "status": "normal", "smart_status": "normal", "diskType": "SATA", "isSsd": false},
					{"id": "sata2", "name": "Drive 2", "model": "HAT5300-8T", "vendor": "Synology", "serial": "21A0A0XXXX02", "size_total": 8001563222016, "temp": 37, "status": "normal", "smart_status": "normal", "diskType": "SATA", "isSsd": false},
					{"id": "sata3", "name": "Drive 3", "model": "HAT5300-8T", "vendor": "Synology", "serial": "21A0A0XXXX03", "size_total": 8001563222016, "temp": 38, "status": "normal", "smart_status": "normal", "diskType": "SATA", "isSsd": false},
					{"id": "nvme0n1", "name": "M.2 Drive 1", "model": "SNV3410-400G", "vendor": "Synology", "serial": "NV34XX01", "size_total": 400088457216, "temp": 47, "status": "normal", "smart_status": "normal", "diskType": "M.2 NVMe", "isSsd": true},
				},
				"storagePools": []map[string]any{
					{"id": "reuse_1", "num_id": 1, "desc": "", "status": "normal", "device_type": "shr_with_1_disk_protect", "size": map[string]int64{"total": 14_900 * gib, "used": 14_400 * gib}, "disks": []string{"sata1", "sata2", "sata3"}},
				},
				"volumes": []map[string]any{
					{"id": "volume_1", "num_id": 1, "desc": "", "vol_path": "/volume1", "status": "normal", "fs_type": "btrfs", "pool_path": "reuse_1",
						"size": map[string]int64{"total": 14_300 * gib, "used": used + 900*gib}},
				},
			})
		case "SYNO.Core.Share.list":
			var out []map[string]any
			for _, s := range shares {
				out = append(out, map[string]any{"name": s.name, "vol_path": s.vol, "desc": s.desc, "hidden": false, "encryption": 0,
					"additional": map[string]any{"share_quota_used": s.usedMB, "share_quota": 0, "is_support_snapshot": true}})
			}
			ok(w, map[string]any{"shares": out, "total": len(out)})
		case "SYNO.Core.Share.create":
			var info struct {
				Name    string `json:"name"`
				VolPath string `json:"vol_path"`
				Desc    string `json:"desc"`
			}
			_ = json.Unmarshal([]byte(r.FormValue("shareinfo")), &info)
			if find(info.Name) != nil {
				fail(w, 3300)
				return
			}
			if info.VolPath != "/volume1" {
				fail(w, 3309)
				return
			}
			shares = append(shares, &share{name: info.Name, vol: info.VolPath, desc: info.Desc})
			ok(w, map[string]string{"name": info.Name})
		case "SYNO.Core.Share.Snapshot.list":
			s := find(unq(r.FormValue("name")))
			if s == nil {
				fail(w, 402)
				return
			}
			var out []map[string]any
			for _, sn := range s.snaps {
				out = append(out, map[string]any{"time": sn.time, "desc": sn.desc, "lock": sn.lock})
			}
			ok(w, map[string]any{"snapshots": out, "total": len(out)})
		case "SYNO.Core.Share.Snapshot.create":
			s := find(unq(r.FormValue("name")))
			if s == nil {
				fail(w, 402)
				return
			}
			var info struct {
				Desc string `json:"desc"`
			}
			_ = json.Unmarshal([]byte(r.FormValue("snapinfo")), &info)
			t := snapName(time.Now().UTC().Add(time.Duration(len(s.snaps)) * time.Second))
			s.snaps = append(s.snaps, snap{time: t, desc: info.Desc})
			ok(w, t)
		case "SYNO.Core.Share.Snapshot.delete":
			s := find(unq(r.FormValue("name")))
			var ids []string
			_ = json.Unmarshal([]byte(r.FormValue("snapshots")), &ids)
			if s == nil || len(ids) == 0 {
				fail(w, 402)
				return
			}
			keep := s.snaps[:0]
			for _, sn := range s.snaps {
				if sn.time != ids[0] {
					keep = append(keep, sn)
				}
			}
			s.snaps = keep
			ok(w, nil)
		case "SYNO.FileStation.CreateFolder.create":
			ok(w, map[string]any{"folders": []map[string]string{{"path": unq(r.FormValue("folder_path")) + "/" + unq(r.FormValue("name"))}}})
		case "SYNO.Core.Upgrade.Server.check":
			ok(w, map[string]any{"available": false})
		case "SYNO.Core.System.reboot", "SYNO.Core.System.shutdown":
			ok(w, nil)
		default:
			fail(w, 102)
		}
	})
}
