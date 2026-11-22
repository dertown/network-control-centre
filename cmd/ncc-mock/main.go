// Command ncc-mock runs a pretend UniFi console, PowerDNS server, Proxmox VE cluster, vCenter, QNAP and Synology NAS and a Home Assistant smart home so you can try NCC
// without touching a real network.
//
//	go run ./cmd/ncc-mock
//
// UniFi console:  https://localhost:9443   user "ncc", password "demo-password" (or API key "demo-key")
// PowerDNS API:   http://localhost:9081    API key "demo-pdns-key"
// Recursor API:   http://localhost:9082    API key "demo-pdns-key"
// Proxmox VE:     https://localhost:9006   token "ncc@pve!monitor" / "demo-token-secret" (or root@pam / demo-password)
// VMware vCenter: https://localhost:9007   user "ncc", password "demo-password"
// QNAP NAS:       https://localhost:9050   user "admin", password "demo-password"
// Synology NAS:   https://localhost:9051   user "ncc", password "demo-password"
// Home Assistant: http://localhost:9123    long-lived token "demo-ha-token"
//
// With -loops the pretend network has two switching loops cabled in, for loop detection.
//
// With -dnslog localhost:4242 it also plays a PowerDNS Recursor streaming query logs to
// NCC's dns_log receiver, so the Traffic page shows sites per client.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/vmware/govmomi/simulator"

	"github.com/dertown/network-control-centre/internal/dnslog"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func main() {
	dnsTo := flag.String("dnslog", "", "send pretend DNS query logs to this NCC dns_log address, e.g. localhost:4242")
	loops := flag.Bool("loops", false, "cable two switching loops into the pretend network, to try loop detection")
	office := flag.Bool("office", false, "add an office's IoT devices (cameras, phones, door controller, UPS...) to the pretend network")
	flag.Parse()
	if *dnsTo != "" {
		go sendDNS(*dnsTo)
	}
	handler := mocklab.UniFi()
	if *loops {
		handler = mocklab.UniFiWithLoops()
		log.Printf("pretend network has switching loops (-loops)")
	}
	if *office {
		handler = mocklab.UniFiOffice()
		log.Printf("pretend network has office IoT devices (-office)")
	}
	unifi := httptest.NewUnstartedServer(handler)
	l, err := netListen(":9443")
	if err != nil {
		log.Fatal(err)
	}
	unifi.Listener = l
	unifi.StartTLS()
	log.Printf("mock UniFi console on https://localhost:9443 (user ncc / demo-password)")

	go func() {
		log.Printf("mock PowerDNS API on http://localhost:9081 (api key demo-pdns-key)")
		log.Fatal(http.ListenAndServe(":9081", mocklab.NewPowerDNS("demo-pdns-key")))
	}()
	go func() {
		log.Printf("mock PowerDNS Recursor API on http://localhost:9082 (api key demo-pdns-key)")
		log.Fatal(http.ListenAndServe(":9082", mocklab.NewRecursor("demo-pdns-key")))
	}()
	pve := httptest.NewUnstartedServer(mocklab.Proxmox("demo-token-secret", "demo-password"))
	if pve.Listener, err = netListen(":9006"); err != nil {
		log.Fatal(err)
	}
	pve.StartTLS()
	log.Printf("mock Proxmox VE on https://localhost:9006 (token ncc@pve!monitor / demo-token-secret)")

	for _, m := range []struct {
		addr, name, user string
		h                http.Handler
	}{{":9050", "QNAP NAS", "admin", mocklab.QNAP("demo-password")}, {":9051", "Synology NAS", "ncc", mocklab.Synology("demo-password")}} {
		srv := httptest.NewUnstartedServer(m.h)
		if srv.Listener, err = netListen(m.addr); err != nil {
			log.Fatal(err)
		}
		srv.StartTLS()
		log.Printf("mock %s on https://localhost%s (user %s / demo-password)", m.name, m.addr, m.user)
	}

	go func() {
		log.Printf("mock Home Assistant on http://localhost:9123 (token demo-ha-token)")
		log.Fatal(http.ListenAndServe(":9123", mocklab.HomeAssistant("demo-ha-token")))
	}()

	vc := simulator.VPX()
	vc.Machine = 3
	if err := vc.Create(); err != nil {
		log.Fatal(err)
	}
	vc.Service.TLS = new(tls.Config)
	vc.Service.Listen = &url.URL{Host: "0.0.0.0:9007", User: url.UserPassword("ncc", "demo-password")}
	vc.Service.NewServer()
	log.Printf("mock VMware vCenter on https://localhost:9007 (user ncc / demo-password)")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
}

// demoLookups is what each mock client looks up, matching the mock DPI data.
var demoLookups = map[string][]string{
	"192.168.1.61": {"r3---sn-ab5l6n7s.googlevideo.com", "i.ytimg.com", "www.youtube.com", "ipv4-c001.nflxvideo.net", "api-global.netflix.com", "samsungcloud.com"},
	"192.168.1.70": {"scontent.cdninstagram.com", "i.instagram.com", "v16-webapp.tiktokv.com", "mmg.whatsapp.net", "www.bbc.co.uk", "gateway.icloud.com"},
	"192.168.1.80": {"cdn.steamcontent.com", "store.steampowered.com", "gateway.discord.gg", "discord.com", "github.com", "www.google.com", "www.reddit.com"},
	"192.168.1.50": {"update.synology.com", "global.synologydownload.com", "s3.amazonaws.com"},
}

func sendDNS(addr string) {
	ips := make([]string, 0, len(demoLookups))
	for ip := range demoLookups {
		ips = append(ips, ip)
	}
	for {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Printf("dnslog: %v (retrying)", err)
			time.Sleep(5 * time.Second)
			continue
		}
		log.Printf("sending pretend DNS query logs to %s", addr)
		for err == nil {
			ip := ips[rand.IntN(len(ips))]
			names := demoLookups[ip]
			// earlier names are looked up more often
			name := names[int(float64(len(names))*rand.Float64()*rand.Float64())]
			err = dnslog.Send(conn, dnslog.Query{From: netip.MustParseAddr(ip), Name: name, QType: 1, Time: time.Now()})
			time.Sleep(20 * time.Millisecond)
		}
		conn.Close()
	}
}
