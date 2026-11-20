// Command ncc-mock runs a pretend UniFi console and PowerDNS server so you can try NCC
// without touching a real network.
//
//	go run ./cmd/ncc-mock
//
// UniFi console:  https://localhost:9443   user "ncc", password "demo-password" (or API key "demo-key")
// PowerDNS API:   http://localhost:9081    API key "demo-pdns-key"
//
// With -loops the pretend network has two switching loops cabled in, for loop detection.
//
// With -dnslog localhost:4242 it also plays a PowerDNS Recursor streaming query logs to
// NCC's dns_log receiver, so the Traffic page shows sites per client.
package main

import (
	"flag"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/signal"
	"time"

	"github.com/dertown/network-control-centre/internal/dnslog"
	"github.com/dertown/network-control-centre/internal/mocklab"
)

func main() {
	dnsTo := flag.String("dnslog", "", "send pretend DNS query logs to this NCC dns_log address, e.g. localhost:4242")
	loops := flag.Bool("loops", false, "cable two switching loops into the pretend network, to try loop detection")
	flag.Parse()
	if *dnsTo != "" {
		go sendDNS(*dnsTo)
	}
	handler := mocklab.UniFi()
	if *loops {
		handler = mocklab.UniFiWithLoops()
		log.Printf("pretend network has switching loops (-loops)")
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
