// Command ncc-mock runs a pretend UniFi console and PowerDNS server so you can try NCC
// without touching a real network.
//
//	go run ./cmd/ncc-mock
//
// UniFi console:  https://localhost:9443   user "ncc", password "demo-password" (or API key "demo-key")
// PowerDNS API:   http://localhost:9081    API key "demo-pdns-key"
package main

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"

	"github.com/dertown/network-control-centre/internal/mocklab"
)

func main() {
	unifi := httptest.NewUnstartedServer(mocklab.UniFi())
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
