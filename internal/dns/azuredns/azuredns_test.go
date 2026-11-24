package azuredns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/dertown/network-control-centre/internal/dns"
)

func TestAzureDNS(t *testing.T) {
	var mu sync.Mutex
	logins := 0
	var puts, deletes []string
	var putBody map[string]any
	base := "/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/dnsZones"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path == "/tenant1/oauth2/v2.0/token" {
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "s3cret" || r.Form.Get("grant_type") != "client_credentials" {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"}`)
				return
			}
			logins++
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Query().Get("api-version") != publicAPI {
			w.WriteHeader(400)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == base:
			_, _ = io.WriteString(w, `{"value":[{"name":"contoso.com"}]}`)
		case r.Method == "GET" && r.URL.Path == base+"/contoso.com/recordsets":
			_, _ = io.WriteString(w, `{"value":[
				{"name":"@","type":"Microsoft.Network/dnszones/SOA","properties":{"TTL":3600,"SOARecord":{"host":"ns1-01.azure-dns.com.","email":"azuredns-hostmaster.microsoft.com","serialNumber":1,"refreshTime":3600,"retryTime":300,"expireTime":2419200,"minimumTTL":300}}},
				{"name":"www","type":"Microsoft.Network/dnszones/A","properties":{"TTL":300,"ARecords":[{"ipv4Address":"10.0.0.5"},{"ipv4Address":"10.0.0.6"}]}},
				{"name":"@","type":"Microsoft.Network/dnszones/TXT","properties":{"TTL":300,"TXTRecords":[{"value":["v=spf1 -all"]}]}}
			],"nextLink":""}`)
		case r.Method == "PUT":
			puts = append(puts, r.URL.Path)
			_ = json.NewDecoder(r.Body).Decode(&putBody)
			_, _ = io.WriteString(w, `{}`)
		case r.Method == "DELETE":
			deletes = append(deletes, r.URL.Path)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	s := dns.Server{Kind: "azuredns", Address: srv.URL, Options: map[string]string{
		OptTenant: "tenant1", OptClient: "app1", OptSubscription: "sub1", OptResourceGroup: "rg1", OptAuthority: srv.URL}}
	creds := map[string]string{SecretClient: "s3cret"}
	ctx := context.Background()
	p := Provider{}

	zones, err := p.ListZones(ctx, s, creds)
	if err != nil || len(zones) != 1 || zones[0].Name != "contoso.com." {
		t.Fatalf("zones %+v %v", zones, err)
	}
	sets, err := p.ListRecords(ctx, s, creds, "contoso.com.")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]dns.RRSet{}
	for _, x := range sets {
		got[x.Name+" "+x.Type] = x
	}
	if a := got["www.contoso.com. A"]; len(a.Records) != 2 || a.TTL != 300 {
		t.Fatalf("www A: %+v", a)
	}
	if txt := got["contoso.com. TXT"]; len(txt.Records) != 1 || txt.Records[0] != `"v=spf1 -all"` {
		t.Fatalf("TXT: %+v", txt)
	}
	if soa := got["contoso.com. SOA"]; len(soa.Records) != 1 || !strings.HasPrefix(soa.Records[0], "ns1-01.azure-dns.com. azuredns-hostmaster.microsoft.com. 1 ") {
		t.Fatalf("SOA: %+v", soa)
	}

	err = p.Apply(ctx, s, creds, "contoso.com", []dns.Change{
		{Op: dns.Replace, RRSet: dns.RRSet{Name: "mail.contoso.com.", Type: "MX", TTL: 600, Records: []string{"10 mx1.contoso.com."}}},
		{Op: dns.Delete, RRSet: dns.RRSet{Name: "www.contoso.com.", Type: "A"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(puts) != 1 || puts[0] != base+"/contoso.com/MX/mail" || len(deletes) != 1 || deletes[0] != base+"/contoso.com/A/www" {
		t.Fatalf("puts %v deletes %v", puts, deletes)
	}
	mx := putBody["properties"].(map[string]any)["MXRecords"].([]any)[0].(map[string]any)
	if mx["exchange"] != "mx1.contoso.com" || mx["preference"].(float64) != 10 {
		t.Fatalf("MX body %v", putBody)
	}
	if logins != 1 {
		t.Fatalf("signed in %d times; the token should be reused", logins)
	}

	// a wrong secret shows Entra ID's own reason, first line only
	bad := map[string]string{SecretClient: "nope"}
	if _, err := p.ListZones(ctx, s, bad); err == nil || !strings.Contains(err.Error(), "AADSTS7000215") || strings.Contains(err.Error(), "Trace") {
		t.Fatalf("bad secret: %v", err)
	}
}

func TestSplitTXT(t *testing.T) {
	if got := splitTXT(`"a b" "c\"d"`); len(got) != 2 || got[0] != "a b" || got[1] != `c"d` {
		t.Fatalf("%q", got)
	}
	if got := splitTXT(`plain`); len(got) != 1 || got[0] != "plain" {
		t.Fatalf("%q", got)
	}
}
