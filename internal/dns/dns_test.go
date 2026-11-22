package dns

import (
	"net/netip"
	"testing"
)

func TestPTRName(t *testing.T) {
	got, _ := PTRName("192.168.1.50")
	if got != "50.1.168.192.in-addr.arpa." {
		t.Fatal(got)
	}
	got, _ = PTRName("2001:db8::1")
	if got != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa." {
		t.Fatal(got)
	}
}

func TestQualifyAndValidate(t *testing.T) {
	if q := Qualify("nas", "home.lan"); q != "nas.home.lan." {
		t.Fatal(q)
	}
	if q := Qualify("@", "home.lan."); q != "home.lan." {
		t.Fatal(q)
	}
	if q := Qualify("NAS.home.lan", "home.lan."); q != "nas.home.lan." {
		t.Fatal(q)
	}
	ok := Change{Op: Replace, RRSet: RRSet{Name: "nas.home.lan.", Type: "A", TTL: 300, Records: []string{"192.168.1.50"}}}
	if err := Validate("home.lan.", ok); err != nil {
		t.Fatal(err)
	}
	bad := []Change{
		{Op: Replace, RRSet: RRSet{Name: "nas.other.lan.", Type: "A", Records: []string{"1.2.3.4"}}},
		{Op: Replace, RRSet: RRSet{Name: "nas.home.lan.", Type: "A", Records: []string{"not-an-ip"}}},
		{Op: Replace, RRSet: RRSet{Name: "nas.home.lan.", Type: "AAAA", Records: []string{"1.2.3.4"}}},
		{Op: Replace, RRSet: RRSet{Name: "www.home.lan.", Type: "CNAME", Records: []string{"a.", "b."}}},
		{Op: Delete, RRSet: RRSet{Name: "home.lan.", Type: "SOA"}},
		{Op: "UPSERT", RRSet: RRSet{Name: "nas.home.lan.", Type: "A"}},
	}
	for i, c := range bad {
		if Validate("home.lan.", c) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if z := BestZone("50.1.168.192.in-addr.arpa.", []Zone{{Name: "168.192.in-addr.arpa."}, {Name: "1.168.192.in-addr.arpa."}, {Name: "home.lan."}}); z != "1.168.192.in-addr.arpa." {
		t.Fatal(z)
	}
}

func TestValidateZoneName(t *testing.T) {
	for in, want := range map[string]string{"IoT.Home.LAN": "iot.home.lan.", "dmz.corp.lan.": "dmz.corp.lan.", "30.168.192.in-addr.arpa": "30.168.192.in-addr.arpa."} {
		if got, err := ValidateZoneName(in); err != nil || got != want {
			t.Errorf("%q: %q %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "lan", "-iot.home.lan", "io t.home.lan", "iot..home.lan", "iot-.home.lan"} {
		if _, err := ValidateZoneName(bad); err == nil {
			t.Errorf("%q should be refused", bad)
		}
	}
}

func TestParentAndReverseZone(t *testing.T) {
	zones := []Zone{{Name: "lan."}, {Name: "home.lan."}, {Name: "iot.home.lan."}}
	if p := ParentZone("cams.iot.home.lan.", zones); p != "iot.home.lan." {
		t.Fatalf("parent: %q", p)
	}
	if p := ParentZone("iot.home.lan", zones); p != "home.lan." {
		t.Fatalf("a zone is not its own parent: %q", p)
	}
	if p := ParentZone("corp.example.", zones); p != "" {
		t.Fatalf("no parent: %q", p)
	}
	for in, want := range map[string]string{
		"192.168.30.0/24": "30.168.192.in-addr.arpa.", "10.20.0.0/22": "20.10.in-addr.arpa.",
		"192.168.50.64/26": "50.168.192.in-addr.arpa.", "10.0.0.0/8": "10.in-addr.arpa.",
		"2001:db8:30::/48": "0.3.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
	} {
		if got := ReverseZone(netip.MustParsePrefix(in)); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}
