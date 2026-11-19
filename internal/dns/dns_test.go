package dns

import "testing"

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
