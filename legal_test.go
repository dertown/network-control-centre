package ncc

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

type thirdParty struct {
	Name, Version, Ecosystem, License string
	Files                             []struct{ Name, Text string }
}

// TestThirdPartyCurrent fails when a dependency changed without regenerating
// third_party_licenses.json, so the About page never lists stale versions.
func TestThirdPartyCurrent(t *testing.T) {
	if !strings.Contains(License, "Apache License") || !strings.Contains(Notice, "Network Control Centre") {
		t.Fatal("LICENSE or NOTICE not embedded")
	}
	var got []thirdParty
	if err := json.Unmarshal(ThirdPartyJSON, &got); err != nil {
		t.Fatal(err)
	}
	listed := map[string]string{}
	for _, p := range got {
		if len(p.Files) == 0 || p.License == "" {
			t.Errorf("%s has no licence", p.Name)
		}
		listed[p.Ecosystem+" "+p.Name] = p.Version
	}
	want := map[string]string{}
	out, err := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}", "./cmd/ncc").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			want["go "+f[0]] = f[1]
		}
	}
	raw, err := os.ReadFile("web/package-lock.json")
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Packages map[string]struct {
			Version string
			Dev     bool
		}
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	for path, p := range lock.Packages {
		if path != "" && !p.Dev {
			want["npm "+path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):]] = p.Version
		}
	}
	for k, v := range want {
		if listed[k] != v {
			t.Errorf("%s %s is not in third_party_licenses.json (listed: %q); run make licenses", k, v, listed[k])
		}
	}
	for k := range listed {
		if _, ok := want[k]; !ok && k != "go Go standard library" {
			t.Errorf("%s is listed but no longer a dependency; run make licenses", k)
		}
	}
}
