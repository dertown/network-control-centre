package api_test

import (
	"net/http"
	"strings"
	"testing"
)

func TestAboutAndHealth(t *testing.T) {
	c := adminClient(t)
	var health map[string]any
	if code := c.do("GET", "/api/health", nil, &health); code != 200 || health["status"] != "ok" || health["go_version"] == "" {
		t.Fatalf("health: %d %v", code, health)
	}
	var about struct {
		Name, LicenseID string
		License, Notice string
		ThirdParty      []struct{ Name, Version, Ecosystem, License string } `json:"third_party"`
	}
	if code := c.do("GET", "/api/about", nil, &about); code != 200 {
		t.Fatalf("about: %d", code)
	}
	if !strings.Contains(about.License, "Apache License") || !strings.Contains(about.License, "Version 2.0") {
		t.Fatalf("license text missing: %.80q", about.License)
	}
	if !strings.Contains(about.Notice, "Copyright") {
		t.Fatalf("notice: %q", about.Notice)
	}
	var react bool
	for _, p := range about.ThirdParty {
		react = react || (p.Ecosystem == "npm" && p.Name == "react" && p.License == "MIT")
	}
	if !react || len(about.ThirdParty) < 10 {
		t.Fatalf("third party: %+v", about.ThirdParty)
	}
	// signed-out callers don't get it
	resp, err := http.Get(c.base + "/api/about")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("signed out: %d", resp.StatusCode)
	}
}
