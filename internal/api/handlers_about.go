package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"runtime/debug"
	"sync"

	ncc "github.com/dertown/network-control-centre"
)

// buildInfo describes the running binary: the commit it was built from (when built from a
// git checkout) and the Go version. /api/health reports it next to the version.
type buildInfo struct {
	Commit    string `json:"commit,omitempty"`
	CommitAt  string `json:"commit_time,omitempty"`
	Modified  bool   `json:"modified,omitempty"` // built with uncommitted changes
	GoVersion string `json:"go_version"`
}

var readBuild = sync.OnceValue(func() buildInfo {
	b := buildInfo{GoVersion: runtime.Version()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				b.Commit = s.Value
			case "vcs.time":
				b.CommitAt = s.Value
			case "vcs.modified":
				b.Modified = s.Value == "true"
			}
		}
	}
	return b
})

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	b := readBuild()
	writeJSON(w, 200, map[string]any{
		"status": "ok", "version": s.Version, "commit": b.Commit, "commit_time": b.CommitAt,
		"modified": b.Modified, "go_version": b.GoVersion,
	})
}

// about serves the About page: the project's LICENSE and NOTICE files as built into the
// binary, and the third-party components with their licences.
func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"name":        "Network Control Centre",
		"license_id":  "Apache-2.0",
		"license":     ncc.License,
		"notice":      ncc.Notice,
		"third_party": json.RawMessage(ncc.ThirdPartyJSON),
	})
}
