package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/dertown/network-control-centre/internal/certdeploy"
)

func (s *Server) deployReady(w http.ResponseWriter) bool {
	if s.Deploy == nil {
		writeErr(w, 404, "certificate deployment is not set up")
		return false
	}
	return true
}

func (s *Server) deployFail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, certdeploy.ErrNotFound):
		writeErr(w, 404, err.Error())
	case errors.Is(err, certdeploy.ErrBusy):
		writeErr(w, 409, err.Error())
	default:
		s.fail(w, err)
	}
}

func (s *Server) deployKinds(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, certdeploy.Kinds())
}

func (s *Server) deployTargets(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	ts, err := s.Deploy.List(r.Context())
	if err != nil {
		s.deployFail(w, err)
		return
	}
	if ts == nil {
		ts = []certdeploy.Target{}
	}
	writeJSON(w, 200, ts)
}

type deployTargetIn struct {
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Options     map[string]string `json:"options"`
	CertID      int64             `json:"cert_id"`
	Credentials map[string]string `json:"credentials"`
	Clear       []string          `json:"clear_credentials"`
}

func (s *Server) createDeployTarget(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	var in deployTargetIn
	if !readJSON(w, r, &in) {
		return
	}
	t := &certdeploy.Target{Name: in.Name, Kind: in.Kind, Host: in.Host, Port: in.Port, Options: in.Options, CertID: in.CertID}
	if err := s.Deploy.Create(r.Context(), t); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(in.Credentials) > 0 {
		if err := s.Deploy.SetCredentials(r.Context(), t.ID, in.Credentials, nil); err != nil {
			_ = s.Deploy.Delete(r.Context(), t.ID)
			s.deployFail(w, err)
			return
		}
	}
	_ = s.Audit.Record(r.Context(), actor(r), "deploy.target.create", "deploy/"+t.Name,
		map[string]any{"kind": t.Kind, "host": t.Host, "port": t.Port, "options": t.Options, "credentials": keysOf(in.Credentials)})
	writeJSON(w, 201, t)
}

func keysOf(m map[string]string) []string {
	var out []string
	for k, v := range m {
		if v != "" {
			out = append(out, k)
		}
	}
	return out
}

func (s *Server) updateDeployTarget(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	var in deployTargetIn
	if !readJSON(w, r, &in) {
		return
	}
	t := &certdeploy.Target{ID: id, Host: in.Host, Port: in.Port, Options: in.Options, CertID: in.CertID}
	if err := s.Deploy.Update(r.Context(), t); err != nil {
		if errors.Is(err, certdeploy.ErrNotFound) {
			s.deployFail(w, err)
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	if len(in.Credentials) > 0 || len(in.Clear) > 0 {
		if err := s.Deploy.SetCredentials(r.Context(), id, in.Credentials, in.Clear); err != nil {
			s.deployFail(w, err)
			return
		}
	}
	_ = s.Audit.Record(r.Context(), actor(r), "deploy.target.update", "deploy/"+t.Name,
		map[string]any{"host": t.Host, "port": t.Port, "options": t.Options, "cert_id": t.CertID,
			"credentials_set": keysOf(in.Credentials), "credentials_cleared": in.Clear})
	writeJSON(w, 200, t)
}

func (s *Server) deleteDeployTarget(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	t, err := s.Deploy.Get(r.Context(), id)
	if err != nil {
		s.deployFail(w, err)
		return
	}
	if err := s.Deploy.Delete(r.Context(), id); err != nil {
		s.deployFail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "deploy.target.delete", "deploy/"+t.Name, map[string]any{"kind": t.Kind, "host": t.Host})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deployServed(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	info, err := s.Deploy.ServedBy(r.Context(), id)
	if err != nil {
		s.deployFail(w, err)
		return
	}
	writeJSON(w, 200, info)
}

func (s *Server) deployPlan(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	var in struct {
		TargetID int64 `json:"target_id"`
		CertID   int64 `json:"cert_id"`
		Connect  bool  `json:"connect"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	plan, err := s.Deploy.Plan(r.Context(), in.TargetID, in.CertID, in.Connect)
	if err != nil {
		if err.Error() == "certificate not found" {
			writeErr(w, 404, err.Error())
			return
		}
		s.deployFail(w, err)
		return
	}
	writeJSON(w, 200, plan)
}

func (s *Server) deployRun(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	var in struct {
		TargetID int64  `json:"target_id"`
		CertID   int64  `json:"cert_id"`
		Accept   string `json:"accept_fingerprint"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	d, err := s.Deploy.Deploy(r.Context(), in.TargetID, in.CertID, in.Accept, actor(r))
	if err != nil {
		if errors.Is(err, certdeploy.ErrNotFound) || errors.Is(err, certdeploy.ErrBusy) {
			s.deployFail(w, err)
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 202, d)
}

func (s *Server) deployHistory(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	target, _ := strconv.ParseInt(r.URL.Query().Get("target"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	ds, err := s.Deploy.History(r.Context(), target, limit)
	if err != nil {
		s.deployFail(w, err)
		return
	}
	writeJSON(w, 200, ds)
}

func (s *Server) deployment(w http.ResponseWriter, r *http.Request) {
	if !s.deployReady(w) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	d, err := s.Deploy.Deployment(r.Context(), id)
	if err != nil {
		s.deployFail(w, err)
		return
	}
	writeJSON(w, 200, d)
}
