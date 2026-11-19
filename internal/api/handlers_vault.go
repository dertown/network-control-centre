package api

import (
	"net/http"

	"github.com/dertown/network-control-centre/internal/vault"
)

func (s *Server) vaultStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.Vault.Status(r.Context()))
}

func (s *Server) vaultUnseal(w http.ResponseWriter, r *http.Request) {
	u, ok := s.Vault.(vault.Unsealer)
	if !ok {
		writeErr(w, 400, "this vault backend is not unsealed through NCC")
		return
	}
	var in struct {
		Passphrase string `json:"passphrase"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := u.Unseal(r.Context(), in.Passphrase); err != nil {
		_ = s.Audit.Record(r.Context(), actor(r), "vault.unseal.failed", "vault", nil)
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "vault.unseal", "vault", nil)
	go s.Poller.PollAll(s.bg())
	writeJSON(w, 200, s.Vault.Status(r.Context()))
}

func (s *Server) vaultSeal(w http.ResponseWriter, r *http.Request) {
	u, ok := s.Vault.(vault.Unsealer)
	if !ok {
		writeErr(w, 400, "this vault backend is not sealed through NCC")
		return
	}
	u.Seal()
	_ = s.Audit.Record(r.Context(), actor(r), "vault.seal", "vault", nil)
	writeJSON(w, 200, s.Vault.Status(r.Context()))
}

func (s *Server) vaultList(w http.ResponseWriter, r *http.Request) {
	ps, err := s.Vault.List(r.Context(), r.URL.Query().Get("prefix"))
	if err != nil {
		s.fail(w, err)
		return
	}
	if ps == nil {
		ps = []string{}
	}
	writeJSON(w, 200, ps)
}

// vaultGet returns the keys of a secret with values hidden.
func (s *Server) vaultGet(w http.ResponseWriter, r *http.Request) {
	sec, err := s.Vault.Get(r.Context(), r.PathValue("path"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"path": r.PathValue("path"), "values": vault.Redact(sec)})
}

// vaultReveal returns secret values; every call is audited.
func (s *Server) vaultReveal(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Path string `json:"path"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	sec, err := s.Vault.Get(r.Context(), in.Path)
	if err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "vault.reveal", "secret/"+in.Path, nil)
	writeJSON(w, 200, map[string]any{"path": in.Path, "values": sec})
}

func (s *Server) vaultPut(w http.ResponseWriter, r *http.Request) {
	var in vault.Secret
	if !readJSON(w, r, &in) {
		return
	}
	v, err := s.Vault.Put(r.Context(), r.PathValue("path"), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	_ = s.Audit.Record(r.Context(), actor(r), "vault.put", "secret/"+r.PathValue("path"), map[string]any{"keys": keys, "version": v})
	writeJSON(w, 200, map[string]int{"version": v})
}

func (s *Server) vaultDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.Vault.Delete(r.Context(), r.PathValue("path")); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "vault.delete", "secret/"+r.PathValue("path"), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
