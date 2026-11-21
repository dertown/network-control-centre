package api

import (
	"net/http"
)

func (s *Server) listCerts(w http.ResponseWriter, r *http.Request) {
	cs, err := s.Certs.List(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if cs == nil {
		writeJSON(w, 200, []any{})
		return
	}
	writeJSON(w, 200, cs)
}

func (s *Server) importCert(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
		CAPEM   string `json:"ca_bundle_pem"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	c, err := s.Certs.Import(r.Context(), in.Name, in.CertPEM, in.KeyPEM, in.CAPEM)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "cert.import", "cert/"+c.Name,
		map[string]any{"fingerprint": c.Fingerprint, "not_after": c.NotAfter, "has_key": c.HasKey, "chain": c.Chain, "dropped": c.Dropped})
	writeJSON(w, 201, c)
}

func (s *Server) certPEM(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	p, err := s.Certs.PEM(r.Context(), id)
	if err != nil {
		writeErr(w, 404, "certificate not found")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write([]byte(p))
}

func (s *Server) deleteCert(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	if err := s.Certs.Delete(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "cert.delete", "cert/"+r.PathValue("id"), nil)
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// setCertChain replaces the CA certificates (intermediates and root) stored with a certificate.
func (s *Server) setCertChain(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	var in struct {
		CAPEM string `json:"ca_bundle_pem"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if _, err := s.Certs.PEM(r.Context(), id); err != nil {
		writeErr(w, 404, "certificate not found")
		return
	}
	c, err := s.Certs.SetChain(r.Context(), id, in.CAPEM)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "cert.chain", "cert/"+c.Name, map[string]any{"chain": c.Chain, "dropped": c.Dropped})
	writeJSON(w, 200, c)
}
