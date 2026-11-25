package api

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/ca"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/vault"
)

// Internal certificate authority: create the root (and intermediates), issue, renew and revoke
// certificates, DNS-based suggestions, downloads and install instructions. The /pki/ paths are
// public (no login) so devices and people can fetch the root certificate and the CRL.

func (s *Server) caSvc() *ca.Service {
	s.caOnce.Do(func() {
		if s.CA == nil {
			s.CA = &ca.Service{DB: s.Store.DB, Vault: s.Vault, Certs: s.Certs}
		}
	})
	return s.CA
}

func (s *Server) caFail(w http.ResponseWriter, err error) {
	if errors.Is(err, ca.ErrNotFound) {
		writeErr(w, 404, "not found")
		return
	}
	s.fail(w, err)
}

// publicBase is NCC's address as the browser sees it, for links in install instructions.
func (s *Server) publicBase(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if p := r.Header.Get("X-Forwarded-Proto"); p == "https" && s.fromTrustedProxy(r) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, p := range s.TrustedProxies {
		if p.Contains(a.Unmap()) {
			return true
		}
	}
	return false
}

func (s *Server) listCAs(w http.ResponseWriter, r *http.Request) {
	cas, err := s.caSvc().List(r.Context())
	if err != nil {
		s.caFail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"cas": cas, "key_types": ca.KeyTypes, "max_leaf_days": ca.MaxLeafDays,
		"default_leaf_days": ca.DefaultLeafDays, "reasons": ca.Reasons, "base": s.publicBase(r)})
}

// createCA makes a root CA and, when asked, an intermediate under it in one go (the wizard).
func (s *Server) createCA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ca.RootRequest
		Intermediate *ca.IntermediateRequest `json:"intermediate"`
		// PublishCRL writes NCC's own CRL address (/pki/ca/{id}.crl) into what each CA signs.
		PublishCRL bool `json:"publish_crl"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	root, err := s.caSvc().CreateRoot(r.Context(), in.RootRequest, actor(r))
	if err != nil {
		s.caError(w, err)
		return
	}
	crlFor := func(c *ca.CA) *ca.CA {
		if !in.PublishCRL {
			return c
		}
		if u, err := s.caSvc().SetCRLURL(r.Context(), c.ID, s.publicBase(r)+"/pki/ca/"+strconv.FormatInt(c.ID, 10)+".crl"); err == nil {
			return u
		}
		return c
	}
	root = crlFor(root)
	_ = s.Audit.Record(r.Context(), actor(r), "ca.create", "ca/"+root.Name, map[string]any{"subject": root.Subject,
		"key_type": root.KeyType, "not_after": root.NotAfter, "fingerprint": root.Fingerprint, "permitted_domains": root.PermittedDomains})
	out := map[string]any{"root": root}
	if in.Intermediate != nil {
		in.Intermediate.CRLURL = in.CRLURL
		sub, err := s.caSvc().CreateIntermediate(r.Context(), root.ID, *in.Intermediate, actor(r))
		if err != nil {
			out["error"] = "The root CA was created, but the intermediate failed: " + err.Error()
			writeJSON(w, 201, out)
			return
		}
		sub = crlFor(sub)
		_ = s.Audit.Record(r.Context(), actor(r), "ca.intermediate", "ca/"+sub.Name, map[string]any{"parent": root.Name,
			"subject": sub.Subject, "key_type": sub.KeyType, "not_after": sub.NotAfter, "fingerprint": sub.Fingerprint})
		out["intermediate"] = sub
	}
	writeJSON(w, 201, out)
}

// caError sends a sealed vault as 423, unknown ids as 404 and every other problem (mostly
// bad input) as 400 with the message.
func (s *Server) caError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ca.ErrNotFound):
		writeErr(w, 404, "not found")
	case errors.Is(err, vault.ErrSealed):
		s.fail(w, err)
	default:
		writeErr(w, 400, err.Error())
	}
}

func (s *Server) createIntermediate(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	var in ca.IntermediateRequest
	if !readJSON(w, r, &in) {
		return
	}
	sub, err := s.caSvc().CreateIntermediate(r.Context(), id, in, actor(r))
	if err != nil {
		s.caError(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "ca.intermediate", "ca/"+sub.Name, map[string]any{"parent": sub.Parent,
		"subject": sub.Subject, "key_type": sub.KeyType, "not_after": sub.NotAfter, "fingerprint": sub.Fingerprint})
	writeJSON(w, 201, sub)
}

func (s *Server) updateCA(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	var in struct {
		CRLURL string `json:"crl_url"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	c, err := s.caSvc().SetCRLURL(r.Context(), id, in.CRLURL)
	if err != nil {
		s.caError(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "ca.crl_url", "ca/"+c.Name, map[string]any{"crl_url": c.CRLURL})
	writeJSON(w, 200, c)
}

func (s *Server) deleteCA(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	c, err := s.caSvc().Delete(r.Context(), id)
	if err != nil {
		s.caError(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "ca.delete", "ca/"+c.Name, map[string]any{"fingerprint": c.Fingerprint})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) listIssued(w http.ResponseWriter, r *http.Request) {
	caID, _ := strconv.ParseInt(r.URL.Query().Get("ca"), 10, 64)
	out, err := s.caSvc().ListIssued(r.Context(), caID)
	if err != nil {
		s.caFail(w, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) issueCert(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ca.IssueRequest
		CAID int64 `json:"ca_id"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	res, err := s.caSvc().Issue(r.Context(), in.CAID, in.IssueRequest, actor(r))
	if err != nil {
		s.caError(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "ca.issue", "cert/"+res.Issued.CertName, map[string]any{"ca": res.Issued.CAName,
		"serial": res.Issued.Serial, "sans": res.Issued.SANs, "usage": res.Issued.Usage, "not_after": res.Issued.NotAfter, "fingerprint": res.Issued.Fingerprint})
	writeJSON(w, 201, res)
}

func (s *Server) renewIssued(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	var in struct {
		RevokeOld bool `json:"revoke_old"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	res, err := s.caSvc().Renew(r.Context(), id, in.RevokeOld, actor(r))
	if err != nil {
		s.caError(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "ca.renew", "cert/"+res.Issued.CertName, map[string]any{"ca": res.Issued.CAName,
		"replaces": id, "serial": res.Issued.Serial, "not_after": res.Issued.NotAfter, "revoke_old": in.RevokeOld})
	writeJSON(w, 201, res)
}

func (s *Server) revokeIssued(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	var in struct {
		Reason int `json:"reason"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	is, err := s.caSvc().Revoke(r.Context(), id, in.Reason)
	if err != nil {
		s.caError(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "ca.revoke", "cert/"+is.CertName, map[string]any{"ca": is.CAName,
		"serial": is.Serial, "reason": ca.Reasons[in.Reason]})
	writeJSON(w, 200, is)
}

// caInstall is the per-platform install guide for a CA's root.
func (s *Server) caInstall(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, 400, "bad id")
		return
	}
	root, err := s.rootOf(r.Context(), id)
	if err != nil {
		s.caFail(w, err)
		return
	}
	writeJSON(w, 200, ca.Install(root, s.publicBase(r)))
}

// rootOf is the root above a CA (or the CA itself when it is a root).
func (s *Server) rootOf(ctx context.Context, id int64) (*ca.CA, error) {
	chain, err := s.caSvc().Chain(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.caSvc().Get(ctx, chain[len(chain)-1].ID)
}

// ---- suggestions from DNS ----

// caSuggestions reads A, AAAA and CNAME records from every DNS server connection and proposes
// certificates for the names no valid certificate covers yet.
func (s *Server) caSuggestions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	records, problems := s.dnsHostRecords(ctx)
	certs, err := s.Certs.List(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	var holders []ca.Holder
	for _, c := range certs {
		p, err := s.Certs.PEM(ctx, c.ID)
		if err != nil {
			continue
		}
		b, _ := pem.Decode([]byte(p))
		if b == nil {
			continue
		}
		x, err := x509.ParseCertificate(b.Bytes)
		if err != nil || x.IsCA {
			continue
		}
		holders = append(holders, ca.Holder{Name: c.Name, Cert: x})
	}
	var permitted []string
	if cas, err := s.caSvc().List(ctx); err == nil {
		for _, c := range cas {
			if c.Issuing {
				permitted = c.PermittedDomains
			}
		}
	}
	writeJSON(w, 200, map[string]any{"suggestions": ca.Suggest(records, holders, permitted, time.Now()), "problems": problems})
}

// dnsHostRecords lists host records of every forward zone on every enabled DNS connection.
func (s *Server) dnsHostRecords(ctx context.Context) ([]ca.HostRecord, []string) {
	ts, err := s.Targets.List(ctx, core.CategoryDNS)
	if err != nil {
		return nil, []string{err.Error()}
	}
	var mu sync.Mutex
	var out []ca.HostRecord
	problems := []string{}
	var wg sync.WaitGroup
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		wg.Add(1)
		go func(t core.Target) {
			defer wg.Done()
			p, srv, creds, err := zonesEnv{s}.DNSServer(ctx, t.ID)
			if err != nil {
				mu.Lock()
				problems = append(problems, t.Name+": "+err.Error())
				mu.Unlock()
				return
			}
			zones, err := p.ListZones(ctx, srv, creds)
			if err != nil {
				mu.Lock()
				problems = append(problems, t.Name+": "+err.Error())
				mu.Unlock()
				return
			}
			sort.Slice(zones, func(i, j int) bool { return zones[i].Name < zones[j].Name })
			n := 0
			for _, z := range zones {
				zn := strings.ToLower(strings.TrimSuffix(z.Name, "."))
				if strings.HasSuffix(zn, ".arpa") {
					continue
				}
				if n++; n > 50 {
					mu.Lock()
					problems = append(problems, t.Name+": only the first 50 zones were read")
					mu.Unlock()
					break
				}
				sets, err := p.ListRecords(ctx, srv, creds, z.Name)
				if err != nil {
					mu.Lock()
					problems = append(problems, t.Name+" "+zn+": "+err.Error())
					mu.Unlock()
					continue
				}
				mu.Lock()
				for _, rr := range sets {
					out = append(out, hostRecord(rr, zn, t.Name))
				}
				mu.Unlock()
			}
		}(t)
	}
	wg.Wait()
	return out, problems
}

func hostRecord(rr dns.RRSet, zone, server string) ca.HostRecord {
	return ca.HostRecord{Name: rr.Name, Type: rr.Type, Values: rr.Records, Zone: zone, Server: server}
}

// ---- public downloads ----

// pkiFile serves /pki/ca/{file}: {id}.crt (DER), {id}.der, {id}.pem, {id}.crl, {id}.mobileconfig
// and {id}-install.txt. No login: these are public by design.
func (s *Server) pkiFile(w http.ResponseWriter, r *http.Request) {
	f := r.PathValue("file")
	idPart, ext, ok := strings.Cut(f, ".")
	install := false
	if strings.HasSuffix(idPart, "-install") && ext == "txt" {
		idPart, install = strings.TrimSuffix(idPart, "-install"), true
	}
	id, err := strconv.ParseInt(idPart, 10, 64)
	if !ok || err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := s.caSvc().Get(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name := c.FileBase()
	h := w.Header()
	h.Set("Cache-Control", "no-cache")
	switch {
	case install:
		root, err := s.rootOf(r.Context(), id)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		h.Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(ca.InstallText(root, s.publicBase(r))))
	case ext == "pem":
		h.Set("Content-Type", "application/x-pem-file")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.pem"`)
		_, _ = w.Write([]byte(c.PEM()))
	case ext == "crt" || ext == "der" || ext == "cer":
		h.Set("Content-Type", "application/pkix-cert")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.`+ext+`"`)
		_, _ = w.Write(c.Cert().Raw)
	case ext == "crl":
		der, err := s.caSvc().CRL(r.Context(), id)
		if err != nil {
			http.Error(w, "no CRL yet: unseal the vault", http.StatusServiceUnavailable)
			return
		}
		h.Set("Content-Type", "application/pkix-crl")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.crl"`)
		_, _ = w.Write(der)
	case ext == "mobileconfig":
		h.Set("Content-Type", "application/x-apple-aspen-config")
		h.Set("Content-Disposition", `attachment; filename="`+name+`.mobileconfig"`)
		_, _ = w.Write(ca.MobileConfig(c))
	default:
		http.NotFound(w, r)
	}
}
