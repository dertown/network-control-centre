package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dertown/network-control-centre/internal/assistant"
	"github.com/dertown/network-control-centre/internal/core"
	"github.com/dertown/network-control-centre/internal/dns"
	"github.com/dertown/network-control-centre/internal/dnszones"
	"github.com/dertown/network-control-centre/internal/drivers"
	"github.com/dertown/network-control-centre/internal/vault"
)

// AI assistant: providers (signed in with the person's own subscriptions), plans made from the
// whole network, and deploying the steps a person picked.

type assistantState struct {
	once      sync.Once
	signIns   *assistant.SignIns
	installs  *assistant.Installs
	deploying sync.Mutex
	busy      bool
}

func (s *Server) ai() *assistant.Service {
	s.aiState.once.Do(func() {
		if s.Assistant == nil {
			s.Assistant = &assistant.Service{DB: s.Store.DB, Vault: s.Vault}
		}
		if err := assistant.Migrate(s.Store.DB); err != nil {
			s.Log.Error("assistant tables", "err", err)
		}
		s.aiState.signIns = &assistant.SignIns{Service: s.Assistant}
		s.aiState.installs = &assistant.Installs{Service: s.Assistant}
	})
	return s.Assistant
}

type aiProviderView struct {
	*assistant.Kind
	assistant.Settings
	Installed bool   `json:"installed"`
	Connected bool   `json:"connected"`
	Problem   string `json:"problem,omitempty"`
	// Path is where the tool was found; NCCVersion is the version NCC installed itself.
	Path       string `json:"path,omitempty"`
	NCCVersion string `json:"ncc_version,omitempty"`
	CanInstall bool   `json:"can_install"`
}

func (s *Server) aiProviders(ctx context.Context) ([]aiProviderView, error) {
	svc := s.ai()
	sts, err := svc.Settings(ctx)
	if err != nil {
		return nil, err
	}
	out := []aiProviderView{}
	for i, k := range assistant.Kinds {
		v := aiProviderView{Kind: k, Settings: sts[i], Installed: true}
		if !k.HTTP {
			if p, err := svc.BinaryPath(k, sts[i]); err != nil {
				v.Installed, v.Problem = false, err.Error()
			} else {
				v.Path = p
			}
			v.NCCVersion = svc.InstalledVersion(k)
			v.CanInstall = svc.CanInstall(k)
		}
		c, err := svc.Connected(ctx, k)
		if err != nil && !errors.Is(err, vault.ErrSealed) {
			return nil, err
		}
		v.Connected = c
		out = append(out, v)
	}
	return out, nil
}

func (s *Server) assistantHome(w http.ResponseWriter, r *http.Request) {
	ps, err := s.aiProviders(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	plans, err := s.ai().Plans(r.Context(), 10)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"providers": ps, "plans": plans})
}

func (s *Server) aiKind(w http.ResponseWriter, r *http.Request) *assistant.Kind {
	k, err := assistant.KindByID(r.PathValue("kind"))
	if err != nil {
		writeErr(w, 404, err.Error())
		return nil
	}
	return k
}

func (s *Server) aiUpdateProvider(w http.ResponseWriter, r *http.Request) {
	k := s.aiKind(w, r)
	if k == nil {
		return
	}
	var in struct {
		Enabled *bool   `json:"enabled"`
		Model   *string `json:"model"`
		Binary  *string `json:"binary"`
		Address *string `json:"address"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	st, err := s.ai().Get(r.Context(), k.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	if in.Enabled != nil {
		st.Enabled = *in.Enabled
	}
	if in.Model != nil {
		st.Model = strings.TrimSpace(*in.Model)
	}
	if in.Binary != nil {
		b := strings.TrimSpace(*in.Binary)
		if strings.ContainsAny(b, " \t\n;|&$`") {
			writeErr(w, 400, "give the path to the tool, without arguments")
			return
		}
		st.Binary = b
	}
	if in.Address != nil {
		a := strings.TrimSpace(*in.Address)
		if a != "" && !strings.HasPrefix(a, "http://") && !strings.HasPrefix(a, "https://") {
			writeErr(w, 400, "the address must start with http:// or https://")
			return
		}
		st.Address = a
	}
	if err := s.ai().Save(r.Context(), st); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "assistant.provider", "ai/"+k.ID,
		map[string]any{"enabled": st.Enabled, "model": st.Model, "binary": st.Binary, "address": st.Address})
	writeJSON(w, 200, st)
}

func (s *Server) aiSignIn(w http.ResponseWriter, r *http.Request) {
	k := s.aiKind(w, r)
	if k == nil {
		return
	}
	s.ai()
	v, err := s.aiState.signIns.Start(k.ID)
	if err != nil {
		if errors.Is(err, vault.ErrSealed) {
			s.fail(w, err)
			return
		}
		writeErr(w, 409, err.Error())
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "assistant.signin", "ai/"+k.ID, map[string]any{"started": true})
	writeJSON(w, 200, v)
}

func (s *Server) aiSignInView(w http.ResponseWriter, r *http.Request) {
	s.ai()
	v, err := s.aiState.signIns.View(r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) aiSignInInput(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Text string `json:"text"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	s.ai()
	v, err := s.aiState.signIns.Input(r.PathValue("id"), in.Text)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) aiSignInCancel(w http.ResponseWriter, r *http.Request) {
	s.ai()
	s.aiState.signIns.Cancel(r.PathValue("id"))
	w.WriteHeader(204)
}

// aiInstallPlan shows exactly what installing a provider's tool will do.
func (s *Server) aiInstallPlan(w http.ResponseWriter, r *http.Request) {
	k := s.aiKind(w, r)
	if k == nil {
		return
	}
	p, err := s.ai().PlanInstall(k.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, p)
}

// aiInstall installs (or updates) a provider's tool in NCC's own folder, once the person has
// seen the plan and confirmed it.
func (s *Server) aiInstall(w http.ResponseWriter, r *http.Request) {
	k := s.aiKind(w, r)
	if k == nil {
		return
	}
	var in struct {
		Confirm bool `json:"confirm"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !in.Confirm {
		writeErr(w, 400, "confirm the install first")
		return
	}
	plan, err := s.ai().PlanInstall(k.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	v, err := s.aiState.installs.Start(k.ID)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "assistant.install", "ai/"+k.ID, map[string]any{
		"package": plan.Package, "location": plan.Location, "node": plan.Node,
		"download_node": plan.DownloadNode, "previous": plan.Installed, "install": v.ID})
	writeJSON(w, 200, v)
}

func (s *Server) aiInstallView(w http.ResponseWriter, r *http.Request) {
	s.ai()
	v, err := s.aiState.installs.View(r.PathValue("id"))
	if err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) aiPaste(w http.ResponseWriter, r *http.Request) {
	k := s.aiKind(w, r)
	if k == nil {
		return
	}
	var in struct {
		Value string `json:"value"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.ai().SavePasted(r.Context(), k, in.Value); err != nil {
		if errors.Is(err, vault.ErrSealed) {
			s.fail(w, err)
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "assistant.signin", "ai/"+k.ID, map[string]any{"pasted": true})
	writeJSON(w, 200, map[string]bool{"connected": true})
}

func (s *Server) aiSignOut(w http.ResponseWriter, r *http.Request) {
	k := s.aiKind(w, r)
	if k == nil {
		return
	}
	if err := s.ai().SignOut(r.Context(), k); err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "assistant.signout", "ai/"+k.ID, nil)
	w.WriteHeader(204)
}

func (s *Server) aiTest(w http.ResponseWriter, r *http.Request) {
	k := s.aiKind(w, r)
	if k == nil {
		return
	}
	start := time.Now()
	ans, err := s.ai().Ask(r.Context(), k.ID, "Reply with the single word OK.")
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if len(ans) > 200 {
		ans = ans[:200] + "…"
	}
	writeJSON(w, 200, map[string]any{"ok": true, "answer": ans, "seconds": time.Since(start).Seconds()})
}

// picture gathers the whole network for the assistant.
func (s *Server) picture(ctx context.Context) (*assistant.Picture, error) {
	ts, err := s.Targets.List(ctx, core.CategoryDevice)
	if err != nil {
		return nil, err
	}
	snaps, err := core.LatestSnapshots(ctx, s.Store.DB)
	if err != nil {
		return nil, err
	}
	in := assistant.Inputs{}
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		ri := assistant.RouterInput{ID: t.ID, Name: t.Name}
		if d, err := drivers.Get(t.Kind); err == nil {
			_, ri.CanChange = d.(drivers.NetworkWriter)
			_, ri.CanSetDomain = d.(drivers.NetworkDomainSetter)
		}
		for i := range snaps {
			if snaps[i].Target == t.Name {
				ri.Snapshot = &snaps[i]
			}
		}
		in.Routers = append(in.Routers, ri)
	}
	view, _, err := s.iotState(ctx)
	if err != nil {
		return nil, err
	}
	in.IoT = view.Devices
	in.IoTNetworks = map[string]bool{}
	for _, n := range view.Networks {
		if n.IoT {
			in.IoTNetworks[n.ID] = true
		}
	}
	dts, err := s.Targets.List(ctx, core.CategoryDNS)
	if err != nil {
		return nil, err
	}
	for _, t := range dts {
		if !t.Enabled {
			continue
		}
		ds := assistant.DNSServer{ID: t.ID, Name: t.Name, Kind: t.Kind, Zones: []string{}}
		p, err := dns.Get(t.Kind)
		if err == nil {
			_, ds.CanCreateZones = p.(dns.ZoneManager)
			var creds vault.Secret
			if creds, err = s.Vault.Get(ctx, t.SecretPath); err == nil {
				zctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				var zs []dns.Zone
				zs, err = p.ListZones(zctx, dns.Server{ID: t.ID, Name: t.Name, Kind: t.Kind, Address: t.Address, Options: t.Options}, creds)
				cancel()
				for _, z := range zs {
					ds.Zones = append(ds.Zones, z.Name)
				}
			}
		}
		if err != nil {
			ds.Error = err.Error()
		}
		in.DNS = append(in.DNS, ds)
	}
	return assistant.BuildPicture(in), nil
}

func (s *Server) aiPicture(w http.ResponseWriter, r *http.Request) {
	p, err := s.picture(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"picture": p, "size": p.Size()})
}

func (s *Server) aiMakePlan(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Provider string `json:"provider"`
		Goal     string `json:"goal"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Goal) > 2000 {
		writeErr(w, 400, "keep the goal under 2000 characters")
		return
	}
	if in.Provider != "" {
		k, err := assistant.KindByID(in.Provider)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		st, err := s.ai().Get(r.Context(), k.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		if !st.Enabled {
			writeErr(w, 409, k.Label+" is not switched on; switch it on under AI providers")
			return
		}
	}
	pic, err := s.picture(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	plan, err := s.ai().MakePlan(r.Context(), pic, in.Provider, in.Goal, actor(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), actor(r), "assistant.plan", "plan/"+plan.ID,
		map[string]any{"provider": in.Provider, "source": plan.Source, "steps": len(plan.Steps), "ai_error": plan.AIError})
	writeJSON(w, 201, plan)
}

func (s *Server) aiPlan(w http.ResponseWriter, r *http.Request) {
	p, err := s.ai().LoadPlan(r.Context(), r.PathValue("id"))
	if errors.Is(err, assistant.ErrNoPlan) {
		writeErr(w, 404, err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, p)
}

func (s *Server) aiDiscard(w http.ResponseWriter, r *http.Request) {
	p, err := s.ai().LoadPlan(r.Context(), r.PathValue("id"))
	if errors.Is(err, assistant.ErrNoPlan) {
		writeErr(w, 404, err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if p.Status != assistant.PlanProposed {
		writeErr(w, 409, "only a plan that has not been deployed can be discarded")
		return
	}
	p.Status = assistant.PlanDiscarded
	if err := s.ai().SavePlan(r.Context(), p); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, p)
}

// aiDeploy applies the steps a person picked. It needs confirm: true, so nothing is ever
// applied by the assistant on its own; the deploy runs in the background and the page follows
// it by reading the plan.
func (s *Server) aiDeploy(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Steps   []string `json:"steps"`
		Confirm bool     `json:"confirm"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !in.Confirm {
		writeErr(w, 400, "confirm the deployment first")
		return
	}
	svc := s.ai()
	p, err := svc.LoadPlan(r.Context(), r.PathValue("id"))
	if errors.Is(err, assistant.ErrNoPlan) {
		writeErr(w, 404, err.Error())
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	if p.Status != assistant.PlanProposed {
		writeErr(w, 409, "this plan was already "+p.Status+"; make a new plan")
		return
	}
	if time.Since(p.CreatedAt) > 24*time.Hour {
		writeErr(w, 409, "this plan is more than a day old and the network may have changed; make a new plan")
		return
	}
	picked := map[string]bool{}
	for _, id := range in.Steps {
		found := false
		for _, st := range p.Steps {
			if st.ID == id {
				found = true
				if st.Problem != "" {
					writeErr(w, 400, "step "+id+" can't be applied: "+st.Problem)
					return
				}
			}
		}
		if !found {
			writeErr(w, 400, "the plan has no step "+id)
			return
		}
		picked[id] = true
	}
	if len(picked) == 0 {
		writeErr(w, 400, "pick at least one step")
		return
	}
	s.aiState.deploying.Lock()
	if s.aiState.busy {
		s.aiState.deploying.Unlock()
		writeErr(w, 409, "another plan is being deployed; wait for it to finish")
		return
	}
	s.aiState.busy = true
	s.aiState.deploying.Unlock()

	who := actor(r)
	now := time.Now().UTC()
	p.Status, p.DeployedBy, p.DeployedAt = assistant.PlanDeploying, who, &now
	if err := svc.SavePlan(r.Context(), p); err != nil {
		s.aiState.deploying.Lock()
		s.aiState.busy = false
		s.aiState.deploying.Unlock()
		s.fail(w, err)
		return
	}
	_ = s.Audit.Record(r.Context(), who, "assistant.deploy", "plan/"+p.ID, map[string]any{"steps": in.Steps})
	go func() {
		defer func() {
			s.aiState.deploying.Lock()
			s.aiState.busy = false
			s.aiState.deploying.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		env := &aiEnv{s: s, actor: who}
		assistant.Deploy(ctx, env, p, picked, func(p *assistant.Plan) {
			if p.Status == assistant.PlanDeploying || p.Status == assistant.PlanProposed {
				p.Status = assistant.PlanDeploying
			}
			_ = svc.SavePlan(context.Background(), p)
		})
		_ = svc.SavePlan(context.Background(), p)
		res := map[string]any{"status": p.Status}
		for _, st := range p.Steps {
			if st.Result != nil {
				res[st.ID] = st.Result.State + ": " + st.Result.Message
			}
		}
		_ = s.Audit.Record(context.Background(), who, "assistant.deployed", "plan/"+p.ID, res)
		s.Hub.Publish("assistant", map[string]any{"plan": p.ID, "status": p.Status})
	}()
	writeJSON(w, 202, p)
}

// aiEnv deploys plan steps with the same code paths as the VLANs and DNS pages.
type aiEnv struct {
	s     *Server
	actor string
}

func (e *aiEnv) router(ctx context.Context, id int64) (*core.Target, drivers.NetworkWriter, vault.Secret, error) {
	t, err := e.s.Targets.Get(ctx, id)
	if err != nil {
		return nil, nil, nil, err
	}
	if t.Category != core.CategoryDevice || !t.Enabled {
		return nil, nil, nil, fmt.Errorf("%s is not an enabled router connection", t.Name)
	}
	d, err := drivers.Get(t.Kind)
	if err != nil {
		return nil, nil, nil, err
	}
	nw, ok := d.(drivers.NetworkWriter)
	if !ok {
		return nil, nil, nil, fmt.Errorf("%s connections cannot change networks", t.Kind)
	}
	creds, err := e.s.Vault.Get(ctx, t.SecretPath)
	if err != nil {
		return nil, nil, nil, err
	}
	return t, nw, creds, nil
}

// fresh polls a router again and returns its new snapshot.
func (e *aiEnv) fresh(ctx context.Context, t *core.Target) error {
	for i := 0; i < 10; i++ {
		_, err := e.s.Poller.PollOne(ctx, t.ID)
		if err == nil {
			return nil
		}
		if err.Error() != "poll already running" {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("could not re-read " + t.Name)
}

func (e *aiEnv) CreateNetwork(ctx context.Context, routerID int64, spec drivers.NetworkSpec) (string, error) {
	t, nw, creds, err := e.router(ctx, routerID)
	if err != nil {
		return "", err
	}
	if err := e.fresh(ctx, t); err != nil {
		return "", err
	}
	snap, err := e.s.snapshotFor(ctx, t)
	if err != nil {
		return "", err
	}
	if snap == nil {
		return "", errors.New("NCC has not read " + t.Name + " yet")
	}
	if err := core.ValidateNetwork(&spec, snap.Networks); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	id, err := nw.CreateNetwork(cctx, devTarget(t), creds, spec)
	_ = e.s.Audit.Record(ctx, e.actor, "vlan.create", "network/"+t.Name+"/"+spec.Name,
		map[string]any{"spec": spec, "id": id, "result": errText(err), "via": "assistant"})
	return id, err
}

func (e *aiEnv) FindNetwork(ctx context.Context, routerID int64, name string) (string, error) {
	t, err := e.s.Targets.Get(ctx, routerID)
	if err != nil {
		return "", err
	}
	if err := e.fresh(ctx, t); err != nil {
		return "", err
	}
	snap, err := e.s.snapshotFor(ctx, t)
	if err != nil || snap == nil {
		return "", err
	}
	for _, n := range snap.Networks {
		if strings.EqualFold(n.Name, name) {
			return n.ID, nil
		}
	}
	return "", nil
}

func (e *aiEnv) MoveClients(ctx context.Context, routerID int64, networkID string, macs []string) (string, error) {
	t, nw, creds, err := e.router(ctx, routerID)
	if err != nil {
		return "", err
	}
	snap, err := e.s.snapshotFor(ctx, t)
	if err != nil {
		return "", err
	}
	if snap == nil {
		return "", errors.New("NCC has not read " + t.Name + " yet")
	}
	plan, err := core.PlanMove(snap, networkID, macs)
	if err != nil {
		return "", err
	}
	moves := plan.Moves()
	if len(moves) == 0 {
		return "Nothing to move: the devices are already there or can't be moved", nil
	}
	mctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	results, err := nw.MoveClients(mctx, devTarget(t), creds, plan.Network.ID, moves, true)
	okN, failed := 0, []string{}
	for _, res := range results {
		detail := map[string]any{"network": plan.Network.Name, "vlan": plan.Network.VLAN, "result": "ok", "via": "assistant"}
		for _, st := range plan.Steps {
			if st.MAC == res.MAC {
				detail["from"], detail["method"] = st.FromName, st.Method
			}
		}
		if res.OK {
			okN++
		} else {
			detail["result"] = "failed: " + res.Error
			failed = append(failed, res.Name+" ("+res.Error+")")
		}
		_ = e.s.Audit.Record(ctx, e.actor, "vlan.move", "client/"+t.Name+"/"+res.Name+" ("+res.MAC+")", detail)
	}
	e.s.refreshTarget(t.ID, 3*time.Second, 15*time.Second)
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Moved %d device%s to %s", okN, map[bool]string{true: "", false: "s"}[okN == 1], plan.Network.Name)
	if len(failed) > 0 {
		return "", fmt.Errorf("%s; failed: %s", msg, strings.Join(failed, ", "))
	}
	return msg, nil
}

// zonePlan builds and applies a plan with the DNS page's zone planner (internal/dnszones), so
// the assistant's zones get the same delegations, checks and audit records as zones made there.
func (e *aiEnv) zonePlan(ctx context.Context, req dnszones.PlanRequest) error {
	env := zonesEnv{e.s}
	plan, err := dnszones.BuildPlan(ctx, env, req)
	if err != nil {
		return err
	}
	if len(plan.Steps) == 0 {
		return nil
	}
	actx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	routers := map[int64]bool{}
	_, err = dnszones.Apply(actx, env, e.s.Store.DB, e.actor, plan, func(res dnszones.StepResult) {
		action := "dnszone." + res.Kind
		if !res.OK {
			action += ".failed"
		}
		target := "dns/" + res.Server + "/" + res.Zone
		if res.Kind == dnszones.StepDHCPDomain {
			target = "network/" + res.Router + "/" + res.Network
			routers[res.RouterID] = true
		}
		_ = e.s.Audit.Record(ctx, e.actor, action, target, map[string]any{"step": res.Step, "error": res.Error, "via": "assistant"})
	})
	for id := range routers {
		e.s.refreshTarget(id, 0)
	}
	e.s.Hub.Publish("dns", map[string]any{"via": "assistant"})
	return err
}

// CreateZone creates a zone, delegated from its parent zone when the server has one.
func (e *aiEnv) CreateZone(ctx context.Context, serverID int64, zone string) error {
	return e.zonePlan(ctx, dnszones.PlanRequest{ServerID: serverID,
		Zones: []dnszones.NewZone{{Name: dns.FQDN(zone), ServerID: serverID, Delegate: true}}})
}

// AssignZone assigns a zone to a VLAN and makes the router hand it out as the network's DHCP
// domain. The zone's DNS server is the one that holds it.
func (e *aiEnv) AssignZone(ctx context.Context, routerID int64, networkID, zone string) error {
	zone = dns.FQDN(zone)
	servers, err := e.s.Targets.List(ctx, core.CategoryDNS)
	if err != nil {
		return err
	}
	var serverID int64
	for _, t := range servers {
		if !t.Enabled {
			continue
		}
		p, srv, creds, err := zonesEnv{e.s}.DNSServer(ctx, t.ID)
		if err != nil {
			continue
		}
		zs, err := p.ListZones(ctx, srv, creds)
		if err != nil {
			continue
		}
		for _, z := range zs {
			if dns.FQDN(z.Name) == zone {
				serverID = t.ID
			}
		}
		if serverID != 0 {
			break
		}
	}
	if serverID == 0 {
		return errors.New("no DNS server has the zone " + strings.TrimSuffix(zone, "."))
	}
	return e.zonePlan(ctx, dnszones.PlanRequest{ServerID: serverID,
		Assign: []dnszones.AssignSpec{{Zone: zone, ServerID: serverID, RouterID: routerID, NetworkID: networkID, SetDHCPDomain: true}}})
}
