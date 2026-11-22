package assistant

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/drivers"
)

// MakePlan builds a plan: NCC's rules first, then (with a provider) the model's improvement
// on them. A model answer that can't be used falls back to the rules, saying why.
func (s *Service) MakePlan(ctx context.Context, p *Picture, provider, goal, by string) (*Plan, error) {
	base := Baseline(p)
	plan := &Plan{ID: newID(), CreatedAt: time.Now().UTC(), CreatedBy: by, Provider: provider, Goal: strings.TrimSpace(goal),
		Status: PlanProposed, Source: "rules", Notes: []string{}}
	ans := base
	if provider != "" {
		st, err := s.Get(ctx, provider)
		if err != nil {
			return nil, err
		}
		k, _ := KindByID(provider)
		plan.Model = firstOf(st.Model, k.DefaultModel)
		prompt, err := Prompt(p, base, goal)
		if err != nil {
			return nil, err
		}
		text, err := s.Ask(ctx, provider, prompt)
		if err == nil {
			var a Answer
			if a, err = ParseAnswer(text); err == nil {
				if steps, _ := Check(p, a); len(steps) == 0 && len(a.Steps) > 0 {
					err = errors.New("none of the model's steps matched the network")
				} else {
					ans = a
					plan.Source = "ai"
				}
			}
		}
		if err != nil {
			plan.AIError = err.Error()
		}
	}
	plan.Summary = strings.TrimSpace(ans.Summary)
	steps, notes := Check(p, ans)
	plan.Steps = steps
	if plan.Steps == nil {
		plan.Steps = []Step{}
	}
	for _, n := range ans.Notes {
		if n = strings.TrimSpace(n); n != "" {
			plan.Notes = append(plan.Notes, n)
		}
	}
	plan.Notes = append(plan.Notes, notes...)
	if plan.Summary == "" {
		plan.Summary = base.Summary
	}
	if err := s.SavePlan(ctx, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// SavePlan stores a plan.
func (s *Service) SavePlan(ctx context.Context, p *Plan) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `INSERT INTO ai_plans(id, created_at, status, data) VALUES(?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET status = excluded.status, data = excluded.data`, p.ID, p.CreatedAt, p.Status, string(b))
	return err
}

// ErrNoPlan is returned for an unknown plan.
var ErrNoPlan = errors.New("no such plan")

// LoadPlan reads a plan.
func (s *Service) LoadPlan(ctx context.Context, id string) (*Plan, error) {
	var d string
	err := s.DB.QueryRowContext(ctx, `SELECT data FROM ai_plans WHERE id = ?`, id).Scan(&d)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoPlan
	}
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal([]byte(d), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Plans lists the newest plans.
func (s *Service) Plans(ctx context.Context, limit int) ([]Plan, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT data FROM ai_plans ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Plan{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		var p Plan
		if json.Unmarshal([]byte(d), &p) == nil {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

// Env is what deploying needs from the rest of NCC. The API server implements it with the
// same code (and audit records) as the VLANs and DNS pages.
type Env interface {
	// CreateNetwork creates a VLAN network on a router and returns its id.
	CreateNetwork(ctx context.Context, routerID int64, spec drivers.NetworkSpec) (string, error)
	// FindNetwork re-reads a router and returns the id of the network with this name, or "".
	FindNetwork(ctx context.Context, routerID int64, name string) (string, error)
	// MoveClients moves clients to a network (previewed again from a fresh read first) and
	// says how it went in a sentence.
	MoveClients(ctx context.Context, routerID int64, networkID string, macs []string) (string, error)
	// CreateZone creates a DNS zone on a DNS server.
	CreateZone(ctx context.Context, serverID int64, zone string) error
	// AssignZone makes a router network hand out zone as its DNS domain.
	AssignZone(ctx context.Context, routerID int64, networkID, zone string) error
}

// Deploy applies the picked steps of a plan in order, recording each step's result. A step
// that needs a network an earlier step failed to create is skipped. progress is called after
// every step with the plan as it stands.
func Deploy(ctx context.Context, env Env, p *Plan, picked map[string]bool, progress func(*Plan)) {
	created := map[string]string{} // "new:<name>" -> real id
	failedNet := map[string]bool{}
	ok, bad := 0, 0
	for i := range p.Steps {
		st := &p.Steps[i]
		if !picked[st.ID] {
			continue
		}
		res := &Result{State: "ok", At: time.Now().UTC()}
		netID := st.NetworkID
		if strings.HasPrefix(netID, "new:") {
			if id, ok := created[netID]; ok {
				netID = id
			} else if failedNet[netID] {
				res.State, res.Message = "skipped", "the "+st.NetworkName+" network was not created"
			} else {
				// created by an earlier deploy, or by hand since the plan was made
				id, err := env.FindNetwork(ctx, st.RouterID, st.NetworkName)
				if err == nil && id != "" {
					netID, created[st.NetworkID] = id, id
				} else if st.Kind != StepCreateVLAN {
					res.State, res.Message = "skipped", "the "+st.NetworkName+" network does not exist; pick the step that creates it"
				}
			}
		}
		if res.State == "ok" {
			var err error
			switch st.Kind {
			case StepCreateVLAN:
				if id, done := created[st.NetworkID]; done {
					res.Message = st.NetworkName + " already exists (" + id + "); nothing to create"
					break
				}
				var id string
				id, err = env.CreateNetwork(ctx, st.RouterID, *st.Network)
				if err == nil {
					// the router may report the new network only after a refresh
					if fid, ferr := env.FindNetwork(ctx, st.RouterID, st.Network.Name); ferr == nil && fid != "" {
						id = fid
					}
					created[st.NetworkID] = id
					res.Message = fmt.Sprintf("Created %s (VLAN %d, %s)", st.Network.Name, st.Network.VLAN, st.Network.Gateway)
				}
			case StepMove:
				var macs []string
				for _, c := range st.Clients {
					if c.Blocked == "" && !c.AlongWith {
						macs = append(macs, c.MAC)
					}
				}
				res.Message, err = env.MoveClients(ctx, st.RouterID, netID, macs)
			case StepCreateZone:
				err = env.CreateZone(ctx, st.DNSServerID, st.Zone)
				if err == nil {
					res.Message = "Created " + strings.TrimSuffix(st.Zone, ".")
				}
			case StepAssignZone:
				err = env.AssignZone(ctx, st.RouterID, netID, st.Zone)
				if err == nil {
					res.Message = st.NetworkName + " now hands out " + strings.TrimSuffix(st.Zone, ".")
				}
			default:
				err = fmt.Errorf("unknown step kind %q", st.Kind)
			}
			if err != nil {
				res.State, res.Message = "failed", err.Error()
				if st.Kind == StepCreateVLAN {
					failedNet[st.NetworkID] = true
				}
			}
		}
		if res.State == "ok" {
			ok++
		} else {
			bad++
		}
		st.Result = res
		if progress != nil {
			progress(p)
		}
	}
	switch {
	case bad == 0:
		p.Status = PlanDeployed
	case ok == 0:
		p.Status = PlanFailed
	default:
		p.Status = PlanPartial
	}
	now := time.Now().UTC()
	p.DeployedAt = &now
	if progress != nil {
		progress(p)
	}
}
