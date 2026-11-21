package proxmox

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
)

// Write access: power actions need VM.PowerMgmt, settings need VM.Config.* and
// deleting needs VM.Allocate. A token with privilege separation off inherits its user's rights.

func (c *client) open(ctx context.Context, creds map[string]string) error {
	if c.token == "" {
		return c.login(ctx, creds["username"], creds["password"])
	}
	return nil
}

// locate finds a VM's current node and state from its NCC id "<target>/<qemu|lxc>/<vmid>".
func (c *client) locate(ctx context.Context, vmID string) (*resource, error) {
	parts := strings.Split(vmID, "/")
	if len(parts) < 3 {
		return nil, fmt.Errorf("proxmox: bad VM id %q", vmID)
	}
	typ, id := parts[len(parts)-2], parts[len(parts)-1]
	if typ != "qemu" && typ != "lxc" {
		return nil, fmt.Errorf("proxmox: bad VM id %q", vmID)
	}
	var rs []resource
	if err := c.get(ctx, "/cluster/resources?type=vm", &rs); err != nil {
		return nil, err
	}
	for i := range rs {
		if rs[i].Type == typ && strconv.FormatInt(int64(rs[i].VMID), 10) == id {
			return &rs[i], nil
		}
	}
	return nil, fmt.Errorf("proxmox: %s %s no longer exists", typ, id)
}

func base(r *resource) string {
	return fmt.Sprintf("/nodes/%s/%s/%d", url.PathEscape(r.Node), r.Type, int64(r.VMID))
}

// wait follows a Proxmox task (UPID) for a while and returns its failure, if any.
// A task still running after the wait is left to finish on its own.
func (c *client) wait(ctx context.Context, node, upid string, limit time.Duration) error {
	if upid == "" {
		return nil
	}
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		var st struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		if err := c.get(ctx, "/nodes/"+url.PathEscape(node)+"/tasks/"+url.PathEscape(upid)+"/status", &st); err != nil {
			return nil // can't follow it (e.g. no Sys.Audit); the request itself was accepted
		}
		if st.Status == "stopped" {
			if st.ExitStatus != "" && st.ExitStatus != "OK" && !strings.HasPrefix(st.ExitStatus, "WARNINGS") {
				return fmt.Errorf("proxmox: %s", st.ExitStatus)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(400 * time.Millisecond):
		}
	}
	return nil
}

func writeErr(err error) error {
	if is403(err) {
		return fmt.Errorf("%w. The NCC token needs write rights for this: for example the PVEVMAdmin role, or turn privilege separation off for a token of an admin user", err)
	}
	return err
}

// Power implements hypervisor.Controller.
func (Provider) Power(ctx context.Context, t hv.Target, creds map[string]string, vmID, action string) error {
	if !hv.ValidAction(action) {
		return fmt.Errorf("unknown action %q", action)
	}
	c, err := newClient(t, creds)
	if err != nil {
		return err
	}
	if err := c.open(ctx, creds); err != nil {
		return err
	}
	r, err := c.locate(ctx, vmID)
	if err != nil {
		return err
	}
	if r.Template != 0 {
		return errors.New("proxmox: templates cannot be started")
	}
	var upid string
	if err := c.do(ctx, "POST", base(r)+"/status/"+action, url.Values{}, &upid); err != nil {
		return writeErr(err)
	}
	return c.wait(ctx, r.Node, upid, 20*time.Second)
}

// Configure implements hypervisor.Controller.
func (Provider) Configure(ctx context.Context, t hv.Target, creds map[string]string, vmID string, s hv.Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c, err := newClient(t, creds)
	if err != nil {
		return err
	}
	if err := c.open(ctx, creds); err != nil {
		return err
	}
	r, err := c.locate(ctx, vmID)
	if err != nil {
		return err
	}
	form := url.Values{}
	if s.Name != nil {
		if r.Type == "lxc" {
			form.Set("hostname", *s.Name)
		} else {
			form.Set("name", *s.Name)
		}
	}
	if s.MemoryMB != nil {
		form.Set("memory", strconv.Itoa(*s.MemoryMB))
	}
	if s.Notes != nil {
		if *s.Notes == "" {
			form.Add("delete", "description")
		} else {
			form.Set("description", *s.Notes)
		}
	}
	if s.CPUs != nil {
		if r.Type == "lxc" {
			form.Set("cores", strconv.Itoa(*s.CPUs))
		} else {
			// vCPUs are sockets × cores; keep the socket count when it divides evenly
			var cfg struct {
				Sockets num `json:"sockets"`
			}
			_ = c.get(ctx, base(r)+"/config", &cfg)
			sockets := int(cfg.Sockets)
			if sockets < 1 || *s.CPUs%sockets != 0 {
				sockets = 1
			}
			form.Set("sockets", strconv.Itoa(sockets))
			form.Set("cores", strconv.Itoa(*s.CPUs/sockets))
		}
	}
	method := "PUT"
	if r.Type == "qemu" {
		method = "POST" // async on QEMU, returns a task id
	}
	var upid string
	if err := c.do(ctx, method, base(r)+"/config", form, &upid); err != nil {
		return writeErr(err)
	}
	return c.wait(ctx, r.Node, upid, 20*time.Second)
}

// Delete implements hypervisor.Controller.
func (Provider) Delete(ctx context.Context, t hv.Target, creds map[string]string, vmID string) error {
	c, err := newClient(t, creds)
	if err != nil {
		return err
	}
	if err := c.open(ctx, creds); err != nil {
		return err
	}
	r, err := c.locate(ctx, vmID)
	if err != nil {
		return err
	}
	if r.Status != "stopped" {
		return errors.New("proxmox: stop the machine before deleting it")
	}
	var upid string
	if err := c.do(ctx, "DELETE", base(r), url.Values{"purge": {"1"}, "destroy-unreferenced-disks": {"1"}}, &upid); err != nil {
		return writeErr(err)
	}
	return c.wait(ctx, r.Node, upid, 60*time.Second)
}
