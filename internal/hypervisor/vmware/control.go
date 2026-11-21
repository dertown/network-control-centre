package vmware

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"

	hv "github.com/dertown/network-control-centre/internal/hypervisor"
)

// Write access needs a role with Virtual machine > Interaction (power), Configuration
// (settings) and Inventory > Remove (delete); the Read-only role cannot change anything.

func findVM(ctx context.Context, c *conn, vmID string) (*object.VirtualMachine, *mo.VirtualMachine, error) {
	ref := vmID[strings.LastIndex(vmID, "/")+1:]
	if ref == "" {
		return nil, nil, fmt.Errorf("vmware: bad VM id %q", vmID)
	}
	vm := object.NewVirtualMachine(c.vc, types.ManagedObjectReference{Type: "VirtualMachine", Value: ref})
	var m mo.VirtualMachine
	if err := vm.Properties(ctx, vm.Reference(), []string{"summary.runtime.powerState", "summary.config.template", "summary.guest.toolsRunningStatus"}, &m); err != nil {
		return nil, nil, fmt.Errorf("vmware: that machine no longer exists (%w)", err)
	}
	return vm, &m, nil
}

func permErr(err error) error {
	if soap.IsSoapFault(err) {
		if _, ok := soap.ToSoapFault(err).VimFault().(types.NoPermission); ok {
			return fmt.Errorf("vmware: permission denied. The NCC user needs a role that can change VMs (for example Virtual Machine Power User or Administrator), not Read-only: %w", err)
		}
		if _, ok := soap.ToSoapFault(err).VimFault().(*types.NoPermission); ok {
			return fmt.Errorf("vmware: permission denied. The NCC user needs a role that can change VMs (for example Virtual Machine Power User or Administrator), not Read-only: %w", err)
		}
	}
	return fmt.Errorf("vmware: %w", err)
}

func run(ctx context.Context, task *object.Task, err error) error {
	if err != nil {
		return permErr(err)
	}
	if err := task.Wait(ctx); err != nil {
		return permErr(err)
	}
	return nil
}

// Power implements hypervisor.Controller.
func (Provider) Power(ctx context.Context, t hv.Target, creds map[string]string, vmID, action string) error {
	if !hv.ValidAction(action) {
		return fmt.Errorf("unknown action %q", action)
	}
	c, err := connect(ctx, t, creds)
	if err != nil {
		return err
	}
	defer c.Close()
	vm, m, err := findVM(ctx, c, vmID)
	if err != nil {
		return err
	}
	if m.Summary.Config.Template {
		return errors.New("vmware: templates cannot be powered on")
	}
	state := m.Summary.Runtime.PowerState
	tools := m.Summary.Guest != nil && m.Summary.Guest.ToolsRunningStatus == string(types.VirtualMachineToolsRunningStatusGuestToolsRunning)
	switch action {
	case hv.ActionStart:
		if state == types.VirtualMachinePowerStatePoweredOn {
			return nil
		}
		task, err := vm.PowerOn(ctx)
		return run(ctx, task, err)
	case hv.ActionStop:
		if state == types.VirtualMachinePowerStatePoweredOff {
			return nil
		}
		task, err := vm.PowerOff(ctx)
		return run(ctx, task, err)
	case hv.ActionShutdown:
		if !tools {
			return errors.New("vmware: VMware Tools is not running in this machine, so it can't be asked to shut down. Use Power off instead")
		}
		if err := vm.ShutdownGuest(ctx); err != nil {
			return permErr(err)
		}
	case hv.ActionReboot:
		if !tools {
			task, err := vm.Reset(ctx) // hard reset without guest tools
			return run(ctx, task, err)
		}
		if err := vm.RebootGuest(ctx); err != nil {
			return permErr(err)
		}
	}
	return nil
}

// Configure implements hypervisor.Controller.
func (Provider) Configure(ctx context.Context, t hv.Target, creds map[string]string, vmID string, s hv.Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	c, err := connect(ctx, t, creds)
	if err != nil {
		return err
	}
	defer c.Close()
	vm, _, err := findVM(ctx, c, vmID)
	if err != nil {
		return err
	}
	spec := types.VirtualMachineConfigSpec{}
	if s.Name != nil {
		spec.Name = *s.Name
	}
	if s.CPUs != nil {
		spec.NumCPUs = int32(*s.CPUs)
	}
	if s.MemoryMB != nil {
		spec.MemoryMB = int64(*s.MemoryMB)
	}
	if s.Notes != nil {
		spec.Annotation = *s.Notes
		if *s.Notes == "" {
			spec.Annotation = " " // an empty string means "no change"
		}
	}
	task, err := vm.Reconfigure(ctx, spec)
	if err := run(ctx, task, err); err != nil {
		if strings.Contains(err.Error(), "hot") || strings.Contains(err.Error(), "InvalidPowerState") {
			return fmt.Errorf("%w. Changing CPU or memory while the machine runs needs CPU/memory hot-add; shut it down first", err)
		}
		return err
	}
	return nil
}

// Delete implements hypervisor.Controller.
func (Provider) Delete(ctx context.Context, t hv.Target, creds map[string]string, vmID string) error {
	c, err := connect(ctx, t, creds)
	if err != nil {
		return err
	}
	defer c.Close()
	vm, m, err := findVM(ctx, c, vmID)
	if err != nil {
		return err
	}
	if m.Summary.Runtime.PowerState != types.VirtualMachinePowerStatePoweredOff {
		return errors.New("vmware: power the machine off before deleting it")
	}
	task, err := vm.Destroy(ctx)
	return run(ctx, task, err)
}
