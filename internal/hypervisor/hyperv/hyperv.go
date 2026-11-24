// Package hyperv implements the NCC virtualization provider for Microsoft Hyper-V hosts, using
// the Hyper-V PowerShell module over WinRM: VMs with state, vCPUs, memory, disks, guest
// addresses (from integration services) and uptime, the host's load, and power, settings and
// delete actions.
package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dertown/network-control-centre/internal/catalog"
	hv "github.com/dertown/network-control-centre/internal/hypervisor"
	"github.com/dertown/network-control-centre/internal/winps"
)

func init() {
	hv.Register(Provider{}, catalog.Vendor{
		Label: "Microsoft Hyper-V", Groups: []string{catalog.GroupVirtualization}, Order: 30,
		Summary: "Hyper-V on Windows Server or Azure Local: VMs, host load and power actions, over WinRM.",
		Help: "Use the Hyper-V host's name and an account in its Hyper-V Administrators group (to only read, Hyper-V Administrators " +
			"is still needed: Hyper-V has no read-only role). Add each clustered host separately. Guest addresses need the guest's " +
			"integration services. " + winps.Help,
		NameDefault: "hyperv", AddressKind: catalog.AddressHost, AddressDefault: "hv01.corp.example", AddressLabel: "Host (name or address)",
		Fields: winps.Fields(`CORP\ncc-hyperv`),
	})
}

// Provider implements hypervisor.Provider and hypervisor.Controller for Hyper-V.
type Provider struct{}

// Kind implements hypervisor.Provider.
func (Provider) Kind() string { return "hyperv" }

const collectScript = `$h=Get-VMHost
$os=Get-CimInstance Win32_OperatingSystem
$cs=Get-CimInstance Win32_ComputerSystem
$load=(Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$vms=@(Get-VM | ForEach-Object {
$disk=0;$used=0
foreach($d in @(Get-VMHardDiskDrive -VM $_)){ try{ $v=Get-VHD -Path $d.Path; $disk+=$v.Size; $used+=$v.FileSize }catch{} }
[pscustomobject]@{id=[string]$_.VMId;n=$_.Name;s=[string]$_.State;c=$_.ProcessorCount;cpu=$_.CPUUsage;mem=$_.MemoryStartup;used=$_.MemoryAssigned;up=[int64]$_.Uptime.TotalSeconds;notes=$_.Notes;ip=@($_.NetworkAdapters | ForEach-Object { $_.IPAddresses });disk=$disk;du=$used;ic=[string]$_.IntegrationServicesState}})
ConvertTo-Json -Compress -Depth 4 -InputObject ([pscustomobject]@{host=$h.ComputerName;cpus=$h.LogicalProcessorCount;mem=$h.MemoryCapacity;free=[int64]$os.FreePhysicalMemory*1024;load=$load;up=[int64]((Get-Date)-$os.LastBootUpTime).TotalSeconds;ver=($os.Caption+' '+$os.Version);model=($cs.Manufacturer+' '+$cs.Model);vms=$vms})`

type hostOut struct {
	Host  string  `json:"host"`
	CPUs  int     `json:"cpus"`
	Mem   int64   `json:"mem"`
	Free  int64   `json:"free"`
	Load  float64 `json:"load"`
	Up    int64   `json:"up"`
	Ver   string  `json:"ver"`
	Model string  `json:"model"`
	VMs   []vmOut `json:"vms"`
}

type vmOut struct {
	ID    string   `json:"id"`
	Name  string   `json:"n"`
	State string   `json:"s"`
	CPUs  int      `json:"c"`
	CPU   float64  `json:"cpu"` // percent of the VM's vCPUs
	Mem   int64    `json:"mem"`
	Used  int64    `json:"used"`
	Up    int64    `json:"up"`
	Notes string   `json:"notes"`
	IPs   []string `json:"ip"`
	Disk  int64    `json:"disk"`
	DU    int64    `json:"du"`
	IC    string   `json:"ic"`
}

func state(s string) string {
	switch s {
	case "Running":
		return hv.StateRunning
	case "Off":
		return hv.StateStopped
	case "Saved", "Paused":
		return hv.StateSuspended
	}
	return hv.StateUnknown
}

// toInventory turns the host's answer into NCC's inventory.
func toInventory(t hv.Target, h hostOut) *hv.Inventory {
	inv := &hv.Inventory{Target: t.Name, Platform: "hyperv", TakenAt: time.Now().UTC(), Version: h.Ver}
	inv.Hosts = []hv.Host{{Name: h.Host, Online: true, CPUs: h.CPUs, CPUUsage: h.Load / 100, MemBytes: h.Mem, MemUsed: h.Mem - h.Free,
		UptimeS: h.Up, Version: h.Ver, Model: strings.TrimSpace(h.Model), Target: t.Name, Platform: "hyperv"}}
	for _, v := range h.VMs {
		var ips []string
		for _, ip := range v.IPs {
			if ip != "" && !strings.HasPrefix(strings.ToLower(ip), "fe80:") {
				ips = append(ips, ip)
			}
		}
		inv.VMs = append(inv.VMs, hv.VM{
			ID: "hyperv/" + v.ID, Name: v.Name, Type: "vm", State: state(v.State), Host: h.Host,
			CPUs: v.CPUs, CPUUsage: v.CPU / 100, MemBytes: v.Mem, MemUsed: v.Used, DiskBytes: v.Disk, DiskUsed: v.DU,
			IPs: ips, UptimeS: v.Up, Notes: v.Notes, GuestTools: v.IC, Target: t.Name, Platform: "hyperv",
		})
	}
	return inv
}

// Collect implements hypervisor.Provider.
func (Provider) Collect(ctx context.Context, t hv.Target, creds map[string]string) (*hv.Result, error) {
	sh, err := winps.Dial(ctx, t.Address, t.Options, creds)
	if err != nil {
		return nil, fmt.Errorf("hyper-v: %w", err)
	}
	defer sh.Close()
	raw, err := sh.Run(ctx, collectScript)
	if err != nil {
		return nil, explain(fmt.Errorf("hyper-v: %w", err))
	}
	var h hostOut
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &h); err != nil {
		return nil, fmt.Errorf("hyper-v: unexpected answer from PowerShell: %w", err)
	}
	return &hv.Result{Inventory: toInventory(t, h)}, nil
}

// vmRef is the PowerShell that finds one VM by the id Collect reported.
func vmRef(vmID string) (string, error) {
	id := strings.TrimPrefix(vmID, "hyperv/")
	if len(id) != 36 || strings.Trim(id, "0123456789abcdefABCDEF-") != "" {
		return "", fmt.Errorf("hyper-v: %q is not a Hyper-V VM id", vmID)
	}
	return "$vm=Get-VM -Id " + winps.Quote(id) + "\n", nil
}

func run(ctx context.Context, t hv.Target, creds map[string]string, script string) error {
	sh, err := winps.Dial(ctx, t.Address, t.Options, creds)
	if err != nil {
		return fmt.Errorf("hyper-v: %w", err)
	}
	defer sh.Close()
	if _, err := sh.Run(ctx, script); err != nil {
		return fmt.Errorf("hyper-v: %w", err)
	}
	return nil
}

// Power implements hypervisor.Controller.
func (Provider) Power(ctx context.Context, t hv.Target, creds map[string]string, vmID, action string) error {
	ref, err := vmRef(vmID)
	if err != nil {
		return err
	}
	cmd := map[string]string{
		hv.ActionStart: "Start-VM -VM $vm", hv.ActionShutdown: "Stop-VM -VM $vm -Force",
		hv.ActionStop: "Stop-VM -VM $vm -TurnOff -Force", hv.ActionReboot: "Restart-VM -VM $vm -Force",
	}[action]
	if cmd == "" {
		return fmt.Errorf("hyper-v: unknown action %q", action)
	}
	return run(ctx, t, creds, ref+cmd)
}

// Configure implements hypervisor.Controller. vCPUs and startup memory can only change while
// the VM is off; Hyper-V says so itself if it isn't.
func (Provider) Configure(ctx context.Context, t hv.Target, creds map[string]string, vmID string, s hv.Settings) error {
	ref, err := vmRef(vmID)
	if err != nil {
		return err
	}
	if err := s.Validate(); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(ref)
	if s.CPUs != nil {
		fmt.Fprintf(&b, "Set-VMProcessor -VM $vm -Count %d\n", *s.CPUs)
	}
	if s.MemoryMB != nil {
		fmt.Fprintf(&b, "Set-VMMemory -VM $vm -StartupBytes %dMB\n", *s.MemoryMB)
	}
	if s.Notes != nil {
		b.WriteString("Set-VM -VM $vm -Notes " + winps.Quote(*s.Notes) + "\n")
	}
	if s.Name != nil {
		b.WriteString("Rename-VM -VM $vm -NewName " + winps.Quote(*s.Name) + "\n")
	}
	return run(ctx, t, creds, b.String())
}

// Delete implements hypervisor.Controller: removes a stopped VM and then its virtual disks.
func (Provider) Delete(ctx context.Context, t hv.Target, creds map[string]string, vmID string) error {
	ref, err := vmRef(vmID)
	if err != nil {
		return err
	}
	return run(ctx, t, creds, ref+`if($vm.State -ne 'Off'){ throw 'Turn the VM off first' }
$disks=@(Get-VMHardDiskDrive -VM $vm | ForEach-Object { $_.Path })
Remove-VM -VM $vm -Force
foreach($p in $disks){ if($p -and (Test-Path -LiteralPath $p)){ Remove-Item -LiteralPath $p -Force } }`)
}

var _ hv.Controller = Provider{}

// errNotHyperV is returned when the host has no Hyper-V module.
var errNotHyperV = errors.New("hyper-v: the Hyper-V PowerShell module is not installed on this host")

// explain turns PowerShell's "not recognized" into a plain reason.
func explain(err error) error {
	if err != nil && strings.Contains(err.Error(), "Get-VMHost") && strings.Contains(err.Error(), "not recognized") {
		return errNotHyperV
	}
	return err
}
