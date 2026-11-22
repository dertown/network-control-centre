// Package smarthome defines NCC's smart home (IoT) interface and the inventory it keeps:
// the hub, its areas (rooms), devices and their entities (lights, switches, plugs,
// thermostats, locks, sensors...), with the controls NCC allows on each.
//
// NCC does not talk to Google Home or Alexa directly: neither offers an open API for
// controlling devices from another app. It talks to a Home Assistant server instead, which
// controls Matter devices (shared from Google Home or Alexa with a pairing code), Google
// Nest and Cast devices, Alexa devices, Zigbee, Hue, TP-Link and many more.
package smarthome

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hub is the smart home server NCC talks to.
type Hub struct {
	Name     string   `json:"name"`    // the home's name in Home Assistant
	Version  string   `json:"version"` // Home Assistant version
	Matter   bool     `json:"matter"`  // the Matter integration is set up, so devices can be paired
	Nest     bool     `json:"nest"`    // the Google Nest (Device Access) integration is set up
	Cast     bool     `json:"cast"`    // Google Cast (Nest speakers and displays, Chromecast)
	Alexa    bool     `json:"alexa"`   // the Alexa Devices integration is set up
	TimeZone string   `json:"time_zone,omitempty"`
	Unit     string   `json:"unit,omitempty"` // temperature unit: °C or °F
	Sources  []string `json:"sources"`        // ecosystems that devices come from, e.g. Matter, Google Nest, Philips Hue
}

// Area is a room or zone.
type Area struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Device is one physical device, which can have several entities (a plug with a switch and
// a power sensor, a thermostat with a climate entity and a humidity sensor).
type Device struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	Firmware     string `json:"firmware,omitempty"`
	Area         string `json:"area,omitempty"`   // area id
	Source       string `json:"source,omitempty"` // ecosystem label: Matter, Google Nest, Philips Hue...
	Online       bool   `json:"online"`           // at least one entity is not "unavailable"
}

// Entity is one thing that has a state and may be controlled.
type Entity struct {
	ID          string    `json:"id"`     // entity_id, e.g. light.kitchen
	Domain      string    `json:"domain"` // light, switch, climate, lock, sensor...
	Name        string    `json:"name"`
	State       string    `json:"state"`
	Device      string    `json:"device,omitempty"` // device id
	Area        string    `json:"area,omitempty"`   // area id (entity's own, else its device's)
	Source      string    `json:"source,omitempty"`
	DeviceClass string    `json:"device_class,omitempty"`
	Unit        string    `json:"unit,omitempty"`
	Changed     time.Time `json:"changed"`
	// Brightness is 0..100 for lights that dim.
	Brightness *int `json:"brightness,omitempty"`
	Dimmable   bool `json:"dimmable,omitempty"`
	// Climate.
	CurrentTemp *float64 `json:"current_temp,omitempty"`
	TargetTemp  *float64 `json:"target_temp,omitempty"`
	MinTemp     float64  `json:"min_temp,omitempty"`
	MaxTemp     float64  `json:"max_temp,omitempty"`
	TempStep    float64  `json:"temp_step,omitempty"`
	HVACModes   []string `json:"hvac_modes,omitempty"`
	HVACAction  string   `json:"hvac_action,omitempty"`
	Humidity    *float64 `json:"humidity,omitempty"`
	// Media players.
	MediaTitle string `json:"media_title,omitempty"`
	// Battery is the device's battery level, when it has one.
	Battery *int `json:"battery,omitempty"`
	// Actions NCC allows on this entity (see the Action constants).
	Actions []string `json:"actions,omitempty"`
}

// Alert is something that needs attention: a device offline, a low battery.
type Alert struct {
	Level   string `json:"level"` // warning | critical
	Subject string `json:"subject"`
	Message string `json:"message"`
	Entity  string `json:"entity,omitempty"`
}

// Inventory is what one read of a smart home hub returns.
type Inventory struct {
	Target   string    `json:"target"`
	Kind     string    `json:"kind"`
	TakenAt  time.Time `json:"taken_at"`
	Hub      Hub       `json:"hub"`
	Areas    []Area    `json:"areas"`
	Devices  []Device  `json:"devices"`
	Entities []Entity  `json:"entities"`
	Alerts   []Alert   `json:"alerts"`
	Warnings []string  `json:"warnings,omitempty"` // parts that could not be read
}

// Target is a configured smart home connection.
type Target struct {
	ID      int64
	Name    string
	Kind    string
	Address string
	Options map[string]string
}

// Result is a collection plus option values to save back, e.g. a pinned certificate.
type Result struct {
	Inventory     *Inventory
	OptionUpdates map[string]string
}

// Command is one control request for one entity.
type Command struct {
	Entity string   `json:"entity"`
	Action string   `json:"action"`
	Value  *float64 `json:"value,omitempty"` // brightness %, temperature
	Mode   string   `json:"mode,omitempty"`  // HVAC mode
}

// Call is the Home Assistant service a command becomes.
type Call struct {
	Domain  string         `json:"domain"`
	Service string         `json:"service"`
	Data    map[string]any `json:"data"`
}

// PairResult describes a finished Matter pairing.
type PairResult struct {
	NewDevices []string `json:"new_devices,omitempty"` // names of devices that appeared
}

// Provider talks to one kind of smart home hub.
type Provider interface {
	Kind() string
	Collect(ctx context.Context, t Target, creds map[string]string) (*Result, error)
	// Call runs a service and returns the entities whose state changed.
	Call(ctx context.Context, t Target, creds map[string]string, c Call) ([]Entity, error)
	// PairMatter adds a Matter device from a setup or pairing code. networkOnly is true for
	// devices already on the network (codes shared from Google Home, Alexa or Apple Home).
	PairMatter(ctx context.Context, t Target, creds map[string]string, code string, networkOnly bool) error
}

var (
	mu        sync.RWMutex
	providers = map[string]Provider{}
)

// Register adds a provider. Providers call it from init.
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	providers[p.Kind()] = p
}

// Get returns a registered provider.
func Get(kind string) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := providers[kind]
	if !ok {
		return nil, fmt.Errorf("no smart home provider %q", kind)
	}
	return p, nil
}

// Kinds lists registered providers.
func Kinds() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(providers))
	for k := range providers {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Actions NCC knows. Each maps to one Home Assistant service.
const (
	ActOn          = "turn_on"
	ActOff         = "turn_off"
	ActToggle      = "toggle"
	ActBrightness  = "brightness"
	ActOpen        = "open"
	ActClose       = "close"
	ActStop        = "stop"
	ActLock        = "lock"
	ActUnlock      = "unlock"
	ActSetTemp     = "set_temperature"
	ActSetMode     = "set_hvac_mode"
	ActPlayPause   = "play_pause"
	ActStart       = "start"
	ActPause       = "pause"
	ActDock        = "dock"
	ActActivate    = "activate" // scenes and scripts
	ActArmHome     = "arm_home"
	ActArmAway     = "arm_away"
	ActDisarm      = "disarm"
	ActPress       = "press"
	ActUnsupported = ""
)

// Domains NCC shows. Others (automations, zones, people, updates...) are left in Home Assistant.
var shownDomains = map[string]bool{
	"light": true, "switch": true, "fan": true, "cover": true, "climate": true, "lock": true, "media_player": true,
	"vacuum": true, "lawn_mower": true, "alarm_control_panel": true, "sensor": true, "binary_sensor": true, "camera": true,
	"scene": true, "script": true, "humidifier": true, "water_heater": true, "valve": true, "input_boolean": true, "button": true,
}

// Shown reports whether NCC lists entities of a domain.
func Shown(domain string) bool { return shownDomains[domain] }

// sensorClasses are the sensor device classes worth listing; others (signal strength,
// timestamps, diagnostics) are noise on an overview.
var sensorClasses = map[string]bool{
	"temperature": true, "humidity": true, "battery": true, "power": true, "energy": true, "carbon_dioxide": true,
	"pm25": true, "illuminance": true, "moisture": true, "pressure": true, "aqi": true, "volatile_organic_compounds": true,
	"carbon_monoxide": true, "gas": true, "water": true, "current": true, "voltage": true,
}

// ShownSensor reports whether a sensor with this device class is worth listing.
func ShownSensor(class string) bool { return sensorClasses[class] }

// sensitiveCovers are cover classes that let people in when opened.
var sensitiveCovers = map[string]bool{"garage": true, "gate": true, "door": true}

// AllowedActions returns what NCC lets people do with an entity.
func AllowedActions(e *Entity) []string {
	if e.State == "unavailable" {
		return nil
	}
	switch e.Domain {
	case "light":
		if e.Dimmable {
			return []string{ActToggle, ActOn, ActOff, ActBrightness}
		}
		return []string{ActToggle, ActOn, ActOff}
	case "switch", "fan", "input_boolean", "humidifier":
		return []string{ActToggle, ActOn, ActOff}
	case "media_player":
		return []string{ActOn, ActOff, ActPlayPause}
	case "cover":
		return []string{ActOpen, ActClose, ActStop}
	case "valve":
		return []string{ActOpen, ActClose}
	case "lock":
		return []string{ActLock, ActUnlock}
	case "climate":
		a := []string{ActSetTemp}
		if len(e.HVACModes) > 0 {
			a = append(a, ActSetMode)
		}
		return a
	case "water_heater":
		return []string{ActSetTemp}
	case "vacuum", "lawn_mower":
		return []string{ActStart, ActPause, ActDock}
	case "scene", "script":
		return []string{ActActivate}
	case "alarm_control_panel":
		return []string{ActArmHome, ActArmAway, ActDisarm}
	case "button":
		return []string{ActPress}
	}
	return nil
}

// Sensitive reports whether an action can let someone into the home or switch off its
// security, so it needs an admin and a confirmation.
func Sensitive(e *Entity, action string) bool {
	switch {
	case e.Domain == "lock" && action == ActUnlock:
		return true
	case e.Domain == "alarm_control_panel" && action == ActDisarm:
		return true
	case e.Domain == "cover" && action == ActOpen && sensitiveCovers[e.DeviceClass]:
		return true
	}
	return false
}

// Plan turns a command into the Home Assistant service call, checking it is allowed.
func Plan(e *Entity, c Command) (Call, string, error) {
	allowed := false
	for _, a := range e.Actions {
		allowed = allowed || a == c.Action
	}
	if !allowed {
		if e.State == "unavailable" {
			return Call{}, "", fmt.Errorf("%s is offline", e.Name)
		}
		return Call{}, "", fmt.Errorf("%s can't do %q", e.Name, c.Action)
	}
	data := map[string]any{"entity_id": e.ID}
	call := func(domain, service, desc string) (Call, string, error) {
		return Call{Domain: domain, Service: service, Data: data}, desc, nil
	}
	switch c.Action {
	case ActOn:
		return call(e.Domain, "turn_on", "Turn on "+e.Name)
	case ActOff:
		return call(e.Domain, "turn_off", "Turn off "+e.Name)
	case ActToggle:
		return call(e.Domain, "toggle", "Switch "+e.Name+" "+map[bool]string{true: "off", false: "on"}[e.State == "on"])
	case ActBrightness:
		if c.Value == nil || *c.Value < 0 || *c.Value > 100 {
			return Call{}, "", fmt.Errorf("brightness must be 0 to 100")
		}
		pct := int(math.Round(*c.Value))
		if pct == 0 {
			return call("light", "turn_off", "Turn off "+e.Name)
		}
		data["brightness_pct"] = pct
		return call("light", "turn_on", fmt.Sprintf("Set %s to %d%%", e.Name, pct))
	case ActOpen:
		if e.Domain == "valve" {
			return call("valve", "open_valve", "Open "+e.Name)
		}
		return call("cover", "open_cover", "Open "+e.Name)
	case ActClose:
		if e.Domain == "valve" {
			return call("valve", "close_valve", "Close "+e.Name)
		}
		return call("cover", "close_cover", "Close "+e.Name)
	case ActStop:
		return call("cover", "stop_cover", "Stop "+e.Name)
	case ActLock:
		return call("lock", "lock", "Lock "+e.Name)
	case ActUnlock:
		return call("lock", "unlock", "Unlock "+e.Name)
	case ActSetTemp:
		if c.Value == nil || math.IsNaN(*c.Value) {
			return Call{}, "", fmt.Errorf("give a temperature")
		}
		lo, hi := e.MinTemp, e.MaxTemp
		if lo == 0 && hi == 0 {
			lo, hi = 5, 35
		}
		if *c.Value < lo || *c.Value > hi {
			return Call{}, "", fmt.Errorf("%s takes %s to %s", e.Name, num(lo), num(hi))
		}
		data["temperature"] = *c.Value
		return call(e.Domain, "set_temperature", fmt.Sprintf("Set %s to %s°", e.Name, num(*c.Value)))
	case ActSetMode:
		ok := false
		for _, m := range e.HVACModes {
			ok = ok || m == c.Mode
		}
		if !ok {
			return Call{}, "", fmt.Errorf("%s has no %q mode", e.Name, c.Mode)
		}
		data["hvac_mode"] = c.Mode
		return call("climate", "set_hvac_mode", fmt.Sprintf("Set %s to %s", e.Name, strings.ReplaceAll(c.Mode, "_", " ")))
	case ActPlayPause:
		return call("media_player", "media_play_pause", "Play or pause "+e.Name)
	case ActStart:
		if e.Domain == "lawn_mower" {
			return call("lawn_mower", "start_mowing", "Start "+e.Name)
		}
		return call("vacuum", "start", "Start "+e.Name)
	case ActPause:
		return call(e.Domain, "pause", "Pause "+e.Name)
	case ActDock:
		if e.Domain == "lawn_mower" {
			return call("lawn_mower", "dock", "Send "+e.Name+" home")
		}
		return call("vacuum", "return_to_base", "Send "+e.Name+" back to its dock")
	case ActActivate:
		return call(e.Domain, "turn_on", "Run "+e.Name)
	case ActArmHome:
		return call("alarm_control_panel", "alarm_arm_home", "Arm "+e.Name+" (home)")
	case ActArmAway:
		return call("alarm_control_panel", "alarm_arm_away", "Arm "+e.Name+" (away)")
	case ActDisarm:
		return call("alarm_control_panel", "alarm_disarm", "Disarm "+e.Name)
	case ActPress:
		return call("button", "press", "Press "+e.Name)
	}
	return Call{}, "", fmt.Errorf("unknown action %q", c.Action)
}

func num(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// Battery thresholds for alerts, in percent.
const (
	BatteryWarn     = 20
	BatteryCritical = 10
)

// Finish fills in derived fields: device online state, battery levels, allowed actions,
// alerts, sources and a stable order.
func (inv *Inventory) Finish() {
	if inv.Areas == nil {
		inv.Areas = []Area{}
	}
	if inv.Devices == nil {
		inv.Devices = []Device{}
	}
	if inv.Entities == nil {
		inv.Entities = []Entity{}
	}
	devIdx := map[string]int{}
	for i := range inv.Devices {
		devIdx[inv.Devices[i].ID] = i
	}
	online := map[string]bool{}
	battery := map[string]int{}
	for _, e := range inv.Entities {
		if e.Device != "" && e.State != "unavailable" {
			online[e.Device] = true
		}
		if e.Domain == "sensor" && e.DeviceClass == "battery" && e.Device != "" {
			if v, err := strconv.ParseFloat(e.State, 64); err == nil {
				battery[e.Device] = int(math.Round(v))
			}
		}
	}
	srcs := map[string]bool{}
	for i := range inv.Devices {
		d := &inv.Devices[i]
		d.Online = online[d.ID]
		if d.Source != "" {
			srcs[d.Source] = true
		}
	}
	inv.Alerts = []Alert{} // never null in JSON: the page maps over it
	for i := range inv.Entities {
		e := &inv.Entities[i]
		if e.Area == "" && e.Device != "" {
			if j, ok := devIdx[e.Device]; ok {
				e.Area = inv.Devices[j].Area
			}
		}
		if b, ok := battery[e.Device]; ok && e.Battery == nil {
			b := b
			e.Battery = &b
		}
		e.Actions = AllowedActions(e)
	}
	// one alert per offline device, and per low battery
	for _, d := range inv.Devices {
		if !d.Online && hasEntities(inv, d.ID) {
			inv.Alerts = append(inv.Alerts, Alert{Level: "warning", Subject: d.Name, Message: "is offline (unavailable in Home Assistant)"})
		}
	}
	for _, e := range inv.Entities {
		if e.Device != "" || e.State != "unavailable" || e.Domain == "scene" || e.Domain == "script" {
			continue
		}
		inv.Alerts = append(inv.Alerts, Alert{Level: "warning", Subject: e.Name, Message: "is unavailable", Entity: e.ID})
	}
	for id, b := range battery {
		j, ok := devIdx[id]
		if !ok || b > BatteryWarn {
			continue
		}
		lvl := "warning"
		if b <= BatteryCritical {
			lvl = "critical"
		}
		inv.Alerts = append(inv.Alerts, Alert{Level: lvl, Subject: inv.Devices[j].Name, Message: fmt.Sprintf("battery at %d%%", b)})
	}
	sort.SliceStable(inv.Alerts, func(i, j int) bool {
		if inv.Alerts[i].Level != inv.Alerts[j].Level {
			return inv.Alerts[i].Level == "critical"
		}
		return inv.Alerts[i].Subject < inv.Alerts[j].Subject
	})
	inv.Hub.Sources = []string{}
	for s := range srcs {
		inv.Hub.Sources = append(inv.Hub.Sources, s)
	}
	sort.Strings(inv.Hub.Sources)
	sort.SliceStable(inv.Areas, func(i, j int) bool { return strings.ToLower(inv.Areas[i].Name) < strings.ToLower(inv.Areas[j].Name) })
	sort.SliceStable(inv.Devices, func(i, j int) bool {
		return strings.ToLower(inv.Devices[i].Name) < strings.ToLower(inv.Devices[j].Name)
	})
	sort.SliceStable(inv.Entities, func(i, j int) bool {
		a, b := inv.Entities[i], inv.Entities[j]
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
}

func hasEntities(inv *Inventory, device string) bool {
	for _, e := range inv.Entities {
		if e.Device == device {
			return true
		}
	}
	return false
}

// Entity returns the entity with an id, or nil.
func (inv *Inventory) Entity(id string) *Entity {
	for i := range inv.Entities {
		if inv.Entities[i].ID == id {
			return &inv.Entities[i]
		}
	}
	return nil
}

// Apply merges changed entity states (from a service call) into the inventory.
func (inv *Inventory) Apply(changed []Entity) {
	for _, c := range changed {
		e := inv.Entity(c.ID)
		if e == nil {
			continue
		}
		e.State = c.State
		e.Changed = c.Changed
		if c.Brightness != nil || e.Domain == "light" {
			e.Brightness = c.Brightness
		}
		if c.TargetTemp != nil {
			e.TargetTemp = c.TargetTemp
		}
		if c.CurrentTemp != nil {
			e.CurrentTemp = c.CurrentTemp
		}
		if c.HVACAction != "" {
			e.HVACAction = c.HVACAction
		}
		e.MediaTitle = c.MediaTitle
		e.Actions = AllowedActions(e)
	}
}

// sourceLabels names the integrations devices come through.
var sourceLabels = map[string]string{
	"matter": "Matter", "nest": "Google Nest", "cast": "Google Cast", "google_assistant_sdk": "Google Assistant",
	"alexa_devices": "Amazon Alexa", "hue": "Philips Hue", "tplink": "TP-Link", "tplink_tapo": "TP-Link Tapo", "zha": "Zigbee (ZHA)",
	"zwave_js": "Z-Wave", "mqtt": "MQTT", "esphome": "ESPHome", "shelly": "Shelly", "tuya": "Tuya", "homekit_controller": "HomeKit",
	"sonos": "Sonos", "ring": "Ring", "roku": "Roku", "wemo": "Wemo", "lifx": "LIFX", "ecobee": "ecobee", "smartthings": "SmartThings",
	"yeelight": "Yeelight", "wiz": "WiZ", "govee_light_local": "Govee", "switchbot": "SwitchBot", "thread": "Thread", "unifiprotect": "UniFi Protect",
	"apple_tv": "Apple TV", "samsungtv": "Samsung TV", "webostv": "LG TV", "broadlink": "Broadlink", "nanoleaf": "Nanoleaf", "ikea": "IKEA",
	"tradfri": "IKEA", "homematicip_cloud": "Homematic IP", "netatmo": "Netatmo", "zigbee2mqtt": "Zigbee2MQTT", "deconz": "deCONZ",
}

// SourceLabel names an integration domain for people, e.g. "nest" is "Google Nest".
func SourceLabel(platform string) string {
	if l, ok := sourceLabels[platform]; ok {
		return l
	}
	if platform == "" {
		return ""
	}
	p := strings.ReplaceAll(platform, "_", " ")
	return strings.ToUpper(p[:1]) + p[1:]
}
