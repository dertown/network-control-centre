// Package homeassistant is NCC's smart home provider for Home Assistant. It reads the
// home's areas, devices and entity states over Home Assistant's WebSocket API, controls
// devices through its REST service API, and pairs Matter devices through the Matter
// integration (python-matter-server).
//
// NCC signs in with a long-lived access token (Home Assistant: your profile → Security →
// Long-lived access tokens). The token is kept in NCC's vault. Use a Home Assistant user
// that is an administrator if you want to pair Matter devices from NCC; reading and
// controlling devices works with any user.
package homeassistant

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dertown/network-control-centre/internal/catalog"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/dertown/network-control-centre/internal/netutil"
	"github.com/dertown/network-control-centre/internal/smarthome"
)

func init() {
	smarthome.Register(Provider{}, catalog.Vendor{
		Label: "Home Assistant", Groups: []string{catalog.GroupSmartHome}, Order: 10,
		Summary: "Devices, rooms and alerts from Home Assistant, and Matter pairing.",
		Help: "Use the address you open Home Assistant at (usually port 8123). In Home Assistant open your profile → Security → " +
			"Long-lived access tokens → Create token, and paste it here. Use an administrator's token so NCC can read rooms and pair " +
			"Matter devices. An HTTPS certificate is pinned on first connection.",
		NameDefault: "home-assistant", AddressDefault: "http://192.168.1.40:8123",
		Fields: []catalog.Field{
			{Key: "token", Label: "Access token", Type: catalog.Token, Store: catalog.StoreSecret, Required: true},
			catalog.TLSField("pin"),
		},
	})
}

// Provider implements smarthome.Provider for Home Assistant.
type Provider struct{}

// Kind implements smarthome.Provider.
func (Provider) Kind() string { return "homeassistant" }

// Option keys.
const (
	OptTLS         = "tls"
	OptFingerprint = "tls_fingerprint"
)

// ErrUnauthorized means Home Assistant refused the token.
var ErrUnauthorized = errors.New("home assistant: the access token was refused; make a new long-lived token in your Home Assistant profile")

type client struct {
	base  *url.URL // http(s)://ha:8123
	http  *http.Client
	pin   *netutil.Pinner
	token string
}

func newClient(t smarthome.Target, creds map[string]string, timeout time.Duration) (*client, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(t.Address), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("home assistant: address must be a URL like http://192.168.1.40:8123, got %q", t.Address)
	}
	u.Path, u.RawQuery = "", ""
	tok := strings.TrimSpace(creds["token"])
	if tok == "" {
		return nil, errors.New("home assistant: no access token saved")
	}
	mode := t.Options[OptTLS]
	if mode == "" {
		mode = "pin"
	}
	hc, pin := netutil.NewClient(mode, t.Options[OptFingerprint], timeout)
	return &client{base: u, http: hc, pin: pin, token: tok}, nil
}

func (c *client) optionUpdates(t smarthome.Target) map[string]string {
	if c.base.Scheme != "https" || t.Options[OptFingerprint] != "" {
		return nil
	}
	if mode := t.Options[OptTLS]; mode != "" && mode != "pin" {
		return nil
	}
	if seen := c.pin.Seen(); seen != "" {
		return map[string]string{OptFingerprint: seen}
	}
	return nil
}

// rest calls the REST API.
func (c *client) rest(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := *c.base
	u.Path = path
	r, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "Bearer "+c.token)
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(r)
	if err != nil {
		return fmt.Errorf("home assistant: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return ErrUnauthorized
	case resp.StatusCode == 400:
		return fmt.Errorf("home assistant refused the request: %s", haMessage(raw))
	case resp.StatusCode >= 300:
		return fmt.Errorf("home assistant: %s: HTTP %d %s", path, resp.StatusCode, haMessage(raw))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("home assistant: %s: unreadable answer", path)
	}
	return nil
}

func haMessage(raw []byte) string {
	var m struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &m) == nil && m.Message != "" {
		return m.Message
	}
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// ws is one WebSocket API session.
type ws struct {
	conn *websocket.Conn
	id   int
}

func (c *client) dial(ctx context.Context) (*ws, error) {
	u := *c.base
	u.Scheme = map[string]string{"http": "ws", "https": "wss"}[u.Scheme]
	u.Path = "/api/websocket"
	conn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPClient: c.http})
	if err != nil {
		return nil, fmt.Errorf("home assistant: connect to %s: %w", u.Host, err)
	}
	conn.SetReadLimit(64 << 20)
	s := &ws{conn: conn}
	var hello struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	if err := s.read(ctx, &hello); err != nil {
		s.close()
		return nil, err
	}
	if hello.Type != "auth_required" {
		s.close()
		return nil, fmt.Errorf("home assistant: unexpected greeting %q", hello.Type)
	}
	if err := s.write(ctx, map[string]string{"type": "auth", "access_token": c.token}); err != nil {
		s.close()
		return nil, err
	}
	if err := s.read(ctx, &hello); err != nil {
		s.close()
		return nil, err
	}
	if hello.Type != "auth_ok" {
		s.close()
		return nil, ErrUnauthorized
	}
	return s, nil
}

func (s *ws) close() { _ = s.conn.Close(websocket.StatusNormalClosure, "") }

func (s *ws) write(ctx context.Context, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if err := s.conn.Write(ctx, websocket.MessageText, b); err != nil {
		return fmt.Errorf("home assistant: %w", err)
	}
	return nil
}

func (s *ws) read(ctx context.Context, v any) error {
	_, b, err := s.conn.Read(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("home assistant: no answer in time")
		}
		return fmt.Errorf("home assistant: %w", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("home assistant: unreadable message")
	}
	return nil
}

// cmdError is an error Home Assistant returned for a command.
type cmdError struct {
	Code    string
	Message string
}

func (e *cmdError) Error() string {
	if e.Message != "" {
		return "home assistant: " + e.Message
	}
	return "home assistant: " + e.Code
}

// cmd sends one command and waits for its result, skipping unrelated messages.
func (s *ws) cmd(ctx context.Context, typ string, fields map[string]any, out any) error {
	s.id++
	msg := map[string]any{"id": s.id, "type": typ}
	for k, v := range fields {
		msg[k] = v
	}
	if err := s.write(ctx, msg); err != nil {
		return err
	}
	for {
		var res struct {
			ID      int             `json:"id"`
			Type    string          `json:"type"`
			Success bool            `json:"success"`
			Result  json.RawMessage `json:"result"`
			Error   *cmdError       `json:"error"`
		}
		if err := s.read(ctx, &res); err != nil {
			return err
		}
		if res.ID != s.id || res.Type != "result" {
			continue
		}
		if !res.Success {
			if res.Error == nil {
				return &cmdError{Code: "unknown_error"}
			}
			return res.Error
		}
		if out == nil || len(res.Result) == 0 || string(res.Result) == "null" {
			return nil
		}
		if err := json.Unmarshal(res.Result, out); err != nil {
			return fmt.Errorf("home assistant: %s: unreadable result", typ)
		}
		return nil
	}
}

// ---- wire types ----

type haConfig struct {
	LocationName string   `json:"location_name"`
	Version      string   `json:"version"`
	TimeZone     string   `json:"time_zone"`
	Components   []string `json:"components"`
	UnitSystem   struct {
		Temperature string `json:"temperature"`
	} `json:"unit_system"`
}

type haArea struct {
	AreaID string `json:"area_id"`
	Name   string `json:"name"`
}

type haDevice struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	NameByUser      string     `json:"name_by_user"`
	Manufacturer    string     `json:"manufacturer"`
	Model           string     `json:"model"`
	SWVersion       string     `json:"sw_version"`
	AreaID          string     `json:"area_id"`
	DisabledBy      *string    `json:"disabled_by"`
	EntryType       *string    `json:"entry_type"`
	Identifiers     [][]string `json:"identifiers"`
	Connections     [][]string `json:"connections"`
	PrimaryConfigID string     `json:"primary_config_entry"`
}

type haEntityReg struct {
	EntityID       string  `json:"entity_id"`
	DeviceID       string  `json:"device_id"`
	AreaID         string  `json:"area_id"`
	Platform       string  `json:"platform"`
	Name           string  `json:"name"`
	DisabledBy     *string `json:"disabled_by"`
	HiddenBy       *string `json:"hidden_by"`
	EntityCategory *string `json:"entity_category"`
}

type haState struct {
	EntityID    string         `json:"entity_id"`
	State       string         `json:"state"`
	Attributes  map[string]any `json:"attributes"`
	LastChanged time.Time      `json:"last_changed"`
}

// Collect implements smarthome.Provider.
func (Provider) Collect(ctx context.Context, t smarthome.Target, creds map[string]string) (*smarthome.Result, error) {
	c, err := newClient(t, creds, 30*time.Second)
	if err != nil {
		return nil, err
	}
	s, err := c.dial(ctx)
	res := &smarthome.Result{OptionUpdates: c.optionUpdates(t)}
	if err != nil {
		return res, err
	}
	defer s.close()

	var cfg haConfig
	if err := s.cmd(ctx, "get_config", nil, &cfg); err != nil {
		return res, err
	}
	var states []haState
	if err := s.cmd(ctx, "get_states", nil, &states); err != nil {
		return res, err
	}
	inv := &smarthome.Inventory{Target: t.Name, Kind: "homeassistant", TakenAt: time.Now().UTC()}
	var areas []haArea
	var devices []haDevice
	var regs []haEntityReg
	// The registries need an administrator token; without them NCC still lists entities.
	if err := s.cmd(ctx, "config/area_registry/list", nil, &areas); err != nil {
		inv.Warnings = append(inv.Warnings, "Rooms and devices could not be read ("+err.Error()+"); use a token from an administrator account.")
	} else {
		if err := s.cmd(ctx, "config/device_registry/list", nil, &devices); err != nil {
			inv.Warnings = append(inv.Warnings, "Devices could not be read: "+err.Error())
		}
		if err := s.cmd(ctx, "config/entity_registry/list", nil, &regs); err != nil {
			inv.Warnings = append(inv.Warnings, "The entity registry could not be read: "+err.Error())
		}
	}
	build(inv, cfg, areas, devices, regs, states)
	res.Inventory = inv
	return res, nil
}

// build turns Home Assistant's registries and states into an inventory.
func build(inv *smarthome.Inventory, cfg haConfig, areas []haArea, devices []haDevice, regs []haEntityReg, states []haState) {
	comps := map[string]bool{}
	for _, c := range cfg.Components {
		comps[c] = true
	}
	inv.Hub = smarthome.Hub{
		Name: cfg.LocationName, Version: cfg.Version, TimeZone: cfg.TimeZone, Unit: cfg.UnitSystem.Temperature,
		Matter: comps["matter"], Nest: comps["nest"], Cast: comps["cast"], Alexa: comps["alexa_devices"],
	}
	inv.Areas = []smarthome.Area{}
	for _, a := range areas {
		inv.Areas = append(inv.Areas, smarthome.Area{ID: a.AreaID, Name: a.Name})
	}
	regBy := map[string]haEntityReg{}
	devPlatform := map[string]string{}
	for _, r := range regs {
		regBy[r.EntityID] = r
		if r.DeviceID != "" && devPlatform[r.DeviceID] == "" {
			devPlatform[r.DeviceID] = r.Platform
		}
	}
	devBy := map[string]*smarthome.Device{}
	inv.Devices = []smarthome.Device{}
	for _, d := range devices {
		if d.DisabledBy != nil || (d.EntryType != nil && *d.EntryType == "service") {
			continue
		}
		platform := ""
		if len(d.Identifiers) > 0 && len(d.Identifiers[0]) > 0 {
			platform = d.Identifiers[0][0]
		}
		if platform == "" {
			platform = devPlatform[d.ID]
		}
		inv.Devices = append(inv.Devices, smarthome.Device{
			ID: d.ID, Name: firstOf(d.NameByUser, d.Name, d.Model, "Unnamed device"), Manufacturer: d.Manufacturer, Model: d.Model,
			Firmware: d.SWVersion, MAC: connMAC(d.Connections), Area: d.AreaID, Source: smarthome.SourceLabel(platform),
		})
	}
	for i := range inv.Devices {
		devBy[inv.Devices[i].ID] = &inv.Devices[i]
	}
	inv.Entities = []smarthome.Entity{}
	used := map[string]bool{}
	for _, st := range states {
		domain, _, _ := strings.Cut(st.EntityID, ".")
		if !smarthome.Shown(domain) {
			continue
		}
		reg, inReg := regBy[st.EntityID]
		if inReg && (reg.DisabledBy != nil || reg.HiddenBy != nil || reg.EntityCategory != nil) {
			continue
		}
		cls := str(st.Attributes["device_class"])
		if domain == "sensor" && !smarthome.ShownSensor(cls) {
			continue
		}
		if domain == "binary_sensor" && cls == "" {
			continue
		}
		e := smarthome.Entity{
			ID: st.EntityID, Domain: domain, State: st.State, DeviceClass: cls, Changed: st.LastChanged,
			Name: firstOf(str(st.Attributes["friendly_name"]), reg.Name, st.EntityID), Unit: str(st.Attributes["unit_of_measurement"]),
		}
		if inReg {
			e.Area = reg.AreaID
			if d := devBy[reg.DeviceID]; d != nil {
				e.Device = d.ID
				e.Source = d.Source
				used[d.ID] = true
			} else {
				e.Source = smarthome.SourceLabel(reg.Platform)
			}
		}
		attrs(&e, st)
		inv.Entities = append(inv.Entities, e)
	}
	// keep only devices that have something to show
	keep := inv.Devices[:0]
	for _, d := range inv.Devices {
		if used[d.ID] {
			keep = append(keep, d)
		}
	}
	inv.Devices = keep
	inv.Finish()
}

// attrs reads the attributes NCC shows for an entity.
func attrs(e *smarthome.Entity, st haState) {
	a := st.Attributes
	switch e.Domain {
	case "light":
		for _, m := range list(a["supported_color_modes"]) {
			if m != "onoff" && m != "unknown" {
				e.Dimmable = true
			}
		}
		if b, ok := number(a["brightness"]); ok && st.State == "on" {
			p := int(math.Round(b / 255 * 100))
			e.Brightness = &p
		}
	case "climate", "water_heater":
		e.CurrentTemp = ptr(a["current_temperature"])
		e.TargetTemp = ptr(a["temperature"])
		e.Humidity = ptr(a["current_humidity"])
		e.MinTemp, _ = number(a["min_temp"])
		e.MaxTemp, _ = number(a["max_temp"])
		e.TempStep, _ = number(a["target_temp_step"])
		e.HVACModes = list(a["hvac_modes"])
		e.HVACAction = str(a["hvac_action"])
	case "media_player":
		e.MediaTitle = firstOf(str(a["media_title"]), str(a["app_name"]))
	}
	if b, ok := number(a["battery_level"]); ok {
		p := int(math.Round(b))
		e.Battery = &p
	}
}

func firstOf(s ...string) string {
	for _, x := range s {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}

func ptr(v any) *float64 {
	if f, ok := number(v); ok {
		return &f
	}
	return nil
}

func list(v any) []string {
	xs, _ := v.([]any)
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Call implements smarthome.Provider: it runs a Home Assistant service and returns the
// entities it changed.
func (Provider) Call(ctx context.Context, t smarthome.Target, creds map[string]string, call smarthome.Call) ([]smarthome.Entity, error) {
	c, err := newClient(t, creds, 30*time.Second)
	if err != nil {
		return nil, err
	}
	var changed []haState
	if err := c.rest(ctx, http.MethodPost, "/api/services/"+url.PathEscape(call.Domain)+"/"+url.PathEscape(call.Service), call.Data, &changed); err != nil {
		return nil, err
	}
	out := make([]smarthome.Entity, 0, len(changed))
	for _, st := range changed {
		domain, _, _ := strings.Cut(st.EntityID, ".")
		e := smarthome.Entity{ID: st.EntityID, Domain: domain, State: st.State, Changed: st.LastChanged}
		attrs(&e, st)
		out = append(out, e)
	}
	return out, nil
}

// PairMatter implements smarthome.Provider through the Matter integration.
func (Provider) PairMatter(ctx context.Context, t smarthome.Target, creds map[string]string, code string, networkOnly bool) error {
	c, err := newClient(t, creds, 30*time.Second)
	if err != nil {
		return err
	}
	s, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer s.close()
	fields := map[string]any{"code": code}
	if networkOnly {
		fields["network_only"] = true
	}
	err = s.cmd(ctx, "matter/commission", fields, nil)
	var ce *cmdError
	if errors.As(err, &ce) {
		switch ce.Code {
		case "unknown_command":
			return errors.New("home assistant: the Matter integration isn't set up; add it in Home Assistant (Settings → Devices & services → Add integration → Matter) first")
		case "unauthorized":
			return errors.New("home assistant: pairing needs a token from an administrator account")
		}
		return fmt.Errorf("matter pairing failed: %s. Pairing codes only work for a few minutes; make a new one in the app and try again", strings.TrimPrefix(ce.Error(), "home assistant: "))
	}
	return err
}

// connMAC returns the network MAC from a device's connections, e.g. [["mac", "aa:bb:..."]].
func connMAC(conns [][]string) string {
	for _, c := range conns {
		if len(c) == 2 && c[0] == "mac" {
			return strings.ToLower(c[1])
		}
	}
	return ""
}
