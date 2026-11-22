package mocklab

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

type haEnt struct {
	id, device, platform, area string
	state                      string
	attrs                      map[string]any
	changed                    time.Time
	category                   string // entity_category (config, diagnostic)
}

// haConnections are the network MACs Home Assistant knows for some devices; they match
// clients of the pretend UniFi network.
var haConnections = map[string][][]string{
	"d-thermo": {{"mac", "DE:AD:00:00:00:07"}},
	"d-hue":    {{"mac", "de:ad:00:00:00:0c"}},
}

type haDev struct {
	id, name, manufacturer, model, sw, area, platform string
}

// HomeAssistant emulates the parts of Home Assistant NCC uses: the WebSocket API (auth,
// get_config, get_states, the area, device and entity registries, matter/commission) and
// the REST service API. It accepts the long-lived token given. The pretend home is a Google
// Home household with Matter, Nest, Cast, Hue and Alexa devices.
func HomeAssistant(token string) http.Handler {
	var lock sync.Mutex
	t0 := time.Now().Add(-3 * time.Hour)
	areas := [][2]string{{"living_room", "Living room"}, {"kitchen", "Kitchen"}, {"hallway", "Hallway"}, {"bedroom", "Bedroom"},
		{"garage", "Garage"}, {"office", "Office"}}
	devs := []*haDev{
		{"d-lamp", "Living room lamp", "Nanoleaf", "Essentials A19", "3.5.10", "living_room", "matter"},
		{"d-hue", "Ceiling light", "Signify", "Hue White Ambiance", "1.116.3", "living_room", "hue"},
		{"d-nesthub", "Nest Hub", "Google Inc.", "Google Nest Hub (2nd gen)", "", "living_room", "cast"},
		{"d-tv", "Living room TV", "Google Inc.", "Chromecast with Google TV", "", "living_room", "cast"},
		{"d-kitchen", "Kitchen lights", "TP-Link", "Tapo L535E", "1.1.0", "kitchen", "matter"},
		{"d-coffee", "Coffee machine plug", "TP-Link", "Tapo P125M", "1.2.3", "kitchen", "matter"},
		{"d-echo", "Echo Show", "Amazon", "Echo Show 8 (3rd gen)", "", "kitchen", "alexa_devices"},
		{"d-thermo", "Thermostat", "Google", "Nest Learning Thermostat (4th gen)", "4.2.6", "hallway", "nest"},
		{"d-lock", "Front door", "Aqara", "Smart Lock U200", "4.0.3", "hallway", "matter"},
		{"d-bell", "Doorbell", "Google", "Nest Doorbell (battery)", "1.67.2", "hallway", "nest"},
		{"d-bedlamp", "Bedside lamp", "IKEA of Sweden", "TRADFRI bulb E27", "2.3.095", "bedroom", "matter"},
		{"d-bedtemp", "Bedroom sensor", "Aqara", "Climate Sensor W100", "1.0.7", "bedroom", "matter"},
		{"d-garage", "Garage door", "Meross", "MSG100 Smart Garage Opener", "6.2.0", "garage", "matter"},
		{"d-outplug", "Outdoor plug", "Eve Systems", "Eve Energy Outdoor", "3.2.1", "garage", "matter"},
		{"d-fan", "Desk fan", "SwitchBot", "Plug Mini (Matter)", "1.4", "office", "matter"},
		{"d-air", "Office air monitor", "Eve Systems", "Eve Room", "1.3.1", "office", "matter"},
		{"d-vac", "Roomba", "iRobot", "Roomba j7+", "22.29.6", "living_room", "roomba"},
		{"d-hacore", "Home Assistant Core", "Home Assistant", "Home Assistant", "2026.11.2", "", "hassio"},
	}
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	ents := []*haEnt{
		{id: "light.living_room_lamp", device: "d-lamp", platform: "matter", state: "on", changed: at(20), attrs: map[string]any{
			"friendly_name": "Living room lamp", "brightness": 178.0, "supported_color_modes": []any{"color_temp", "xy"}}},
		{id: "light.ceiling_light", device: "d-hue", platform: "hue", state: "off", changed: at(-60), attrs: map[string]any{
			"friendly_name": "Ceiling light", "supported_color_modes": []any{"color_temp"}}},
		{id: "media_player.nest_hub", device: "d-nesthub", platform: "cast", state: "playing", changed: at(150), attrs: map[string]any{
			"friendly_name": "Nest Hub", "media_title": "Morning Jazz", "app_name": "YouTube Music"}},
		{id: "media_player.living_room_tv", device: "d-tv", platform: "cast", state: "off", changed: at(-200), attrs: map[string]any{
			"friendly_name": "Living room TV"}},
		{id: "light.kitchen_lights", device: "d-kitchen", platform: "matter", state: "on", changed: at(5), attrs: map[string]any{
			"friendly_name": "Kitchen lights", "brightness": 255.0, "supported_color_modes": []any{"brightness"}}},
		{id: "switch.coffee_machine_plug", device: "d-coffee", platform: "matter", state: "off", changed: at(90), attrs: map[string]any{
			"friendly_name": "Coffee machine plug", "device_class": "outlet"}},
		{id: "sensor.coffee_machine_plug_power", device: "d-coffee", platform: "matter", state: "0.4", changed: at(90), attrs: map[string]any{
			"friendly_name": "Coffee machine plug Power", "device_class": "power", "unit_of_measurement": "W"}},
		{id: "media_player.echo_show", device: "d-echo", platform: "alexa_devices", state: "idle", changed: at(30), attrs: map[string]any{
			"friendly_name": "Echo Show"}},
		{id: "climate.thermostat", device: "d-thermo", platform: "nest", state: "heat", changed: at(-300), attrs: map[string]any{
			"friendly_name": "Thermostat", "current_temperature": 20.5, "temperature": 21.0, "min_temp": 9.0, "max_temp": 32.0,
			"target_temp_step": 0.5, "hvac_modes": []any{"off", "heat", "cool", "heat_cool"}, "hvac_action": "heating", "current_humidity": 44.0}},
		{id: "lock.front_door", device: "d-lock", platform: "matter", state: "locked", changed: at(100), attrs: map[string]any{
			"friendly_name": "Front door"}},
		{id: "sensor.front_door_battery", device: "d-lock", platform: "matter", state: "64", changed: at(100), attrs: map[string]any{
			"friendly_name": "Front door Battery", "device_class": "battery", "unit_of_measurement": "%"}},
		{id: "camera.doorbell", device: "d-bell", platform: "nest", state: "idle", changed: at(-30), attrs: map[string]any{
			"friendly_name": "Doorbell"}},
		{id: "binary_sensor.doorbell_motion", device: "d-bell", platform: "nest", state: "off", changed: at(160), attrs: map[string]any{
			"friendly_name": "Doorbell Motion", "device_class": "motion"}},
		{id: "light.bedside_lamp", device: "d-bedlamp", platform: "matter", state: "off", changed: at(-400), attrs: map[string]any{
			"friendly_name": "Bedside lamp", "supported_color_modes": []any{"brightness"}}},
		{id: "sensor.bedroom_sensor_temperature", device: "d-bedtemp", platform: "matter", state: "18.9", changed: at(170), attrs: map[string]any{
			"friendly_name": "Bedroom sensor Temperature", "device_class": "temperature", "unit_of_measurement": "°C"}},
		{id: "sensor.bedroom_sensor_humidity", device: "d-bedtemp", platform: "matter", state: "52", changed: at(170), attrs: map[string]any{
			"friendly_name": "Bedroom sensor Humidity", "device_class": "humidity", "unit_of_measurement": "%"}},
		{id: "sensor.bedroom_sensor_battery", device: "d-bedtemp", platform: "matter", state: "8", changed: at(170), attrs: map[string]any{
			"friendly_name": "Bedroom sensor Battery", "device_class": "battery", "unit_of_measurement": "%"}},
		{id: "cover.garage_door", device: "d-garage", platform: "matter", state: "closed", changed: at(-120), attrs: map[string]any{
			"friendly_name": "Garage door", "device_class": "garage"}},
		{id: "switch.outdoor_plug", device: "d-outplug", platform: "matter", state: "unavailable", changed: at(-900), attrs: map[string]any{
			"friendly_name": "Outdoor plug", "device_class": "outlet"}},
		{id: "switch.desk_fan", device: "d-fan", platform: "matter", state: "on", changed: at(110), attrs: map[string]any{
			"friendly_name": "Desk fan"}},
		{id: "sensor.office_air_monitor_carbon_dioxide", device: "d-air", platform: "matter", state: "812", changed: at(175), attrs: map[string]any{
			"friendly_name": "Office air monitor CO2", "device_class": "carbon_dioxide", "unit_of_measurement": "ppm"}},
		{id: "sensor.office_air_monitor_temperature", device: "d-air", platform: "matter", state: "22.1", changed: at(175), attrs: map[string]any{
			"friendly_name": "Office air monitor Temperature", "device_class": "temperature", "unit_of_measurement": "°C"}},
		{id: "sensor.office_air_monitor_signal", device: "d-air", platform: "matter", state: "-61", changed: at(175), category: "diagnostic", attrs: map[string]any{
			"friendly_name": "Office air monitor Signal", "device_class": "signal_strength", "unit_of_measurement": "dBm"}},
		{id: "vacuum.roomba", device: "d-vac", platform: "roomba", state: "docked", changed: at(-500), attrs: map[string]any{
			"friendly_name": "Roomba", "battery_level": 100.0}},
		{id: "scene.movie_night", platform: "homeassistant", area: "living_room", state: "2026-11-20T21:04:00+00:00", changed: at(-600), attrs: map[string]any{
			"friendly_name": "Movie night"}},
		{id: "scene.good_night", platform: "homeassistant", state: "2026-11-20T23:30:00+00:00", changed: at(-500), attrs: map[string]any{
			"friendly_name": "Good night"}},
		{id: "automation.porch_light_at_sunset", platform: "automation", state: "on", changed: at(-700), attrs: map[string]any{
			"friendly_name": "Porch light at sunset"}},
		{id: "sun.sun", platform: "sun", state: "below_horizon", changed: at(-60), attrs: map[string]any{"friendly_name": "Sun"}},
		{id: "update.home_assistant_core_update", device: "d-hacore", platform: "hassio", state: "off", changed: at(-800), category: "config", attrs: map[string]any{
			"friendly_name": "Home Assistant Core Update"}},
	}
	paired := 0

	stateJSON := func(e *haEnt) map[string]any {
		return map[string]any{"entity_id": e.id, "state": e.state, "attributes": e.attrs,
			"last_changed": e.changed.UTC().Format(time.RFC3339Nano), "last_updated": e.changed.UTC().Format(time.RFC3339Nano)}
	}
	find := func(id string) *haEnt {
		for _, e := range ents {
			if e.id == id {
				return e
			}
		}
		return nil
	}

	// service runs a pretend service on an entity and reports whether it changed.
	service := func(domain, svc string, data map[string]any) ([]map[string]any, error) {
		id, _ := data["entity_id"].(string)
		e := find(id)
		if e == nil || !strings.HasPrefix(id, domain+".") {
			return nil, fmt.Errorf("Referenced entities %s are missing or not currently available", id)
		}
		if e.state == "unavailable" {
			return nil, fmt.Errorf("Entity %s is unavailable", id)
		}
		set := func(s string) { e.state = s }
		switch domain + "." + svc {
		case "light.turn_on":
			set("on")
			if p, ok := data["brightness_pct"].(float64); ok {
				e.attrs["brightness"] = float64(int(p * 255 / 100))
			} else if _, ok := e.attrs["brightness"]; !ok {
				e.attrs["brightness"] = 255.0
			}
		case "light.turn_off", "switch.turn_off", "fan.turn_off", "media_player.turn_off":
			set("off")
		case "switch.turn_on", "fan.turn_on":
			set("on")
		case "media_player.turn_on":
			set("idle")
		case "light.toggle", "switch.toggle", "fan.toggle":
			if e.state == "on" {
				set("off")
			} else {
				set("on")
				if domain == "light" {
					if _, ok := e.attrs["brightness"]; !ok {
						e.attrs["brightness"] = 255.0
					}
				}
			}
		case "media_player.media_play_pause":
			if e.state == "playing" {
				set("paused")
			} else {
				set("playing")
			}
		case "cover.open_cover":
			set("open")
		case "cover.close_cover":
			set("closed")
		case "cover.stop_cover":
		case "lock.lock":
			set("locked")
		case "lock.unlock":
			set("unlocked")
		case "climate.set_temperature":
			e.attrs["temperature"] = data["temperature"]
		case "climate.set_hvac_mode":
			set(data["hvac_mode"].(string))
			if e.state == "off" {
				e.attrs["hvac_action"] = "off"
			} else {
				e.attrs["hvac_action"] = "idle"
			}
		case "vacuum.start":
			set("cleaning")
		case "vacuum.pause":
			set("paused")
		case "vacuum.return_to_base":
			set("returning")
		case "scene.turn_on":
			set(time.Now().UTC().Format(time.RFC3339))
		default:
			return nil, fmt.Errorf("Service %s.%s not found", domain, svc)
		}
		if domain == "light" && e.state == "off" {
			delete(e.attrs, "brightness")
		}
		e.changed = time.Now()
		return []map[string]any{stateJSON(e)}, nil
	}

	mux := http.NewServeMux()
	authOK := func(r *http.Request) bool { return r.Header.Get("Authorization") == "Bearer "+token }
	mux.HandleFunc("GET /api/", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			http.Error(w, "401: Unauthorized", 401)
			return
		}
		writeJSON(w, map[string]string{"message": "API running."})
	})
	mux.HandleFunc("POST /api/services/{domain}/{service}", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			http.Error(w, "401: Unauthorized", 401)
			return
		}
		var data map[string]any
		_ = json.NewDecoder(r.Body).Decode(&data)
		lock.Lock()
		out, err := service(r.PathValue("domain"), r.PathValue("service"), data)
		lock.Unlock()
		if err != nil {
			w.WriteHeader(400)
			writeJSON(w, map[string]string{"message": err.Error()})
			return
		}
		writeJSON(w, out)
	})
	mux.HandleFunc("GET /api/websocket", func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		c.SetReadLimit(1 << 20)
		ctx := r.Context()
		send := func(v any) error {
			b, _ := json.Marshal(v)
			return c.Write(ctx, websocket.MessageText, b)
		}
		recv := func() (map[string]any, error) {
			_, b, err := c.Read(ctx)
			if err != nil {
				return nil, err
			}
			var m map[string]any
			return m, json.Unmarshal(b, &m)
		}
		_ = send(map[string]string{"type": "auth_required", "ha_version": "2026.11.2"})
		m, err := recv()
		if err != nil {
			return
		}
		if m["type"] != "auth" || m["access_token"] != token {
			_ = send(map[string]string{"type": "auth_invalid", "message": "Invalid access token or password"})
			return
		}
		_ = send(map[string]string{"type": "auth_ok", "ha_version": "2026.11.2"})
		for {
			m, err := recv()
			if err != nil {
				return
			}
			id := m["id"]
			ok := func(res any) { _ = send(map[string]any{"id": id, "type": "result", "success": true, "result": res}) }
			fail := func(code, msg string) {
				_ = send(map[string]any{"id": id, "type": "result", "success": false, "error": map[string]string{"code": code, "message": msg}})
			}
			lock.Lock()
			switch m["type"] {
			case "get_config":
				ok(map[string]any{"location_name": "Home", "version": "2026.11.2", "time_zone": "Europe/London",
					"unit_system": map[string]string{"temperature": "°C"},
					"components":  []string{"matter", "nest", "cast", "alexa_devices", "hue", "roomba", "scene", "automation", "http", "websocket_api"}})
			case "get_states":
				out := make([]map[string]any, 0, len(ents))
				for _, e := range ents {
					out = append(out, stateJSON(e))
				}
				ok(out)
			case "config/area_registry/list":
				out := []map[string]any{}
				for _, a := range areas {
					out = append(out, map[string]any{"area_id": a[0], "name": a[1]})
				}
				ok(out)
			case "config/device_registry/list":
				out := []map[string]any{}
				for _, d := range devs {
					var entry any
					if d.platform == "hassio" {
						entry = "service"
					}
					out = append(out, map[string]any{"id": d.id, "name": d.name, "name_by_user": nil, "manufacturer": d.manufacturer,
						"model": d.model, "sw_version": d.sw, "area_id": nilIfEmpty(d.area), "disabled_by": nil, "entry_type": entry,
						"identifiers": [][]string{{d.platform, d.id}}, "connections": haConnections[d.id]})
				}
				ok(out)
			case "config/entity_registry/list":
				out := []map[string]any{}
				for _, e := range ents {
					out = append(out, map[string]any{"entity_id": e.id, "device_id": nilIfEmpty(e.device), "area_id": nilIfEmpty(e.area),
						"platform": e.platform, "name": nil, "disabled_by": nil, "hidden_by": nil, "entity_category": nilIfEmpty(e.category)})
				}
				ok(out)
			case "matter/commission":
				code, _ := m["code"].(string)
				lock.Unlock()
				time.Sleep(1500 * time.Millisecond) // pairing takes a moment
				lock.Lock()
				if code == "" || code == "00000000000" {
					fail("pairing_failed", "Commission with code failed")
					break
				}
				paired++
				did := fmt.Sprintf("d-new%d", paired)
				name := "Smart plug"
				if paired > 1 {
					name = fmt.Sprintf("Smart plug %d", paired)
				}
				devs = append(devs, &haDev{did, name, "Eve Systems", "Eve Energy", "3.5.0", "", "matter"})
				ents = append(ents, &haEnt{id: fmt.Sprintf("switch.smart_plug_%d", paired), device: did, platform: "matter", state: "off",
					changed: time.Now(), attrs: map[string]any{"friendly_name": name, "device_class": "outlet"}})
				ok(nil)
			default:
				fail("unknown_command", "Unknown command.")
			}
			lock.Unlock()
		}
	})
	return mux
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
