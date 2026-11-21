# Home Assistant for NCC's Smart home page

Google Home and Alexa don't let other apps control their devices, so NCC's **Smart home**
page works through [Home Assistant](https://www.home-assistant.io/), a free smart home
server. Home Assistant controls:

- **Matter** devices, including ones already in Google Home, Alexa or Apple Home. Matter
  lets a device have several controllers at once ("multi-admin"), so the device stays in
  Google Home and NCC gets control too.
- **Google Nest** thermostats, cameras and doorbells that don't speak Matter, through the
  Google Nest integration. Google charges a one-time US$5 for Device Access.
- **Nest speakers and displays and Chromecasts** (Google Cast integration, found automatically).
- **Amazon Echo** devices (Alexa Devices integration).
- Hue, TP-Link Kasa and Tapo, Zigbee, Z-Wave, Shelly, Sonos, Ring and hundreds more.

## 1. Run Home Assistant and the Matter server

Either way works:

- **Docker** (next to NCC, or on any Linux host on the same LAN): copy this folder, set
  `TZ` in `docker-compose.yml`, and run `docker compose up -d`. Both containers use the
  host's network so Matter's mDNS and IPv6 traffic reach your devices.
- **Home Assistant OS as a Proxmox VM** (the Home Assistant project's recommended install):
  create a VM from the HAOS `qcow2` image with its network on the same bridge and VLAN as
  your smart home devices, then install the **Matter Server** add-on from the add-on store.

Matter devices that use **Thread** (many sensors, locks and bulbs) are reached through a
Thread border router. A Google Nest Hub (2nd gen), Nest Hub Max or Nest Wifi Pro is one;
Home Assistant uses it as long as it is on the same network and IPv6 is allowed between
them. Keep Home Assistant on the same VLAN as your Google devices, or make sure mDNS and
IPv6 cross between the VLANs.

## 2. Set up Home Assistant

1. Open `http://<host>:8123` and create the owner account.
2. **Settings → Devices & services → Add integration → Matter**. With the Docker setup
   enter `ws://localhost:5580/ws`; the HAOS add-on is found by itself.
3. Optional: add **Google Nest**, **Google Cast** and **Alexa Devices** the same way.
4. Give your rooms names under **Settings → Areas**; NCC groups devices by them.
5. Click your name (bottom left) → **Security** → **Long-lived access tokens** → **Create
   token**. Copy it; Home Assistant shows it only once. Use an administrator account so NCC
   can read rooms and pair Matter devices.

## 3. Connect NCC

In NCC open **Smart home** (or **Settings → Add Home Assistant**), enter the address
(`http://<host>:8123`) and paste the token. The token is stored in NCC's vault. NCC reads
Home Assistant every poll interval and right after each change.

## 4. Share Google Home devices with NCC

For each Matter device in Google Home:

1. Google Home app → tap the device → **Settings** → **Linked Matter apps & services** →
   **Link apps & services** → **Share with code**.
2. In NCC: **Smart home → Add Matter device**, paste the 11-digit code within a few
   minutes, **Check code**, then **Pair device**.

Alexa: device → gear → **Other assistants and apps** → **Add another**. Apple Home: device →
Settings → **Turn On Pairing Mode**.

## What NCC lets people do

| Who | Can |
| --- | --- |
| Viewer | See devices, states, rooms, batteries and alerts |
| Operator | Switch lights, plugs and fans; dim lights; set thermostats; lock; close garage doors; play and pause; start robots; run scenes |
| Admin | Everything above, plus unlock doors, open garage doors and gates and disarm alarms (each after a confirmation), and pair Matter devices |

Every change is written to NCC's audit log.
