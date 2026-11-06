# VenusOS-VictronBLE

Shows Victron devices that only speak Bluetooth in Venus OS, as if they were wired:
in the GUI (touch screen and Remote Console), in VRM and in anything that reads the
Venus OS D-Bus (Node-RED, Home Assistant through MQTT...).

It reads the encrypted **Instant Readout** advertisements that these devices broadcast,
decrypts those of the devices you whitelist, and publishes each of them as a read-only
Venus OS D-Bus service.

| Device type | Examples | D-Bus service |
|---|---|---|
| DC/DC converter | Orion-Tr Smart, Orion Smart | `com.victronenergy.dcdc.ble_<mac>` |
| AC charger | Blue Smart IP22 / IP65 / IP67, Phoenix Smart | `com.victronenergy.charger.ble_<mac>` |

Strictly read only: no Bluetooth connection, no pairing, no D-Bus path that controls a device.

Tested on Venus OS v3.75 (Raspberry Pi 5) with an Orion-Tr Smart 12/12-18 isolated and a
Blue Smart IP65 12|25. Installed with [SetupHelper](https://github.com/kwindrem/SetupHelper).

## Installation

With SetupHelper's PackageManager (Settings → PackageManager → Inactive packages → new):
package name `VenusOS-VictronBLE`, GitHub user `florent1080`, branch/tag `latest`.

Or by hand, as root on the GX device:

    cd /data && wget -qO - https://github.com/florent1080/VenusOS-VictronBLE/archive/latest.tar.gz | tar -xzf -
    mv /data/VenusOS-VictronBLE-latest /data/VenusOS-VictronBLE
    /data/VenusOS-VictronBLE/setup install

The first installation:
- creates an empty whitelist, `/data/conf/victron-ble.json`;
- turns the Venus OS **Bluetooth sensors** on (Settings → Integrations → Bluetooth sensors).
  Their passive scan is the lightest one and this package listens to it. This happens once:
  updates and the reinstalls after a Venus OS update never touch that setting again.

Everything lives in `/data`, so it survives Venus OS updates.

## 1. Enable Instant Readout and get the key (VictronConnect)

For each device, in the VictronConnect app, connected to the device over Bluetooth:

1. open the settings (gear icon), then the **⋮** menu, then **Product info**;
2. turn **Instant readout via Bluetooth** on (Blue Smart chargers: firmware v3.61 or later);
3. **Instant readout details → Show** displays the **MAC address** and the **encryption key**
   (32 hexadecimal characters).

The key is renewed when the device's Bluetooth PIN is changed or reset: copy it again then.
It only gives read access to the readings, but keep it private.

## 2. Whitelist the device

    /data/VenusOS-VictronBLE/victron-ble discover

lists every Victron device heard, with its model, signal and status, and suggests the command
to add the ones this package supports:

    /data/VenusOS-VictronBLE/victron-ble add FC:00:00:00:00:01 --name "Orion-Tr Smart"

The key is then asked without being displayed (it stays out of the shell history). `add`
refuses a key whose first byte differs from the one the device broadcasts, and a device whose
model is already published by another service (see *Duplicates*). The running service picks the
change up within seconds: no restart needed.

Other commands: `remove MAC`, `validate` (checks the file), `discover --all`, `discover --json`,
`decode` (decrypts recorded frames, for debugging). `victron-ble -h` lists them.

The whitelist can also be edited by hand; it is checked and reloaded on the fly, and a mistake
never stops the devices already published (the last valid version stays in use):

```json
{
  "version": 1,
  "timeout_s": 60,
  "log_level": "INFO",
  "scanner": "auto",
  "devices": [
    {"mac": "FC:00:00:00:00:01", "key": "<32 hex>", "type": "dcdc", "name": "Orion-Tr Smart"},
    {"mac": "CC:00:00:00:00:02", "key": "<32 hex>", "type": "charger", "name": "Blue Smart IP65"}
  ]
}
```

| Key | Meaning |
|---|---|
| `timeout_s` | after this many seconds without an advertisement, `/Connected` goes to 0 and the readings become invalid; the device stays listed (5 to 3600, default 60) |
| `log_level` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |
| `scanner` | `auto` (default, see below), `venus`, `bluez` or `none` |
| `devices[].type` | `dcdc` or `charger` |
| `devices[].name` | name shown in Venus OS, also editable from the GUI |
| `devices[].allow_duplicate` | `true` to publish a device despite a duplicate warning |

## What appears in Venus OS

Each device appears in Settings → Devices like a wired one. Its name can be changed there
(Device → Name) or from VRM; the new name is saved in the whitelist.

| D-Bus path | DC/DC converter | AC charger |
|---|---|---|
| `/Dc/0/Voltage` | output voltage | output 1 voltage |
| `/Dc/0/Current` | — (the Orion-Tr does not measure current) | output 1 current |
| `/Dc/1/*`, `/Dc/2/*` | — | outputs 2 and 3, three-output models only |
| `/Dc/In/V` | input voltage | — |
| `/NrOfOutputs` | — | number of outputs |
| `/Ac/In/L1/I` | — | AC input current, when the model reports it |
| `/State`, `/ErrorCode` | Victron codes | Victron codes |
| `/DeviceOffReason` | off-reason bit mask | — |
| `/Mgmt/Connection` | `Bluetooth (Instant Readout)` | same |
| `/DeviceInstance` | stable VRM instance, kept by localsettings (`/Settings/Devices/victronble_<mac>/ClassAndVrmInstance`) | same |

Not published: `/Mode` and relays (control paths), the charger temperature (Venus OS documents
`/Dc/0/Temperature` as the *battery* temperature), firmware version and serial number (not in
Instant Readout).

Venus OS uses a published charger like a wired one: for instance its power is counted in the
"DC system" figure of the overview.

## How it listens

The service never scans by itself unless it has to: it reads the Linux HCI monitor channel
(the one `btmon` uses), which only receives what the Bluetooth controller hears and cannot
send anything. The radio scan comes from:

- `scanner: auto` (default): the **Venus OS Bluetooth sensors** service (passive scan, about
  17 % of the time). If you turn them off, the service starts its own BlueZ discovery and stops
  it when you turn them back on. It reads that setting, never changes it.
- `venus`: never scan ourselves (devices go disconnected while the sensors are off).
- `bluez`: always our own BlueZ discovery (an active scan, 100 % of the time).

Advertisement monitors (BlueZ AdvertisementMonitor) are deliberately not used: on Venus OS 3.75,
registering one disables the brute-force protection of the GX's own Bluetooth PIN
(`vesmart-server` does not know the corresponding kernel event).

## Duplicates

A device already wired over VE.Direct (a SmartSolar, a BMV...) usually also broadcasts Instant
Readout. To avoid seeing it twice, a whitelisted device whose model is already published by
another D-Bus service is **not** published, with a warning in the log, unless its entry has
`"allow_duplicate": true` (what `victron-ble add --force` writes).

## Files and logs

| Path | Content |
|---|---|
| `/data/conf/victron-ble.json` | the whitelist (keys inside: mode 0600) |
| `/run/victron-ble/seen.json` | every Victron device heard, refreshed every 5 s (no key inside); read by `discover` |
| `/var/log/victron-ble/current` | service log (`tai64nlocal < /var/log/victron-ble/current`) |

## Troubleshooting

- **`discover` shows the device as "KEY REJECTED"**: the key changed (PIN modified or reset) or
  was mistyped. Copy it again from VictronConnect, `remove` then `add` the device.
- **"no Instant Readout frame"**: Instant Readout is off on the device (step 1).
- **Nothing heard at all**: check that Bluetooth is on (Settings → Bluetooth) and look at the
  log; `tools/venus-ble-diag.sh` (run as root) is a complete Bluetooth diagnostic.
- **A wired device is not published twice**: that is the duplicate protection (see above).

## Development

The tests run on any computer, without Bluetooth or Venus OS:

    python -m unittest discover -s tests -v

They include frames recorded on a van. To also check decryption with your own devices, put
their keys in `tests/fixtures/keys.local.json` (`{"MAC": "key"}`, ignored by git).

The service can replay recorded advertisements instead of listening, to exercise the whole
chain away from the devices:

    python src/main.py --replay frames.jsonl --config my.json --seen /tmp/seen.json

## Credits

The Instant Readout parsers are derived from
[victron_ble](https://github.com/keshavdv/victron-ble) 0.9.3 by keshavdv and contributors,
released under the Unlicense (see `src/parsers/LICENSE-victron_ble.txt`).
Thanks to [kwindrem](https://github.com/kwindrem) for SetupHelper.
