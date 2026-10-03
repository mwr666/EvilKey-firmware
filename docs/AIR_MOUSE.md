# AirMouse

Open **Settings → AirMouse**, choose **USB** or **BLE**, then Start.
Hold the key still during calibration. USB uses a mouse-only USB role;
BLE uses a separately paired mouse profile. Exit returns to normal FIDO.

## Controls

| Control | Action |
| --- | --- |
| MOVE | Hold to move the pointer by tilting the key; release or leave the zone to stop |
| LEFT / RIGHT | Momentary mouse buttons |
| DRAG | Tap to hold left and enable motion; tap again to release and stop |
| SCROLL | Slide along the central vertical strip |
| SETTINGS | Hold for three seconds to open pointer settings |
| EXIT | Hold for three seconds to return to FIDO |

Holding MOVE releases an active drag and returns to momentary movement.
A normal RIGHT press also releases drag. DRAG is visible on screen and is not
remembered after exit. Settings, disconnection and input faults release buttons
and stop movement. Lift the finger before resuming after entry or a fault.

Pointer settings provide calibration, sensitivity levels 1–5 and vertical
inversion. BLE also offers Pair/Connect and confirmed Forget Pairing.
The tested touch panel reports one contact; drag therefore works with one finger.

The QMI8658C accelerometer supplies tilt relative to a calibrated neutral
orientation. A shared radial dead zone and smoothing preserve diagonal movement.
Pointer preferences use `ws_airmouse`, separately from FIDO credentials.
See [BLE pairing and radio lifecycle](BLE_CONTROLS.md).
