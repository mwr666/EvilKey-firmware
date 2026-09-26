# Air Mouse: design, implementation, and verification

Air Mouse is the QMI8658C feature added in EvilKey 0.3.0. Table Mouse is outside this release. It uses the onboard motion sensor for the pointer, the FT3168 touchscreen for buttons and scrolling, and native USB for a standard relative HID mouse. In Settings it appears between Diagnostics and USB & Storage; USB Tool remains last.

The Waveshare PCB V1 has a QMI8658C IMU at I2C address `0x6B`, an FT3168 touch controller, and native USB. The board runs the two I2C clients from the same board task. Air Mouse configures the accelerometer for ±2 g at 125 Hz. Entry calibration averages 60 gravity-vector samples while the user holds the key still. The pointer uses tilt relative to that neutral orientation, with a circular dead zone, low-pass smoothing, fractional pixel accumulation, and bounded HID deltas. Recalibration is available on the Air Mouse pointer settings screen.

Starting Air Mouse uses a one-shot RTC token followed by a software reset. The token is consumed at boot; the mode is not persisted in NVS. The USB role has its own development VID/PID, product name, and relative-mouse-only HID report descriptor. It does not enumerate CTAP, MSC, keyboard, consumer, or absolute-mouse interfaces. Incoming HID output is gated before the CTAP parser in this role. Exit releases the mouse buttons and restarts into the normal USB role.

The active LVGL page places tall left and right click zones across the top, with a vertical scroll strip between them. HOLD TO MOVE occupies the middle. SETTINGS and EXIT sit at the bottom and require uninterrupted three-second holds. The Air Mouse settings screen contains CALIBRATE (also a three-second hold), sensitivity levels 1–5, INVERT VERTICAL, and BACK TO MOUSE. Level 3 retains the accepted speed; inversion affects only HID Y. The two preferences persist in the separate `ws_airmouse` NVS namespace. Pointer reports and mouse buttons are disabled on this settings screen. The original FIDO approval and PIN hit regions remain unchanged.

The user confirmed the four cursor directions, diagonal movement, MOVE, clicks, scroll, pointer settings, and FIDO return on the final 0.3.0 image flashed to COM5. Extended neutral-drift, cable-reconnection, and endurance checks have not been reported. See [validation status](../firmware/VALIDATION.md).

## Interaction design

- The Air Mouse Settings page provides START. It is available from the normal FIDO USB role when the motion sensor and touch controller are ready. Starting reconnects USB in the mouse-only role; FIDO, Manager Drive, and USB Tool are inactive until EXIT.
- The active screen has tall LEFT and RIGHT click areas at the top and a vertical scroll strip between them. HOLD TO MOVE fills the middle. SETTINGS and EXIT are at the bottom and require uninterrupted three-second holds with progress feedback. Swipe navigation is disabled on this screen.
- Holding MOVE enables calibrated tilt steering. Tilt direction controls cursor direction; tilt magnitude controls speed, like an analog joystick. A second finger can click or scroll at the same time. Releasing MOVE immediately stops pointer reports and clears the fractional remainder.
- SETTINGS opens pointer options and releases mouse buttons. CALIBRATE requires a three-second hold while the key is still. Sensitivity has five levels; level 3 retains the accepted speed. INVERT VERTICAL changes only HID Y. BACK TO MOUSE returns to the controls.
- EXIT releases all buttons and reconnects the normal USB role. The Air Mouse role is a one-shot choice and is never stored as the startup role. Pointer preferences are stored separately from FIDO credentials and Manager settings.

## Hardware and source integration

- The firmware targets Waveshare PCB V1. V1 and V2 swap LCD CS and IMU interrupt pins, so interrupt-based changes must use the fitted board revision. QMI8658C is on the shared I2C bus at `0x6B`; FT3168 touch uses the same bus.
- `firmware/templates/port/ws_board.c` owns I2C bus 0 and polls touch. IMU reads run from that board task rather than as unsynchronized concurrent I2C transactions.
- `firmware/templates/port/ws_ui.h` defines page order and actions, `ws_ui.c` handles touch regions, and `ws_lvgl.c` renders the pages. Template changes must be regenerated into `EvilKeyV1/src/engine/board`.
- `firmware/EvilKeyV1/src/PicoFidoArduino.cpp` selects the distinct mouse-only USB descriptor and identity before enumeration. The USB Tool descriptor also advertises keyboard, consumer, system, and absolute mouse usages and must not be used for Air Mouse. `UsbTool.cpp` provides the low-level TinyUSB relative mouse transport pattern only; script execution and USB Tool state remain separate.
- Manager 1.1.6 exports the complete 0.3.0 project with the same Air Mouse USB definitions and source defaults as the tested firmware. Air Mouse pointer preferences are adjusted on the key.

## Verification and open checks

Host checks cover Settings order and hit regions, one-shot startup and exit, mouse-only descriptor shape, two-point touch acquisition, movement gating and release, click and scroll balance, IMU response, and unchanged FIDO security state. Source regeneration and partition fit are checked during the firmware build. The final firmware image and its hash are recorded in [validation status](../firmware/VALIDATION.md).

On the device, the user confirmed the controls, cursor directions and diagonals, pointer settings, and FIDO return after flashing the final 0.3.0 image. Extended neutral drift, precisely timed simultaneous two-finger actions, reset and cable-reconnection cycles, prolonged use, and BOOT/RESET recovery from the mouse role were not separately measured.

## Implementation history

The first physical Air Mouse run revealed two regressions: touches did not activate controls, and cursor motion was rotated by a quarter turn with too little travel. An intermediate gyro candidate mapped GX to horizontal HID X and GY to vertical HID Y, increased sensitivity with angular speed, and raised the per-report delta limit. The active mouse screen bypasses the normal display wake-tap filter because it stays awake; intermittent touch I2C errors no longer permanently disable touch in this role. The status line distinguishes touch sensor errors from touches outside the control zones. Later candidates replaced the gyro steering with accelerometer tilt.

A further device observation found that diagonal wrist motion moved the pointer on only one axis. The previous pointer transform removed a separate 1.2 dps dead zone from each gyro axis and computed gain independently. An intermediate candidate applied one radial dead zone and one gain to the two-axis vector, preserving a weaker secondary component and its direction. The final tilt implementation retains a shared radial response; the user confirmed diagonal motion on the device.

The next touch change added a central HOLD TO MOVE control. Cursor deltas are produced only while it is touched. Releasing it clears fractional pixel accumulation, so movement stops immediately. The FT3168 is specified for two touch points; the Air Mouse role reads the second contact from registers `0x09..0x0C`, while the FIDO UI retains its original single-contact read. The second finger selects LEFT, RIGHT, or SCROLL independently of HOLD TO MOVE. The user confirmed MOVE, click, and scroll operation on the final image; a separate simultaneous two-finger timing test was not recorded.

The final steering design changed the pointer from angular-rate motion to analog-style tilt velocity. Calibration establishes a neutral gravity direction. Two orthogonal axes tangent to that direction are projected from the screen orientation; a shared radial dead zone and gain keep diagonal movement proportional in both axes. The second touch point supplies the scroll Y coordinate even when the MOVE finger is reported first. The Air Mouse Settings description uses three short explicit lines, and START uses the same dark control style as the other Settings buttons. Direction and diagonal operation were confirmed on the device; extended neutral stability was not measured.

The first physical test of tilt velocity showed a 90-degree cursor rotation: key left moved the cursor up, key right moved it down, key up moved it right, and key down moved it left. The USB cursor vector now uses `(tilt_y, -tilt_x)` after the shared radial response. This maps the observed physical right and down directions to HID right and down without changing diagonal gain. After flashing the corrected image to COM5, the user reported that four-way direction, diagonal movement, MOVE, click/scroll, and return to FIDO all work. Extended neutral-drift, reset, and cable-reconnection checks remain open.

The active mouse page gained a guarded SETTINGS control in place of CALIBRATE. The new Air Mouse settings page has a guarded CALIBRATE action, five sensitivity steps, and an INVERT VERTICAL toggle. The two preferences are stored as a small validated NVS record in the `ws_airmouse` namespace, separate from credentials and Manager settings. The user confirmed that these controls work on the 0.3.0-dev image; persistence through a full restart has not been specifically confirmed.

## Hardware sources

- [Waveshare board documentation](https://docs.waveshare.com/ESP32-S3-Touch-AMOLED-1.64): PCB revision, shared I2C bus, touch, IMU, and native USB.
- [FT3168 datasheet](https://files.waveshare.com/wiki/common/DATA_SHEET_FT3168.pdf): two-touch capability.
- [QMI8658C datasheet](https://files.waveshare.com/wiki/common/QMI8658C_datasheet_rev_0.9.pdf): accelerometer configuration and registers.
- [Espressif ESP32-S3 memory types](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/memory-types.html) for RTC no-init storage across software restart.
