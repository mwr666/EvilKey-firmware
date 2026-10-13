# Validation - firmware 0.8.0

[Release notes](RELEASE_0.8.0.md) and [RELEASE_CURRENT.json](../RELEASE_CURRENT.json)
identify the exact PCB V1 and V1.1 release images and supported ABI versions.
Both images passed application/partition readback and unchanged nvs, wsdev,
part0 and otadata digests, followed by functional checks of version, interface,
FIDO/PIN, usual functions and data availability. V1.1 includes IMU/Gamepad after
BLE connection. Confirmed V1.1 compatibility begins with this release.

Host checks cover both PCB profiles, linked storage guards, preserving/fresh
installer cancellation and failure, artifact identity and packaging rejection.
They also cover Gamepad, USB/BLE AirMouse, Settings and Apps IMU paths. Software
checks, readback and physical functional checks establish different facts.

Source export checks cover generated LF hashes, SDK, encoding/links, public
packaging and component/license separation. Rebuilding creates a new artifact;
verify its identity and behavior before use. The exact published BINs retain
their recorded acceptance rather than inheriting it from a version label.

Long-duration endurance, sustained concurrent CTAP loads, battery/Wi-Fi and
console/XInput compatibility remain unqualified. Firmware remains a development
configuration, without a new security-hardening or FIDO-certification claim.
V1.1 firmware support does not qualify the printed V1 enclosure fit. Historical
video and performance conditions remain unchanged.

See [native app qualification](ABI5_QUALIFICATION.md) for rendering limits.
