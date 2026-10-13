# Validation — firmware 0.7.6

[Release notes](RELEASE_0.7.6.md) and [RELEASE_CURRENT.json](../RELEASE_CURRENT.json)
identify the released BIN, source, ABI versions and supported hardware.
The exact image passed application/partition readback and protected-storage
preservation on Waveshare PCB V1.0. No partition migration was required.

Source export checks cover generated-file/SDK integrity, UTF-8, documentation
links, release checksums and component/license separation. Software checks
do not extend the hardware compatibility or production security scope.
A rebuild creates a new artifact; verify its hash and behavior before use.

Current source uses Arduino-ESP32 3.3.12 with Os. The separate
[native app qualification](ABI5_QUALIFICATION.md) describes scene limits.

PCB V1.1, battery/Wi-Fi operation, sustained concurrent CTAP load, long-duration
endurance and production security hardening remain unqualified.
