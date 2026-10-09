# Validation — firmware 0.7.5

[Release notes](RELEASE_0.7.5.md) identify the exact accepted image and the
software checks completed before release. [RELEASE_CURRENT.json](../RELEASE_CURRENT.json)
records its size, SHA-256, ABI versions, compiler profile and hardware scope.

The 2026-10-09 installation verified application readback and unchanged protected
storage. The owner confirmed correct GUI, Apps and FIDO/PIN behavior on PCB V1.0.
This is acceptance of the published BIN, not automatic acceptance of rebuilt images.

The public source export is checked for generated-file/SDK integrity, UTF-8,
documentation links, release checksums and component/license separation.
No new full Arduino build from this split public checkout is claimed.

PCB V1.1, battery/Wi-Fi operation, sustained concurrent CTAP load, long-duration
endurance and production security hardening remain unqualified. Native 3D app
performance requires its own [app qualification](ABI5_QUALIFICATION.md).

[0.6.1 historical release notes](RELEASE_0.6.1.md) describe the earlier artifact.
