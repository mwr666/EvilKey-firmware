# Validation - firmware 0.8.1

[Release notes](RELEASE_0.8.1.md) and [RELEASE_CURRENT.json](../RELEASE_CURRENT.json)
identify the exact PCB V1 and V1.1 release images. Both passed full builds,
linked NVS erase guards, application/table readback and unchanged protected
nvs, otadata, part0 and wsdev digests. SD was not accessed during installation.
The owner confirmed UI startup and several Race laps without freezes on each
board. Exact duration/FPS and new credential authentication were not measured.

Host checks cover normal/missing/late/stale display completion, buffer ownership,
healthy rendering paths, both PCB profiles, storage guards, preserving/fresh
installer cancellation/failure and packaging rejection. Public source checks
cover generated LF hashes, locked overlay integration, SDK, documentation
links, component separation and exact release images. Rebuilds require their
own artifact validation; source export does not promise identical binaries.

V1.1 compatibility begins with 0.8.0; its [notes](RELEASE_0.8.0.md) preserve the
previous broader functional scope. Firmware remains a development configuration:
no Secure Boot/flash/NVS provisioning, FIDO certification, physical-extraction
resistance, quantitative performance or long-duration endurance claim is added.
The V1 enclosure and historical videos keep their existing labels.

See [native app qualification](ABI5_QUALIFICATION.md) for retained rendering limits.
