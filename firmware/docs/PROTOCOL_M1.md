# M1 display/settings protocol — version 1

Implementation-specific protocol for the Arduino Waveshare V1 port 0.2.6.
This document describes the new code in this package, not a FIDO Alliance
standard or a statement of conformance certification.

## Transport and authorization

Use the existing FIDO HID CTAPHID.CBOR transport. The CTAP command is
`authenticatorConfig` (`0x0d`), subcommand `0xff` (vendor prototype).
No new USB interface, COM port, keyboard, CCID, WebUSB or network server is added.

Obtain a fresh PIN/UV token with **ACFG (0x20)** only. No RP scope is supplied.
The app defaults to the built-in UV path and the physical numeric panel, but
also supports standard ClientPIN for a PIN entered on the PC. PIN protocol 2 is
preferred when advertised; protocol 1 is explicitly selectable. A failure is
never used as a reason to downgrade automatically or consume another PIN retry.

CTAP request map:

| Key | Value |
|---|---|
| 1 | `0xff` |
| 2 | Subcommand parameters, as below |
| 3 | PIN/UV protocol, 1 or 2 |
| 4 | `pinUvAuthParam`, computed by that protocol |

Authenticated bytes are the standard Config context:
`0xff * 32 || 0x0d || 0xff || canonical_CBOR(subcommand_parameters)`.
Use python-fido2's `PinProtocol.authenticate`; this package does not implement a
new cryptographic primitive in the PC app.

The new handler is included **after** the existing Config protocol, HMAC and
ACFG-permission checks. It additionally requires a live, user-verified token,
no RP scope and an initial token age of at most 30,000 ms. Before processing the
M1 request, it removes ACFG permission and invalidates the object-authorization
session. The app obtains a new token for each M1 operation. This is not a claim
that all legacy CTAP token lifecycle semantics have been redesigned.

## Vendor IDs and parameters

Read:

```
{1: 0x50464d3100000001}
```

Write:

```
{1: 0x50464d3100000002, 2: <32-byte settings record>}
```

Additional vendor integer/text parameters are rejected. Read with a settings
record and write without a record are rejected. A read never creates a settings
record in NVS. The first successful write creates one.

## Settings record (32 bytes)

All multibyte integers are unsigned **big endian**. This is not a raw C struct.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | ASCII `PFM1` |
| 4 | 1 | Schema version `1` |
| 5 | 1 | Normal brightness, 8–255 |
| 6 | 1 | Dim brightness, 1–32 and no greater than normal brightness |
| 7 | 1 | Animation: exactly 0 or 1 |
| 8 | 2 | Idle-to-dim seconds: 0 or 5–3600 |
| 10 | 2 | Dim-to-off seconds: 0 or 5–3600 |
| 12 | 2 | Presence/approve timeout seconds: 1–120 |
| 14 | 2 | Panel PIN timeout seconds: 15–120 |
| 16 | 4 | Accent `0x00RRGGBB` |
| 20 | 4 | Settings revision |
| 24 | 8 | Reserved: all zero |

A zero idle-to-dim interval disables dimming and blanking. A zero dim-to-off
interval leaves the screen dim rather than blank. Touch availability and active
prompts retain the existing UI1 wake/fail-safe behavior. Accent brightness is
bounded by `299*R + 587*G + 114*B >= 128000`, a practical readability constraint,
not a claim of formal color-contrast accessibility certification.

## Response

Canonical CBOR map, keys in ascending integer order:

| Key | Value |
|---|---|
| 1 | M1 API version: 1 |
| 2 | Effective 32-byte settings record |
| 3 | Port release string: `0.2.6-dev` |
| 4 | Boolean storage-health result |
| 5 | Build flags: bit 0 local UV, bit 1 touch confirmation, bit 2 BOOT fallback, bit 3 display |

Build flags describe compile-time availability. They do not assert that a
particular panel has passed a physical I/O test. The response does not include
PINs, tokens, credential identifiers, private keys or stored account metadata.

## Commit and concurrency

The record supplied by the writer contains the **previous expected revision**,
obtained in an authenticated read. A mutex serializes M1 writes. The firmware
checks revision equality before committing and rejects `UINT32_MAX` to avoid
wraparound. On success, the persisted and returned revision is incremented.

Only `wsdev / pf_manager / ui_v1` is accessed. Existing keystore namespace
`pico_fido`, retry records and the credential partition are not accessed by the
M1 store. There is no partition erase, reformat or eFuse operation in this API.

The entire record is written with `nvs_set_blob`, committed with `nvs_commit`,
and read back for byte comparison. Only then is the public RAM snapshot updated
and success returned. RTOS critical sections cover short RAM copies, never NVS
I/O. A failed commit or readback reports an error, not a false success. A
post-commit error can mean the record is already persistent despite missing
acknowledgement; the caller must re-read or power-cycle and re-read before
another deliberate write. There is no automatic retry.

An absent record uses validated compile-time defaults. A corrupt/unreadable
record uses safe defaults and reports storage health as false. The app may
explicitly write a validated replacement; it does not silently reformat NVS.

## Error mapping

Invalid record/parameters: `CTAP1_ERR_INVALID_PARAMETER`.
Missing record: `CTAP2_ERR_MISSING_PARAMETER`.
Stale/overflowed revision: `CTAP2_ERR_NOT_ALLOWED`.
Store/commit/readback failure: `CTAP2_ERR_PROCESSING`.
Inactive, unverified, RP-scoped, old or unauthorized token:
`CTAP2_ERR_PIN_AUTH_INVALID`.

A lost Windows handle/WinError 1167 is a transport failure, not proof of the
result of a write. The application invalidates cached settings and does not
resend the command automatically.

## Verification boundaries

Host tests exercise the actual codec, storage implementation with NVS/RTOS
substitutes, and the M1 inner handler with mocked CBOR/HMAC surrounding code.
They do not establish FIDO conformance, Windows HID correctness, power-loss
atomicity of physical flash or interoperability of a linked ESP32 binary.
