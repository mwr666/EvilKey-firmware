#!/usr/bin/env python3
"""Source transformations for the pinned 0.2.x FIDO-only Arduino port.

Each change has a unique anchor. Neither cryptography nor attestation is changed.
This module also handles already-generated relative-include trees.
"""
from __future__ import annotations
import re

PATCH_MARKER = "PF_PROFILE_PATCH_023"

def one(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"Profile patch anchor not unique: {old[:90]!r}")
    return text.replace(old, new, 1)

def function_replace(text: str, name: str, replacement: str) -> str:
    matches = list(re.finditer(r"(?m)^(?:static\s+)?[\w *]+\b" + re.escape(name) +
                              r"\([^;{}]*\)\s*\{", text))
    if len(matches) != 1: raise RuntimeError(f"Function not unique: {name}")
    m = matches[0]
    brace = text.find("{", m.start(), m.end())
    depth = 0
    scanner = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    for token in scanner.finditer(text, brace):
        if token.group() == "{": depth += 1
        elif token.group() == "}":
            depth -= 1
            if depth == 0:
                return text[:m.start()] + replacement.rstrip() + text[token.end():]
    raise RuntimeError(f"Unbalanced function: {name}")

def patch_hid(text: str) -> str:
    if PATCH_MARKER in text: raise RuntimeError("HID profile patch already applied")
    anchor = ("            resp->versionMajor = get_version_major ? get_version_major() : PICOKEYS_SDK_VERSION_MAJOR;\n"
              "            resp->versionMinor = get_version_minor ? get_version_minor() : PICOKEYS_SDK_VERSION_MINOR;")
    replacement = ("            /* " + PATCH_MARKER + ": only management/transport compatibility. */\n"
                   "#if PF_YK5_FIDO_COMPAT\n"
                   "            resp->versionMajor = PF_COMPAT_VERSION_MAJOR;\n"
                   "            resp->versionMinor = PF_COMPAT_VERSION_MINOR;\n"
                   "            resp->versionBuild = PF_COMPAT_VERSION_PATCH;\n"
                   "#else\n" + anchor + "\n"
                   "            resp->versionBuild = 0; /* Initialize every response, not stale buffer data. */\n"
                   "#endif")
    return one(text, anchor, replacement)

def patch_management(text: str) -> str:
    if PATCH_MARKER in text: raise RuntimeError("Management profile patch already applied")
    text = function_replace(text, "cap_supported", r"""bool cap_supported(uint16_t cap) {
    /* PF_PROFILE_PATCH_023: compile-time FIDO-only capabilities win over stale EF_DEV_CONF.
     * The old stored record is not erased or modified. */
    return (cap & PF_PROFILE_CAPABILITIES) != 0;
}""")
    text = function_replace(text, "man_get_config", r"""int man_get_config(void) {
    /* A complete bounded management read-info response; no unsupported applets. */
    const size_t n = pf_profile_build_management_info(res_APDU, 64, pico_serial.id);
    if (n == 0) {
        res_APDU_size = 0;
        return PICOKEYS_ERR_MEMORY_FATAL;
    }
    res_APDU_size = (uint16_t)n;
    return PICOKEYS_OK;
}""")
    # Management writes over HID already return INVALID_CMD in this engine.
    # Also reject the APDU variant instead of persisting unapplied/unsupported settings.
    text = function_replace(text, "cmd_write_config", r"""static int cmd_write_config(void) {
    /* USB/application capabilities are configured in code, not by this read-only adapter. */
    return SW_INS_NOT_SUPPORTED();
}""")
    return text

def patch_cbor(text: str) -> str:
    if PATCH_MARKER in text: raise RuntimeError("CBOR profile patch already applied")
    return one(text, "        else if (cmd == 0xC2) {",
        "        else if (cmd == 0xC2) {\n"
        "            /* PF_PROFILE_PATCH_023: only management page zero exists. */\n"
        "            const int page_error = pf_profile_check_management_page(data, len);\n"
        "            if (page_error != 0) return page_error;")

def patch_button(text: str) -> str:
    if PATCH_MARKER in text: raise RuntimeError("Button profile patch already applied")
    return one(text, "    const uint32_t button_timeout = 30000;",
        "    /* PF_PROFILE_PATCH_023: configurable deadline, never automatic approval. */\n"
        "    const uint32_t button_timeout = (uint32_t)FIDO_V1_PRESENCE_TIMEOUT_SECONDS * 1000u;")

TRANSFORMS = {
    "sdk/src/usb/hid/hid.c": patch_hid,
    "fido/src/fido/management.c": patch_management,
    "fido/src/fido/cbor.c": patch_cbor,
    "sdk/src/button.c": patch_button,
}
