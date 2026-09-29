#!/usr/bin/env python3
"""Generate a self-contained Arduino source tree from locked upstream revisions.

Python 3.10+, Git, Internet for first preparation. No ESP-IDF installation,
CMake, pip packages, device connection, flashing, or eFuse operations required.
Only the generated src/engine directory is produced. Existing output is kept.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent
LOCK = json.loads((ROOT / "UPSTREAM_LOCK.json").read_text(encoding="utf-8"))
REPOS = {
    "fido": ("https://github.com/polhenarejos/pico-fido.git", LOCK["pico_fido_commit"]),
    "sdk": ("https://github.com/polhenarejos/pico-keys-sdk.git", LOCK["pico_keys_sdk_commit"]),
    "crypto": ("https://github.com/polhenarejos/mbedtls.git", "fc39404125e93ee00e6758605e6c6f2c8db440f1"),
    "cbor": ("https://github.com/intel/tinycbor.git", "c0aad2fb2137a31b9845fbaae3653540c410f215"),
    "lvgl": ("https://github.com/lvgl/lvgl.git", LOCK["lvgl_commit"]),
    "ducky": (LOCK["s3_ducky_url"], LOCK["s3_ducky_commit"]),
}
# Chosen from the ESP branch of the pinned Pico Keys CMake source list.
SDK_SOURCES = """main.c usb/usb.c fs/file.c fs/vault_container.c fs/object_store.c
fs/object_store_txn.c fs/object_container.c fs/object_container_store.c
fs/object_policy.c fs/object_crypto_provider.c fs/flash.c fs/low_flash.c fs/phy.c
otp/otp.c otp/otp_esp32.c rng/random.c rng/hwrng.c eac.c crypto_utils.c tlv.c
debug.c apdu.c rescue.c serial.c pico_time.c button.c led/led.c signal.c vault.c
usb/hid/hid.c""".split()
FIDO_SOURCES = """fido.c object_authorization.c object_provider.c resident_container.c
files.c cmd_register.c cmd_authenticate.c cmd_version.c cbor.c cbor_reset.c
cbor_get_info.c cbor_make_credential.c known_apps.c cbor_client_pin.c credential.c
cbor_get_assertion.c cbor_selection.c cbor_cred_mgmt.c cbor_config.c cbor_vendor.c
fido_vault.c cbor_large_blobs.c management.c defs.c""".split()
CBOR_SOURCES = ["cborencoder.c", "cborparser.c", "cborparser_dup_string.c"]
C_TOKENS = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[A-Za-z_]\w*', re.S)
INCLUDE = re.compile(r'(?m)^(\s*#\s*include\s*)[<"]([^>"\n]+)[>"]([^\n]*)$')

# These are platform-owned PSA Internal Trusted Storage (ITS) headers, NOT
# missing headers from the private Mbed TLS distribution. In the locked sources
# the includes occur in the native-ITS #else branch, inside an optional module.
# Keep the compiler's conditional evaluation: replace only these unresolved
# includes with a hard #error in that SAME branch. Inactive branches compile;
# activating native ITS fails explicitly, without using Arduino's PSA headers
# or introducing empty headers / fake storage implementations.
NATIVE_ITS_HEADERS = frozenset({
    "psa/error.h", "psa/internal_trusted_storage.h",
})
NATIVE_ITS_CONSUMERS = frozenset({
    "psa_crypto_se.c", "psa_crypto_storage.c",
})
NATIVE_ITS_ERROR = "PICO_FIDO_NATIVE_PSA_ITS_UNSUPPORTED"



def run(args: list[str], cwd: Path | None = None) -> str:
    print("+", " ".join(args), flush=True)
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def verify_repo(path: Path, sha: str) -> None:
    if run(["git", "rev-parse", "HEAD"], path) != sha:
        raise RuntimeError(f"Wrong revision in {path}; no automatic reset is performed")
    run(["git", "diff", "--exit-code", "--ignore-submodules=all", "HEAD", "--"], path)
    if run(["git", "ls-files", "--others", "--exclude-standard"], path):
        raise RuntimeError(f"Untracked files in cache {path}; use a clean dedicated cache")


def checkout(cache: Path, name: str, offline: bool) -> Path:
    path = cache / name
    url, sha = REPOS[name]
    if not path.exists():
        if offline:
            raise RuntimeError(f"Missing offline cache: {path}")
        path.mkdir(parents=True)
        run(["git", "init", "--quiet"], path)
        run(["git", "config", "core.autocrlf", "false"], path)
        run(["git", "remote", "add", "origin", url], path)
        run(["git", "fetch", "--depth", "1", "origin", sha], path)
        run(["git", "checkout", "--detach", "FETCH_HEAD"], path)
    verify_repo(path, sha)
    return path


def one(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {text.count(old)}")
    return text.replace(old, new, 1)


def function_replace(text: str, name: str, replacement: str) -> str:
    """Replace a C function with a brace-aware scan ignoring strings/comments."""
    matches = list(re.finditer(r"(?m)^(?:static\s+)?[\w *]+\b" + re.escape(name) +
                               r"\([^;{}]*\)\s*\{", text))
    if len(matches) != 1:
        raise RuntimeError(f"Cannot uniquely locate function {name}")
    start = matches[0].start()
    brace = text.find("{", matches[0].start(), matches[0].end())
    depth = 0
    scanner = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    for token in scanner.finditer(text, brace):
        t = token.group()
        if t == "{": depth += 1
        elif t == "}":
            depth -= 1
            if depth == 0:
                return text[:start] + replacement.rstrip() + text[token.end():]
    raise RuntimeError(f"Unbalanced function {name}")



# The SDK event header and Newlib's system signal.h both use _SIGNAL_H_.
# Arduino's SDK headers may include the latter before Pico Keys' event header.
SIGNAL_HEADER_BLOB_SHA1 = "c52b017e1bfffc9f645269523d399142d79439c9"
SIGNAL_HEADER_GUARD = "PICOKEYS_SDK_SIGNAL_H_INCLUDED"


def patch_signal_header(text: str) -> str:
    """Separate the Pico Keys event guard from the C library signal guard.

    Do not undefine the system guard, replace system headers, remove event
    declarations, or add fake implementations. Keep the event API unchanged.
    """
    text = one(text, "#ifndef _SIGNAL_H_", "#ifndef " + SIGNAL_HEADER_GUARD,
               "signal.h opening guard")
    text = one(text, "#define _SIGNAL_H_",
               "#define " + SIGNAL_HEADER_GUARD + "\n\n#include <stdint.h>",
               "signal.h guard and uint32_t declaration")
    text = one(text, "#endif // _SIGNAL_H_", "#endif // " + SIGNAL_HEADER_GUARD,
               "signal.h closing comment")
    return text


def private_crypto(text: str) -> str:
    """Namespace source-level identifiers, NEVER strings, include paths or comments.

    A private software Mbed TLS copy avoids the incompatible precompiled Arduino
    Mbed TLS ABI and duplicate symbols. Algorithm statements are unchanged.
    """
    def convert(m: re.Match[str]) -> str:
        s = m.group()
        if s.startswith(("mbedtls_", "psa_", "mbedtls_svc_")): return "pf_" + s
        if s.startswith(("MBEDTLS_", "PSA_")): return "PF_" + s
        return s
    return C_TOKENS.sub(convert, text)


def upstream_path(roots: dict[str, Path], relative: str) -> Path:
    if relative.startswith("pico-keys-sdk/"):
        return roots["sdk"] / relative.removeprefix("pico-keys-sdk/")
    return roots["fido"] / relative


def make_patches(roots: dict[str, Path]) -> dict[Path, str]:
    spec = importlib.util.spec_from_file_location("base_port", ROOT / "tools/base_port.py")
    assert spec and spec.loader
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    original = {}
    for relative, sha in LOCK["upstream_git_blob_sha1"].items():
        raw = upstream_path(roots, relative).read_bytes()
        if base.git_blob_hash(raw) != sha:
            raise RuntimeError(f"Unexpected original source: {relative}")
        original[relative] = raw.decode("utf-8")
    modified = base.patch_files(original)
    patches = {upstream_path(roots, name): value for name, value in modified.items()}
    # Use a pinned original even when the user's older UPSTREAM_LOCK.json
    # does not yet list signal.h. The cache is read-only; patch generated output.
    signal_header = roots["sdk"] / "src/signal.h"
    raw = signal_header.read_bytes()
    if base.git_blob_hash(raw) != SIGNAL_HEADER_BLOB_SHA1:
        raise RuntimeError("Unexpected original source: pico-keys-sdk/src/signal.h")
    patches[signal_header] = patch_signal_header(raw.decode("utf-8"))
    path = roots["sdk"] / "src/main.c"
    s = patches[path]
    s = one(s, '#include "tinyusb.h"\n', '', "main: no IDF TinyUSB driver")
    s = one(s, '#include "ws_board.h"', '#include "ws_board.h"\n#include "ws_usb_tool_state.h"\n#include "pf_engine_api.h"\nstatic void pf_service_usb_state(void);', "main API")
    s = one(s, '        execute_tasks();', '        pf_service_usb_state();\n        execute_tasks();', "main event task")
    anchor = '#ifdef ESP_PLATFORM\nextern tinyusb_config_t tusb_cfg;'
    if s.count(anchor) != 1: raise RuntimeError("main startup anchor changed")
    s = s[:s.index(anchor)] + (ROOT / "templates/engine_entry.c.inc").read_text(encoding="utf-8")
    patches[path] = s
    path = roots["sdk"] / "src/usb/usb.c"
    s = function_replace(patches[path], "usb_init", (ROOT / "templates/usb_init.c.inc").read_text(encoding="utf-8"))
    # Arduino's stock TinyUSB supplies standard HID; no custom class driver hook.
    s = function_replace(s, "usbd_app_driver_get_cb", "/* Native standard HID; no extra class driver. */")
    s = function_replace(s, "card_start", (ROOT / "templates/card_worker.c.inc").read_text(encoding="utf-8"))
    s = one(s, '#ifdef ESP_PLATFORM\n        hcore1 = NULL;\n#endif',
            '#ifdef ESP_PLATFORM\n        /* The statically-backed dispatcher persists between CTAP1/CTAP2 loops. */\n#endif',
            "persistent ESP card worker")
    patches[path] = s
    path = roots["sdk"] / "src/usb/usb.h"
    s = path.read_text(encoding="utf-8")
    s = one(s, "extern void card_start(uint8_t, void *(*func)(void *));",
            "extern bool card_start(uint8_t, void *(*func)(void *));",
            "card worker launch result")
    patches[path] = s
    path = roots["sdk"] / "src/usb/hid/hid.c"
    s = path.read_text(encoding="utf-8")
    s = one(s, 'extern void init_fido(void);',
            'extern bool pf_air_mouse_role(void);\nextern void init_fido(void);',
            "Air Mouse HID security boundary")
    # Keep the CTAP state machine, but remove its second TinyUSB initialization.
    old = s[s.index('int driver_init_hid(void) {'):]
    stop = old.index('    ctap_req =')
    replacement = 'int driver_init_hid(void) {\n    /* USB is started once by Arduino. */\n'
    s = one(s, old[:stop], replacement, "hid: sole TinyUSB owner")
    # Invalid HID instances must not enter the upstream arrays.
    signature = 'void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id, hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {'
    s = one(s, signature, signature + '\n    /* A mouse-only USB role never accepts CTAP packets, even if a host sends 64 raw bytes. */\n    if (pf_air_mouse_role()) return;\n    /* USB Tool owns non-CTAP output reports (for example keyboard LEDs). */\n    if (hid_set_report_cb && hid_set_report_cb(itf, report_id, report_type, buffer, bufsize) != 0) return;\n    if (itf != 0 || report_id != 0 || !buffer || bufsize != 64) return;', "hid input guard")
    s = one(s, '                card_start(ITF_HID, apdu_thread);',
            '                if (!card_start(ITF_HID, apdu_thread)) return ctap_error(CTAP1_ERR_OTHER);',
            "CTAP1 worker launch failure")
    s = one(s, '                card_start(ITF_HID, cbor_thread);',
            '                if (!card_start(ITF_HID, cbor_thread)) return ctap_error(CTAP1_ERR_OTHER);',
            "CTAP2 worker launch failure")
    patches[path] = s
    path = roots["sdk"] / "src/compat/esp_compat.h"
    s = path.read_text(encoding="utf-8")
    s = one(s, '#include "freertos/task.h"', '#include "freertos/task.h"\n#include "freertos/semphr.h"', "ESP semaphore declarations")
    s = one(s, '4096*ITF_TOTAL*2', '16384', 'core1 S2 stack allocation')
    patches[path] = s
    # Stop cleanly on missing/unmappable storage instead of dereferencing NULL.
    path = roots["sdk"] / "src/fs/low_flash.c"
    s = path.read_text(encoding="utf-8")
    s = one(s, '    part0 = esp_partition_find_first(0x40, 0x1, "part0");',
            '    part0 = esp_partition_find_first(0x40, 0x1, "part0");\n    if (!part0) abort();', "storage guard")
    old = '    esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA, (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map);\n    data_start_addr = 0;'
    new = '    if (esp_partition_mmap(part0, 0, part0->size, ESP_PARTITION_MMAP_DATA, (const void **)&map, (esp_partition_mmap_handle_t *)&fd_map) != ESP_OK) abort();\n    data_start_addr = 0;'
    s = one(s, old, new, "storage mapping guard")
    patches[path] = s
    path = roots["sdk"] / "config/mbedtls_config.h"
    s = path.read_text(encoding="utf-8")
    alt_names = sorted(set(re.findall(r"\bMBEDTLS_[A-Z0-9_]+_ALT\b", s)))
    # The Arduino core's hardware crypto ABI is not used by the private copy.
    disable = alt_names + ["MBEDTLS_PLATFORM_MEMORY", "MBEDTLS_PLATFORM_NO_STD_FUNCTIONS",
        "MBEDTLS_PLATFORM_CALLOC_MACRO", "MBEDTLS_PLATFORM_FREE_MACRO",
        "MBEDTLS_PLATFORM_STD_CALLOC", "MBEDTLS_PLATFORM_STD_FREE",
        "MBEDTLS_USE_PSA_CRYPTO", "MBEDTLS_AESNI_C", "MBEDTLS_AESCE_C"]
    s += "\n/* Arduino port: private portable crypto; libc allocation, own entropy. */\n"
    s += "\n".join("#undef " + name for name in sorted(set(disable))) + "\n"
    s += "#define MBEDTLS_ENTROPY_HARDWARE_ALT\n#define MBEDTLS_PLATFORM_C\n"
    patches[path] = s
    profile_spec = importlib.util.spec_from_file_location("profile_patch", ROOT / "tools/profile_patch.py")
    assert profile_spec and profile_spec.loader
    profile = importlib.util.module_from_spec(profile_spec)
    profile_spec.loader.exec_module(profile)
    for relative, transform in profile.TRANSFORMS.items():
        repo, path_name = relative.split("/", 1)
        path = roots[repo] / path_name
        original_text = patches.get(path)
        if original_text is None:
            original_text = path.read_text(encoding="utf-8")
        patches[path] = transform(original_text)
    touch_spec = importlib.util.spec_from_file_location("touch_patch", ROOT / "tools/touch_patch.py")
    assert touch_spec and touch_spec.loader
    touch = importlib.util.module_from_spec(touch_spec)
    touch_spec.loader.exec_module(touch)
    for relative, transform in touch.TRANSFORMS.items():
        repo, name = relative.split("/", 1)
        p = roots[repo] / name
        patches[p] = transform(patches.get(p, p.read_text(encoding="utf-8")))
    manager_spec = importlib.util.spec_from_file_location("manager_source", ROOT / "tools/manager_source.py")
    assert manager_spec and manager_spec.loader
    manager = importlib.util.module_from_spec(manager_spec)
    manager_spec.loader.exec_module(manager)
    for relative, transform in manager.TRANSFORMS.items():
        repo, name = relative.split("/", 1)
        p = roots[repo] / name
        patches[p] = transform(patches.get(p, p.read_text(encoding="utf-8")))
    ducky3_spec = importlib.util.spec_from_file_location("ducky3_hid_patch", ROOT / "tools/ducky3_hid_patch.py")
    assert ducky3_spec and ducky3_spec.loader
    ducky3 = importlib.util.module_from_spec(ducky3_spec)
    ducky3_spec.loader.exec_module(ducky3)
    for relative, transform in ducky3.TRANSFORMS.items():
        repo, name = relative.split("/", 1)
        p = roots[repo] / name
        patches[p] = transform(patches.get(p, p.read_text(encoding="utf-8")))
    return patches


def source_plan(roots: dict[str, Path]) -> tuple[list[Path], dict[Path, str]]:
    sources = [roots["sdk"] / "src" / p for p in SDK_SOURCES]
    sources += [roots["fido"] / "src/fido" / p for p in FIDO_SOURCES]
    cmake = (roots["sdk"] / "picokeys_sdk_import.cmake").read_text(encoding="utf-8")
    crypto = sorted(set(re.findall(r'third-party/mbedtls/library/([\w.-]+\.c)', cmake)))
    sources += [roots["crypto"] / "library" / p for p in crypto]
    # Match Mbed TLS's normal portable build, including platform and entropy
    # implementations normally provided by the ESP-IDF component port.
    sources += list((roots["crypto"] / "library").glob("*.c"))
    sources += [roots["cbor"] / "src" / p for p in CBOR_SOURCES]
    sources += [roots["ducky"] / "components/ducky" / p for p in ("ducky.c", "ducky_keymap.c")]
    sources += [ROOT / "templates/port" / p for p in ("ws_board.c", "ws_panel.c", "ws_ui.c", "ws_lvgl.c", "ws_presence.c", "ws_crypto_port.c", "ws_pinpad.c", "ws_uv_retries.c", "ws_settings_codec.c", "ws_settings_store.c", "ws_manager_drive_state.c", "ws_usb_tool_state.c")]
    for p in sources:
        if not p.is_file(): raise RuntimeError(f"Missing locked source: {p}")
    files = set(sources)
    for name, subdirs in {"sdk": ["src", "config"], "fido": ["src/fido"],
                          "crypto": ["include", "library"], "cbor": ["src"],
                          "ducky": ["components/ducky"]}.items():
        for subdir in subdirs:
            for p in (roots[name] / subdir).rglob("*"):
                if p.suffix in {".h", ".hpp", ".inc"}: files.add(p)
    files.update((ROOT / "templates/port").glob("*.h"))
    files.update((ROOT / "templates/port").glob("*.inc"))
    mapping: dict[Path, str] = {}
    for p in files:
        for name, root in roots.items():
            if p.is_relative_to(root):
                mapping[p] = name + "/" + p.relative_to(root).as_posix()
                break
        else:
            mapping[p] = "board/" + p.name
    # tinycbor's version header is normally generated by its own build system.
    version = roots["cbor"] / "src/tinycbor-version.h"
    mapping[version] = "cbor/src/tinycbor-version.h"
    return sorted(set(sources)), mapping


def rewrite_includes(text: str, origin: Path, output: Path, mapping: dict[Path, Path],
                     include_dirs: list[Path], crypto_config: Path, external_api: Path,
                     external_version: Path | None = None) -> str:
    def replace(m: re.Match[str]) -> str:
        name = m.group(2)
        if name == "pf_engine_api.h":
            target = external_api
        elif name == "pf_firmware_version.h" and external_version is not None:
            target = external_version
        else:
            candidates = [origin.parent / name] + [p / name for p in include_dirs]
            target = next((mapping[p.resolve()] for p in candidates if p.resolve() in mapping), None)
            if target is None:
                if (name in NATIVE_ITS_HEADERS
                        and origin.parent.name == "library"
                        and origin.name in NATIVE_ITS_CONSUMERS):
                    # Do not try to evaluate #if in Python. Let the C
                    # preprocessor decide whether this unsupported branch is
                    # active, and fail closed if it is. All surrounding #if,
                    # #else and #endif directives remain unchanged.
                    prefix = re.sub(r"\binclude\b", "error", m.group(1), count=1)
                    message = (f"{NATIVE_ITS_ERROR}: {name}; "
                               "this Arduino port has no native PSA ITS backend")
                    return prefix + '"' + message + '"' + m.group(3)
                # Every other unresolved private crypto include is still an
                # immediate preparation error; never use the system ABI.
                if name.startswith(("mbedtls/", "psa/")):
                    raise RuntimeError(f"Unresolved private crypto include {name} in {origin}")
                return m.group()
        return m.group(1) + '"' + os.path.relpath(target, output.parent).replace(os.sep, '/') + '"' + m.group(3)
    text = INCLUDE.sub(replace, text)
    # build_info.h uses a macro include for its custom config; make it relative.
    custom = os.path.relpath(crypto_config, output.parent).replace(os.sep, '/')
    text = re.sub(r'(?m)^(\s*#\s*include\s+)MBEDTLS_CONFIG_FILE\s*$',
                  lambda m: m.group(1) + '"' + custom + '"', text)
    return text



# Header/source extensions accepted by Arduino's sketch file discovery. Files
# merely present in our output directory are not necessarily staged for build.
ARDUINO_CODE_SUFFIXES = frozenset({
    ".c", ".cpp", ".S", ".h", ".hpp", ".hh", ".tpp", ".ipp",
})


def validate_local_includes(engine: Path) -> None:
    """Validate generated relative includes, including Arduino staging support.

    This is a layout check, not compilation or a C preprocessor. System
    includes are left to the toolchain. Resolved local includes must both exist
    and have a sketch-supported extension; .inc is not a supported header.
    """
    for path in engine.rglob("*"):
        if not path.is_file() or path.suffix not in ARDUINO_CODE_SUFFIXES | {".inc"}:
            continue
        for match in INCLUDE.finditer(path.read_text(encoding="utf-8")):
            name = match.group(2)
            if not name.startswith("."):
                continue
            target = (path.parent / name).resolve()
            if not target.is_file():
                raise RuntimeError(f"Broken generated include in {path}: {name}")
            if target.suffix not in ARDUINO_CODE_SUFFIXES:
                raise RuntimeError(
                    f"ARDUINO_UNSUPPORTED_INCLUDE_EXTENSION: {path}: {name}; "
                    "use a supported header extension such as .h before preparation"
                )


def validate_output(engine: Path) -> None:
    cfiles = list(engine.rglob("*.c"))
    if len(cfiles) < 70: raise RuntimeError("Incomplete engine source set")
    forbidden_files = {"usb_descriptors.c", "led_neopixel.c", "led_pico.c"}
    for path in cfiles:
        s = path.read_text(encoding="utf-8")
        if path.name in forbidden_files: raise RuntimeError(f"Unexpected source {path}")
        # Only C tokens, not comments, count as unsafe operations.
        code = re.sub(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"', '', s, flags=re.S)
        if re.search(r'\b(?:esp_efuse_(?:write|set_|batch|disable)|esp_secure_boot_enable|esp_flash_encrypt_check_and_update)', code):
            raise RuntimeError(f"Unexpected security provisioning operation in {path}")
        if re.search(r'\b(?:tinyusb_driver_install|tusb_init|tud_init|app_main)\s*\(', code):
            raise RuntimeError(f"Second USB/app startup in {path}")
    validate_local_includes(engine)


def vendor_lvgl(lvgl_root: Path, stage: Path, generated: dict[str, str],
                apply_rgb565_overlay: bool = True) -> None:
    """Vendor the exact locked LVGL tree required by the Arduino sketch.

    LVGL v8.4.0 exposes its version macros from the repository-root ``lvgl.h``.
    It does *not* contain a repository-root ``lv_version.h``.  Keep this copy
    list tied to files that actually exist in the pinned upstream revision so
    Windows fails neither with FileNotFoundError/WinError 2 nor with a mutable
    Library Manager dependency.
    """
    src_root = lvgl_root / "src"
    root_header = lvgl_root / "lvgl.h"
    if not src_root.is_dir():
        raise RuntimeError(f"Locked LVGL source directory is missing: {src_root}")
    if not root_header.is_file():
        raise RuntimeError(f"Locked LVGL root header is missing: {root_header}")

    lvgl_dest = stage / "lvgl"
    shutil.copytree(src_root, lvgl_dest / "src")
    shutil.copy2(root_header, lvgl_dest / "lvgl.h")
    shutil.copy2(ROOT / "templates/lvgl_conf.h", stage / "lv_conf.h")

    # Preserve the RGB565 gradient polish when regenerating the committed
    # engine. Refuse to overlay an unexpected LVGL source revision.
    rgb565_overlays = {
        "lv_draw_sw_rect.c": "190e68e2c170539a3ba16e26a1f0e8100710c2b3ed4e4a761de234ffbe103db1",
        "lv_draw_sw_dither.c": "ea74f50e6abaf5ac84865cb8c4d7df668cb5f2193b4f1599b771d995adfc69e2",
    }
    if apply_rgb565_overlay:
        for name, expected_hash in rgb565_overlays.items():
            target = lvgl_dest / "src" / "draw" / "sw" / name
            actual_hash = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise RuntimeError(f"Locked LVGL {name} changed; RGB565 overlay needs review")
            shutil.copy2(ROOT / "templates" / "lvgl_patches" / name, target)

    copied = [stage / "lv_conf.h", lvgl_dest / "lvgl.h"]
    copied += sorted((lvgl_dest / "src").rglob("*"))
    for actual in copied:
        if actual.is_file():
            rel = actual.relative_to(stage).as_posix()
            generated[rel] = hashlib.sha256(actual.read_bytes()).hexdigest()


def prepare(cache: Path, offline: bool) -> None:
    src = ROOT / "EvilKeyV1/src"
    dest = src / "engine"
    ready = src / "engine_ready.h"
    if dest.exists() or ready.exists():
        raise RuntimeError("Engine already exists. Use a fresh copy to regenerate; existing work is never overwritten.")
    roots = {name: checkout(cache, name, offline).resolve() for name in REPOS}
    patches = make_patches(roots)
    sources, virtual = source_plan(roots)
    include_dirs = [roots["sdk"] / p for p in ["src", "src/usb", "src/fs", "src/rng", "src/led", "src/otp", "src/usb/hid"]]
    include_dirs += [roots["fido"] / "src/fido", roots["crypto"] / "include", roots["crypto"] / "library", roots["cbor"] / "src",
                     roots["ducky"] / "components/ducky", roots["ducky"] / "components/ducky/include",
                     ROOT / "templates/port"]
    stage = Path(tempfile.mkdtemp(prefix=".engine-stage-", dir=src))
    # Includes are computed for the final locations, then written into staging.
    mapping = {p.resolve(): dest / relative for p, relative in virtual.items()}
    config = mapping[(roots["sdk"] / "config/mbedtls_config.h").resolve()]
    generated = {}
    try:
        for original, relative in sorted(virtual.items(), key=lambda item: item[1]):
            target = dest / relative
            actual = stage / relative
            actual.parent.mkdir(parents=True, exist_ok=True)
            if original.name == "tinycbor-version.h" and not original.exists():
                text = "#pragma once\n#define TINYCBOR_VERSION_MAJOR 0\n#define TINYCBOR_VERSION_MINOR 6\n#define TINYCBOR_VERSION_PATCH 1\n"
            else:
                text = patches.get(original, None)
                if text is None: text = original.read_text(encoding="utf-8")
            text = rewrite_includes(text, original, target, mapping, include_dirs, config,
                                    src / "pf_engine_api.h", src / "pf_firmware_version.h")
            text = private_crypto(text)
            if original in sources:
                common = os.path.relpath(src / "pf_build_config.h", target.parent).replace(os.sep, '/')
                text = '#include "' + common + '"\n' + text
            actual.write_text(text, encoding="utf-8", newline="\n")
            generated[relative] = hashlib.sha256(text.encode()).hexdigest()

        # Vendor the exact locked LVGL 8.4 source into the generated Arduino
        # engine. This avoids a mutable Arduino Library Manager dependency and
        # makes the GUI build use the same reviewed LVGL revision every time.
        vendor_lvgl(roots["lvgl"], stage, generated)

        # Reject inadvertent peripheral/provisioning/duplicate startup sources.
        # Relative-path tests are repeated after move because stage has a different name.
        stage.rename(dest)
        validate_output(dest)
        license_dir = ROOT / "EvilKeyV1/data/upstream-licenses"
        license_dir.mkdir(parents=True, exist_ok=True)
        for name, root in roots.items():
            for p in root.glob("*"):
                if p.is_file() and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE")):
                    shutil.copy2(p, license_dir / (name + "_" + p.name))
        manifest = {"profile": "arduino-v1-development", "port_version": "0.4.0", "arduino_core": "3.3.12-recommended;3.3.11-supported",
                    "revisions": {name: sha for name, (_, sha) in REPOS.items()},
                    "translation_units": len(list(dest.rglob("*.c"))), "generated_sha256": generated,
                    "integrated_changes": ["C1", "S2", "LVGL_R5", "LVGL_R8_PREMIUM", "M1", "ARDUINO_HEADER_R1", "USB_TOOL_R26", "USB_TOOL_R27_HAK5", "USB_TOOL_R28_RAM_OPT", "PSRAM_DUCKY3_R29", "HAK5_AUTO_SYNC_R30", "HAK5_WINDOWS_IO_R31", "DUCKY3_ARCH_R32", "DUCKY3_OS_FIX_R33", "DUCKY3_HOST_OS_R34", "DUCKY3_COMPAT_ARCH_R35", "STAGE8A_8B_R35", "LOOT_INDEX_R35", "HAK5_LIBRARY_AUDIT_R35", "USB_TOOL_SAFE_AUTO_DETACH_R36", "CRYSTAL_SCREENSAVER_R37", "CRYSTAL_CONTRAST_R38"],
                    "package_revision": "EVILKEY_0_4_0_APPS_ABI_V2",
                    "external_usbd_stack_bytes_required": 16384,
                    "validation": "source-generation checks only; not a hardware certification"}
        (ROOT / "EvilKeyV1/GENERATED_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        ready.write_text("#pragma once\n#define PF_ENGINE_GENERATED 1\n#define PF_DEVICE_PROFILE_PATCH 1\n#define PF_LOCAL_UV_PATCH 1\n", encoding="utf-8")
        print(f"\nPrepared {len(list(dest.rglob('*.c')))} C translation units including pinned LVGL 8.4.0.")
        print("Open EvilKeyV1/EvilKeyV1.ino in Arduino IDE. Nothing was flashed.")
    except BaseException:
        if stage.exists(): shutil.rmtree(stage)
        # Keep any final generated directory for diagnosis; no marker => no valid build.
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, default=ROOT / ".cache")
    parser.add_argument("--offline", action="store_true", help="Use already populated clean locked repositories")
    args = parser.parse_args()
    if not shutil.which("git"):
        parser.error("Install Git and reopen the terminal so git is in PATH")
    try:
        prepare(args.cache.resolve(), args.offline)
        return 0
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"ERROR: {exc}\nNo device operation was performed.", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
