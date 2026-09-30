#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate one app and create a binary-only distribution ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[2]
HEADER = struct.Struct("<8sHHHHHHH32sI32s64s32s6s")


def decoded(raw):
    value, separator, padding = raw.partition(b"\0")
    if not value or not separator or any(padding):
        raise ValueError("invalid package metadata")
    return value.decode("utf-8")


def build(app: Path):
    package = app / "package"
    manifest_file = package / "manifest.json"
    manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    app_id = manifest["id"]
    if manifest["schema"] != "evilkey-app-manifest-v1" or not re.fullmatch(
        r"(?:[a-z0-9]|[a-z0-9][a-z0-9._-]{0,29}[a-z0-9_-])", app_id
    ) or ".." in app_id:
        raise ValueError("unexpected app manifest")
    if manifest["bundle"] != f"{app_id}.ekapp":
        raise ValueError("unexpected bundle name")
    bundle = package / manifest["bundle"]
    data = bundle.read_bytes()
    if len(data) < HEADER.size:
        raise ValueError("short bundle")
    (magic, size, revision, abi, flags, major, minor, patch, raw_id,
     wasm_size, digest, raw_owner, raw_license, reserved) = HEADER.unpack_from(data)
    asset_size = struct.unpack_from("<I", reserved)[0]
    if (magic, size, revision, abi, flags, reserved[4:]) != \
            (b"EKEYAPP1", 192, 3, 4, 0, bytes(2)):
        raise ValueError("unsupported package header")
    program = data[HEADER.size:HEADER.size + wasm_size]
    payload = data[HEADER.size:]
    if (len(payload) != wasm_size + asset_size or not 8 <= wasm_size <= 65536 or
        asset_size > 1024 * 1024 or program[:8] != b"\0asm\x01\0\0\0" or
        hashlib.sha256(payload).digest() != digest):
        raise ValueError("payload length, magic or digest mismatch")
    if (decoded(raw_id), decoded(raw_owner), decoded(raw_license)) != (
        manifest["id"], manifest["owner"], manifest["license"]):
        raise ValueError("header and manifest metadata differ")
    if (manifest["version"], manifest["api"], manifest["bundle_sha256"]) != (
        f"{major}.{minor}.{patch}", "evilkey_v4",
        hashlib.sha256(data).hexdigest()):
        raise ValueError("manifest version, ABI, size or hash mismatch")
    if manifest.get("program_sha256", hashlib.sha256(program).hexdigest()) != \
            hashlib.sha256(program).hexdigest() or \
            manifest.get("program_size", wasm_size) != wasm_size:
        raise ValueError("development bytecode metadata mismatch")
    if not manifest["owner"] or not manifest["license"]:
        raise ValueError("missing owner or license")
    license_bytes = (app / "LICENSE.md").read_bytes()
    if manifest["owner"] not in license_bytes.decode("utf-8"):
        raise ValueError("license text does not name the declared owner")
    customer_manifest = {
        key: manifest[key] for key in (
            "schema", "id", "owner", "license", "version", "api",
            "bundle", "bundle_sha256", "capabilities"
        )
    }
    files = {
        bundle.name: data,
        "manifest.json": (json.dumps(customer_manifest, indent=2,
                                     ensure_ascii=False) + "\n").encode("utf-8"),
        "LICENSE.md": license_bytes,
        "SDK-MIT-LICENSE.txt": (ROOT / "apps" / "sdk" / "LICENSE").read_bytes(),
    }
    out_dir = ROOT / "release" / "apps"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{app_id}_{manifest['version']}_ABI4.zip"
    if out.exists():
        raise ValueError(f"refusing to overwrite {out}")
    with zipfile.ZipFile(out, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    with zipfile.ZipFile(out) as archive:
        if set(archive.namelist()) != set(files):
            raise ValueError("unexpected ZIP contents")
        for name, content in files.items():
            if archive.read(name) != content:
                raise ValueError(f"ZIP readback mismatch: {name}")
    out.with_suffix(".zip.sha256").write_text(
        f"{hashlib.sha256(out.read_bytes()).hexdigest()}  {out.name}\n", encoding="ascii")
    return out


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-dir", type=Path, required=True)
    args = parser.parse_args()
    print(build(args.app_dir.resolve()))
