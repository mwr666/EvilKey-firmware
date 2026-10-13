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
from pack_ekapp import HEADER, ICON_BYTES, PAYLOAD_OFFSET, PACKAGE_REVISION, UI_PROFILE, UI_PROFILE_BYTES


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
     wasm_size, digest, raw_owner, raw_license, asset_size, reserved,
     raw_name, icon_digest, extension_reserved) = HEADER.unpack_from(data)
    if (magic, size, revision, abi, flags, reserved, extension_reserved) != \
            (b"EKEYAPP1", 320, PACKAGE_REVISION, abi, flags, bytes(2), UI_PROFILE_BYTES) or abi not in (4,5) or flags & ~3 or (abi==4 and flags):
        raise ValueError("unsupported package header")
    icon = data[HEADER.size:PAYLOAD_OFFSET]
    if len(icon) != ICON_BYTES or hashlib.sha256(icon).digest() != icon_digest:
        raise ValueError("icon length or hash mismatch")
    if decoded(raw_name) != manifest["name"] or manifest["package_revision"] != PACKAGE_REVISION or \
        manifest.get("ui_profile") != UI_PROFILE or \
        manifest["icon"] != {"width":64,"height":64,"format":"rgb565-le", "sha256":icon_digest.hex()}:
        raise ValueError("launcher manifest metadata mismatch")
    program = data[PAYLOAD_OFFSET:PAYLOAD_OFFSET + wasm_size]
    payload = data[PAYLOAD_OFFSET:]
    if (len(payload) != wasm_size + asset_size or not 8 <= wasm_size <= 65536 or
        asset_size > 1024 * 1024 or program[:8] != b"\0asm\x01\0\0\0" or
        hashlib.sha256(payload).digest() != digest):
        raise ValueError("payload length, magic or digest mismatch")
    if (decoded(raw_id), decoded(raw_owner), decoded(raw_license)) != (
        manifest["id"], manifest["owner"], manifest["license"]):
        raise ValueError("header and manifest metadata differ")
    if (manifest["version"], manifest["api"], manifest["bundle_sha256"]) != (
        f"{major}.{minor}.{patch}", f"evilkey_v{abi}",
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
            "schema", "id", "name", "package_revision", "ui_profile", "icon", "owner", "license", "version", "api",
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
    customer_manifest['required_features']=flags
    blob=data[PAYLOAD_OFFSET+wasm_size:];extra=0;models=[]
    if blob:
        if len(blob)<12 or blob[:8]!=b'EKASSET1':raise ValueError('asset header')
        count,reserved=struct.unpack_from('<HH',blob,8)
        if count>32 or reserved or len(blob)<12+count*20:raise ValueError('asset table')
        previous_id=0;end=12+count*20
        for i in range(count):
            ident,kind,w,h,offset,length,reserved=struct.unpack_from('<HHHHIII',blob,12+i*20)
            if ident<=previous_id or reserved or offset<end or offset+length>len(blob):raise ValueError('asset bounds')
            previous_id=ident;end=offset+length;resource=blob[offset:end]
            if kind<=1:
                if not 1<=w<=280 or not 1<=h<=456 or length!=w*h*2:raise ValueError('bitmap dimensions')
            elif kind in (2,4):
                from mesh import validate
                if not flags&1 or w or h or ident>32767:raise ValueError('mesh feature/dimensions')
                if kind==4:
                    if length!=36:raise ValueError('model descriptor')
                    source=package/(app_id+'.models')/(str(ident)+'.ekmesh')
                    if not source.resolve().is_relative_to(package.resolve()):raise ValueError('model outside package')
                    content=source.read_bytes();expected=struct.unpack_from('<I',resource)[0]
                    if len(content)!=expected or hashlib.sha256(content).digest()!=resource[4:]:raise ValueError('external mesh mismatch')
                    validate(content);name=app_id+'.models/'+str(ident)+'.ekmesh';files[name]=content;extra+=len(content)
                    models.append({'file':name,'bytes':len(content),'sha256':hashlib.sha256(content).hexdigest()})
                else:validate(resource)
            else:raise ValueError('unknown asset type')
        if end!=len(blob) or len(blob)+extra>1048576:raise ValueError('aggregate asset quota')
    customer_manifest['model_resources']=models
    customer_manifest['required_features']=flags
    files['manifest.json']=(json.dumps(customer_manifest,indent=2,ensure_ascii=False)+'\n').encode('utf-8')
    out_dir = ROOT / "release" / "apps"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{app_id}_{manifest['version']}_ABI{abi}.zip"
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
