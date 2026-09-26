#!/usr/bin/env python3
"""Build and run host regressions against the patched, pinned DuckyScript runtime."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import os
import shlex
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache" / "ducky" / "components" / "ducky"
GENERATED = ROOT / "EvilKeyV1" / "src" / "engine" / "ducky" / "components" / "ducky"


def load_patch_module():
    path = ROOT / "tools" / "ducky3_hid_patch.py"
    spec = importlib.util.spec_from_file_location("ducky3_hid_patch", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def find_visual_studio() -> tuple[Path, Path] | None:
    program_files_x86 = os.environ.get("ProgramFiles(x86)")
    if not program_files_x86:
        return None
    vswhere = Path(program_files_x86) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if not vswhere.is_file():
        return None
    result = subprocess.run(
        [
            str(vswhere),
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    installation = Path(result.stdout.strip())
    vcvars = installation / "VC" / "Auxiliary" / "Build" / "vcvars64.bat"
    compilers = sorted((installation / "VC" / "Tools" / "MSVC").glob("*/bin/Hostx64/x64/cl.exe"))
    return (compilers[-1], vcvars) if vcvars.is_file() and compilers else None


def compile_runtime(temp: Path, include: Path, output: Path, test_source: Path,
                    extra_includes: tuple[Path, ...] = ()) -> None:
    sources = [
        test_source,
        temp / "ducky.c",
        temp / "ducky_keymap.c",
    ]
    cc = shlex.split(os.environ.get("CC", "cc"))
    if shutil.which(cc[0]):
        command = cc + [
            "-std=c11",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(include),
            "-I",
            str(temp),
            *(item for path in extra_includes for item in ("-I", str(path))),
            *map(str, sources),
            "-o",
            str(output),
        ]
        subprocess.run(command, check=True)
        return

    visual_studio = find_visual_studio()
    if visual_studio is None:
        raise SystemExit("No host C compiler. Set CC to GCC/Clang or install Visual C++ Build Tools.")
    compiler, vcvars = visual_studio
    command = [
        str(compiler),
        "/nologo",
        "/std:c11",
        "/O1",
        "/W4",
        "/WX",
        "/wd4244",
        "/D_CRT_SECURE_NO_WARNINGS",
        f"/I{include}",
        f"/I{temp}",
        *(f"/I{path}" for path in extra_includes),
        *map(str, sources),
        f"/Fo{temp}\\",
        f"/Fd{temp / 'ducky_os_r33.pdb'}",
        f"/Fe:{output}",
    ]
    environment_result = subprocess.run(
        f'call "{vcvars}" >nul && set',
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
    environment = os.environ.copy()
    for line in environment_result.stdout.splitlines():
        if "=" in line:
            name, value = line.split("=", 1)
            environment[name] = value
    subprocess.run(command, check=True, env=environment)


def prepare_patched_runtime(temp: Path) -> Path:
    """Materialize the exact patched runtime used by firmware and host tools."""
    cache_required = [
        CACHE / "ducky.c",
        CACHE / "ducky_keymap.c",
        CACHE / "ducky_keymap.h",
        CACHE / "include" / "ducky.h",
        CACHE / "include" / "ducky_hid_codes.h",
    ]
    generated_required = [
        GENERATED / "ducky.c",
        GENERATED / "ducky_keymap.c",
        GENERATED / "ducky_keymap.h",
        GENERATED / "include" / "ducky.h",
        GENERATED / "include" / "ducky_hid_codes.h",
    ]
    use_generated = os.environ.get("PICO_DUCKY_RUNTIME_SOURCE", "").lower() == "generated"
    if not use_generated and all(path.is_file() for path in cache_required):
        source = CACHE
        patch = load_patch_module()
        patched_c = patch.patch_ducky_c((source / "ducky.c").read_text(encoding="utf-8"))
        patched_h = patch.patch_ducky_h((source / "include" / "ducky.h").read_text(encoding="utf-8"))
        patched_keymap = patch.patch_ducky_keymap_c(
            (source / "ducky_keymap.c").read_text(encoding="utf-8")
        )
    elif all(path.is_file() for path in generated_required):
        # Source ZIPs deliberately omit the reproducible Git cache. The
        # generated engine is the exact patched runtime compiled into firmware,
        # so it remains a valid host-regression input without a network fetch.
        source = GENERATED
        patched_c = (source / "ducky.c").read_text(encoding="utf-8")
        patched_h = (source / "include" / "ducky.h").read_text(encoding="utf-8")
        patched_keymap = (source / "ducky_keymap.c").read_text(encoding="utf-8")
        generated_preamble = '#include "../../../../pf_build_config.h"\n'
        if not patched_c.startswith(generated_preamble) or not patched_keymap.startswith(generated_preamble):
            raise SystemExit("Generated DuckyScript runtime has an unexpected build-config preamble.")
        patched_c = patched_c.removeprefix(generated_preamble)
        patched_keymap = patched_keymap.removeprefix(generated_preamble)
    else:
        missing = [str(path) for path in cache_required + generated_required if not path.is_file()]
        raise SystemExit(
            "Missing both pinned s3-ducky cache and generated runtime. "
            "Run firmware\\prepare.cmd first.\n"
            + "\n".join(missing)
        )

    include = temp / "include"
    include.mkdir()
    if os.name == "nt" and not shutil.which(shlex.split(os.environ.get("CC", "cc"))[0]):
        compatibility = '''#if defined(_MSC_VER)\nstatic bool pf_host_mul_overflow_i64(int64_t a, int64_t b, int64_t *out)\n{\n    if (a == 0 || b == 0) { *out = 0; return false; }\n    if ((a == -1 && b == INT64_MIN) || (b == -1 && a == INT64_MIN)) return true;\n    int64_t value = a * b;\n    if (value / b != a) return true;\n    *out = value;\n    return false;\n}\n#define __builtin_mul_overflow(a, b, out) pf_host_mul_overflow_i64((a), (b), (out))\n#endif\n\n'''
        patched_c = patched_c.replace(
            '#include "ducky_keymap.h"\n',
            '#include "ducky_keymap.h"\n\n' + compatibility,
            1,
        )
    (temp / "ducky.c").write_text(patched_c, encoding="utf-8", newline="\n")
    (include / "ducky.h").write_text(
        patched_h,
        encoding="utf-8",
        newline="\n",
    )
    (temp / "ducky_keymap.c").write_text(
        patched_keymap,
        encoding="utf-8",
        newline="\n",
    )
    shutil.copy2(source / "ducky_keymap.h", temp / "ducky_keymap.h")
    shutil.copy2(source / "include" / "ducky_hid_codes.h", include / "ducky_hid_codes.h")
    return include


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="picofido-ducky-r33-") as temp_name:
        temp = Path(temp_name)
        include = prepare_patched_runtime(temp)

        # Keep architecture regressions as separate executables because every
        # source file intentionally owns main().
        tests = (
            ("r33", "test_ducky_os_r33.c"),
            ("r34", "test_ducky_os_r34.c"),
            ("r35", "test_ducky_preprocessor_r35.c"),
            ("r35_key_combos", "test_ducky_key_combos_r35.c"),
            ("r35_button", "test_ducky_button_r35.c"),
            ("r35_variables", "test_ducky_variables_r35.c"),
            ("r35_attackmode", "test_ducky_attackmode_r35.c"),
            ("r35_stage8", "test_ducky_stage8_r35.c"),
            ("r35_hid_out", "test_usb_tool_hid_out_r35.c"),
        )
        for revision, filename in tests:
            test_source = ROOT / "tests" / "release_026" / filename
            output = temp / (f"ducky_os_{revision}.exe" if os.name == "nt" else f"ducky_os_{revision}")
            compile_runtime(temp, include, output, test_source)
            subprocess.run([str(output)], check=True, timeout=60)

        index_test = ROOT / "tests" / "release_026" / "test_loot_index_format_r35.c"
        index_output = temp / ("loot_index_r35.exe" if os.name == "nt" else "loot_index_r35")
        compile_runtime(temp, include, index_output, index_test,
                        (ROOT / "EvilKeyV1" / "src",))
        subprocess.run([str(index_output)], check=True, timeout=60)

    print("PASS: patched pinned DuckyScript runtime host regression")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
