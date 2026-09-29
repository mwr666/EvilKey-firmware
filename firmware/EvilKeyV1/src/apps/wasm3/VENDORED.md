# Wasm3 source snapshot

Source: https://github.com/wasm3/wasm3
Commit: `0228c02233f6f4f5d3a85ab0b14244a2ebadc1ba`
License: MIT (see `LICENSE`).

This directory contains the upstream core `.c` files and headers needed by
the EvilKey Apps VM. The `m3_api_wasi*.c`, `m3_api_libc.c`,
`m3_api_tracer.c`, and `m3_api_uvwasi.c` host libraries are deliberately
excluded. EvilKey Apps ABI v3 accepts only guests with zero imports; drawing
commands are read from the guest's linear memory after each call.
Local patch: `m3_config_platforms.h` enables gas metering for Arduino-ESP32.
The EvilKey Apps runtime rejects builds without it so the firmware and host
enforce the same per-call instruction budget.
Local patch: Arduino-ESP32 uses the iterative opcode dispatcher in
`m3_exec_defs.h`, `m3_exec.h`, and `m3_compile.c`. Xtensa GCC emits an indirect
call and a return for each opcode instead of a tail call; without this patch,
ordinary app initialization can exhaust the Apps worker's native stack. Nested Wasm
calls and blocks also have a 6144-byte native stack budget.
Do not replace this snapshot without rerunning the host VM probes and the
full Arduino image size check.
