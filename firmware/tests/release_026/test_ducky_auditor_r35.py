#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))


def load_analyzer():
    path = TOOLS / "analyze_hak5_compat.py"
    spec = importlib.util.spec_from_file_location("analyze_hak5_compat", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    analyzer = load_analyzer()
    with tempfile.TemporaryDirectory(prefix="picofido-auditor-r35-") as temp_name:
        runner = analyzer.build_runtime_runner(Path(temp_name))

        valid = analyzer.runtime_audit(
            runner,
            "DEFINE #MODE HID\nDEFINE #ACTION STRING ok\nATTACKMODE #MODE\n#ACTION\n",
        )
        assert valid["status"] == "ok", valid

        linux_branch = analyzer.runtime_audit(
            runner,
            "IF ($_OS == LINUX) THEN\nUNKNOWN_ACTIVE_COMMAND\nEND_IF\n",
        )
        assert linux_branch["reason"] == "runtime_parse_error", linux_branch
        assert linux_branch["line"] == 2, linux_branch

        system_report = analyzer.runtime_audit(runner, "SYSTEM_SLEEP\n")
        assert system_report["status"] == "ok", system_report

        absolute_mouse = analyzer.runtime_audit(runner, "MOUSE_ABSOLUTE 16384 8192\n")
        assert absolute_mouse["status"] == "ok", absolute_mouse

        descriptor_profile = analyzer.runtime_audit(
            runner,
            "ATTACKMODE HID VID_046D PID_C31C MAN_HAK5 PROD_DUCKY SERIAL_1337\n"
            "SAVE_ATTACKMODE\nATTACKMODE OFF\nRESTORE_ATTACKMODE\n",
        )
        assert descriptor_profile["status"] == "ok", descriptor_profile

        policy = analyzer.policy_audit_text(
            "IF FALSE THEN\nEXFIL $VALUE\nEND_IF\n"
            "$_EXFIL_MODE_ENABLED = TRUE\nHIDE_PAYLOAD\n"
        )
        assert policy == [
            "keystroke_reflection",
            "payload_snapshot_hiding",
            "variable_exfil",
        ], policy

        assert analyzer.policy_audit_text("EXFIL $VALUE\n") == ["variable_exfil"]
        assert analyzer.policy_audit_text("$_EXFIL_MODE_ENABLED = TRUE\n") == [
            "keystroke_reflection"
        ]
        assert analyzer.policy_audit_text("RESTORE_PAYLOAD\n") == [
            "payload_snapshot_hiding"
        ]
        assert analyzer.policy_audit_text("EXFIL $VALUE\n$_EXFIL_MODE_ENABLED = TRUE\n",
            allow_variable_exfil=True,allow_keystroke_reflection=True) == []
        assert analyzer.policy_audit_text("HIDE_PAYLOAD\n",allow_variable_exfil=True,
            allow_keystroke_reflection=True) == ["payload_snapshot_hiding"]

    print("PASS: Hak5 auditor uses the patched runtime and approval policy gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
