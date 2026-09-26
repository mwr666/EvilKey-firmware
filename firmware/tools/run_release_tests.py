#!/usr/bin/env python3
"""Host-only release tests. Hardware, USB bus and full Arduino link are not exercised."""
from pathlib import Path
import argparse, os, shlex, shutil, subprocess, tempfile

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--sanitize',action='store_true');args=parser.parse_args()
    root=Path(__file__).resolve().parents[1];p=root/'templates/port';t=root/'tests/release_026'
    groups=[
      ('power',[t/'test_screen_power.c'],'board_stubs'),
      ('power_config',[t/'test_power_config.c'],'board_stubs'),
      ('presence',[t/'test_presence.c',p/'ws_presence.c'],'board_stubs'),
      ('pinpad',[t/'test_pinpad.c',p/'ws_pinpad.c',p/'ws_presence.c',p/'ws_ui.c'],'board_stubs'),
      ('gui',[t/'test_gui_ui1.c',p/'ws_ui.c'],'board_stubs'),
      ('board',[t/'test_board_ui1.c',p/'ws_pinpad.c',p/'ws_presence.c',p/'ws_ui.c',p/'ws_settings_codec.c'],'board_stubs'),
      ('panel',[t/'test_panel_ui1.c',p/'ws_ui.c'],'panel_stubs'),
      ('local_uv_binding',[t/'test_local_uv_binding.c'],'board_stubs'),
    ]
    for name in ['settings_store','manager_auth','manager_drive_state','usb_tool_state']:
        if(t/f'test_{name}.c').exists():groups.append((name,[t/f'test_{name}.c',p/'ws_settings_codec.c'],'settings_stubs'))
    cc=shlex.split(os.environ.get('CC','cc'));env=os.environ.copy()
    if not shutil.which(cc[0]):parser.error('No C compiler. Set CC to GCC/Clang.')
    if args.sanitize:env.update(ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1')
    with tempfile.TemporaryDirectory(prefix='picofido-tests-') as tmp:
        for name,sources,stubs in groups:
            out=Path(tmp)/name;flags=['-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation']
            if args.sanitize:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie']
            print('BUILD / RUN:',name,'sanitized' if args.sanitize else 'normal',flush=True)
            subprocess.run(cc+flags+['-I',str(t/stubs),'-I',str(p)]+list(map(str,sources))+['-o',str(out)],check=True)
            subprocess.run([str(out)],env=env,check=True,timeout=60)
    print(f'PASS: {len(groups)} C executables. This is NOT an Arduino or hardware test.')
if __name__=='__main__':main()
