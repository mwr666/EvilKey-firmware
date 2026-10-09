"""Test actual Manager Drive callback/API bodies; pinned SDK compiles full unit."""
from pathlib import Path
import argparse,subprocess
p=argparse.ArgumentParser();p.add_argument('--zig',required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[2];out=root/'firmware/build/manager-eject';out.mkdir(parents=True,exist_ok=True)
source=(root/'firmware/EvilKeyV1/src/PicoFidoArduino.cpp').read_text()
def function(start,source=source):
 assert start in source, 'Missing completed-eject behavior: '+start
 at=source.index(start);brace=source.index('{',at);level=1;end=brace+1
 while level:
  level+=(source[end]=='{')-(source[end]=='}');end+=1
 return source[at:end]
(out/'manager-drive-under-test.inc').write_text('\n'.join(function(n) for n in
 ('static bool manager_drive_start_stop(', 'static void manager_drive_scsi_complete(', 'extern "C" bool pf_manager_drive_take_eject(')))
adapter=(root/'firmware/EvilKeyV1/src/PfUsbMsc.cpp').read_text()
(out/'msc-adapter-under-test.inc').write_text('\n'.join(function(n,adapter) for n in
 ('bool tud_msc_start_stop_cb(', 'void tud_msc_scsi_complete_cb(', 'int32_t tud_msc_read10_cb(', 'int32_t tud_msc_write10_cb(')))
exe=out/'test.exe'
subprocess.run([a.zig,'c++','-std=c++17','-O2','-UNDEBUG','-I'+str(out),str(root/'firmware/tests/test_manager_drive_eject.cpp'),'-o',str(exe)],check=True)
subprocess.run([str(exe)],check=True,timeout=30)
print('PASS actual callback completion/non-eject/duplicate/role/aborted/10000 atomic handoffs and real MSC adapter LUN/media I/O guards')
