#!/usr/bin/env python3
"""Qualify shared model APIs on host; target timing is a separate procedure."""
import argparse,subprocess,hashlib,json,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
p=argparse.ArgumentParser();p.add_argument('--zig',required=True);p.add_argument('--game',type=Path,required=True);p.add_argument('--baseline',type=Path);args=p.parse_args()
apps=root/'firmware/EvilKeyV1/src/apps';out=root/'firmware/test-output/scene3d';out.mkdir(parents=True,exist_ok=True);commands=[];log=[]
def run(command):
 commands.append(list(map(str,command)));c=subprocess.run(command,capture_output=True,text=True);log.append(c.stdout+c.stderr);print(c.stdout+c.stderr,end='',flush=True)
 if c.returncode:raise RuntimeError(f'command failed: {c.returncode}')
z=args.zig;g=args.game.resolve();h=root/'firmware/tools/apps_storage_host'
try:
 run([sys.executable,root/'apps/sdk/test_mesh.py'])
 run([z,'cc','-Os','-UNDEBUG','-DEK_RENDER_HOST_THREADS','-I'+str(apps),apps/'ek_scene3d.c',apps/'ek_render_parallel.c',apps/'ek_package.c',root/'firmware/tests/test_scene3d_mesh.c','-o',out/'mesh.exe'])
 run([out/'mesh.exe',g/'models/23.ekmesh',g/'package/evil.racer3d.ekapp'])
 run([z,'cc','-Os','-UNDEBUG','-DEK_RENDER_HOST_THREADS','-DEK_SCENE_CACHE_ALLOC_TEST','-I'+str(apps),apps/'ek_scene3d.c',apps/'ek_render_parallel.c',root/'firmware/tests/test_scene3d_underlay.c','-o',out/'underlay.exe'])
 run([out/'underlay.exe'])
 if args.baseline:
  rename=['-Dek_scene3d_create=baseline_create','-Dek_scene3d_destroy=baseline_destroy','-Dek_scene3d_set_assets=baseline_assets','-Dek_scene3d_render=baseline_render','-Dek_scene3d_profile=baseline_profile']
  run([z,'cc','-Os','-UNDEBUG','-DEK_RENDER_HOST_THREADS','-I'+str(apps),*rename,'-c',args.baseline,'-o',out/'baseline.o'])
  run([z,'cc','-Os','-UNDEBUG','-DEK_RENDER_HOST_THREADS','-DEK_MESH_CACHE_TEST','-I'+str(apps),apps/'ek_scene3d.c',apps/'ek_render_parallel.c',root/'firmware/tests/test_scene3d_mesh_cache.c',out/'baseline.o','-o',out/'mesh-cache.exe'])
  run([out/'mesh-cache.exe',g/'models/23.ekmesh',g/'models/24.ekmesh'])
 run([z,'c++','-std=c++17','-O2','-UNDEBUG','-DEK_STORAGE_HOST_TEST','-DEK_MODELS_ALLOC_TEST','-I'+str(h),'-x','c++',h/'models_test.cpp',apps/'ek_storage.cpp',apps/'ek_package.c',apps/'ek_assets.c','-o',out/'models-sd.exe'])
 run([out/'models-sd.exe',g/'models/23.ekmesh'])
 run([z,'cc','-target','wasm32-freestanding','-O2','-nostdlib','-Wl,--no-entry','-Wl,--export=app_input_ptr','-Wl,--export=app_init','-Wl,--export=app_step','-Wl,--export=probe_fault_next','-I'+str(apps),root/'firmware/tools/apps_mesh_guest.c','-o',out/'mesh-guest.wasm'])
 run([z,'cc','-Os','-UNDEBUG','-I'+str(apps),'-I'+str(apps/'wasm3'),root/'firmware/tests/test_vm_mesh.c',apps/'ek_vm.c',apps/'ek_assets.c',*sorted((apps/'wasm3').glob('*.c')),'-o',out/'vm-mesh.exe'])
 run([out/'vm-mesh.exe',g/'models/23.ekmesh',out/'mesh-guest.wasm'])
 status='PASS'
except Exception:
 status='FAIL';raise
finally:
 evidence=root/'specs/scene3d-model-assets/evidence';evidence.mkdir(parents=True,exist_ok=True)
 (evidence/'host.txt').write_text(''.join(log),encoding='utf-8')
 files=[*sorted(apps.glob('*.c')),*sorted(apps.glob('*.h')),*sorted((root/'apps/sdk').glob('*.py')),g/'models/23.ekmesh',g/'models/24.ekmesh',g/'package/evil.racer3d.ekapp']
 files += [root/'firmware/tests/test_scene3d_mesh_cache.c',root/'firmware/tests/test_scene3d_mesh.c',root/'firmware/tests/test_scene3d_underlay.c',root/'firmware/tests/test_vm_mesh.c',root/'firmware/tools/apps_mesh_guest.c']
 if args.baseline:files.append(args.baseline)
 (evidence/'host.json').write_text(json.dumps({'spec_revision':5,'status':status,'hardware':'NOT RUN','cache_comparison':'PASS' if args.baseline and status=='PASS' else 'NOT RUN','clock':'NULL ordinary renders; advancing synthetic clock for timeout','storage_digest':'mock, mechanism only; real SHA independently checked in artifact readback and target mbedTLS','commands':commands,'log':'host.txt','inputs_sha256':{str(f):hashlib.sha256(f.read_bytes()).hexdigest() for f in files}},indent=2)+'\n',encoding='utf-8')
