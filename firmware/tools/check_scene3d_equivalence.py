#!/usr/bin/env python3
"""Differential native Scene3D output against frozen accepted main 0.7.4."""
import argparse,json,subprocess,hashlib
from pathlib import Path
root=Path(__file__).resolve().parents[2]
a=argparse.ArgumentParser();a.add_argument('--zig',required=True);a.add_argument('--parallel',action='store_true');args=a.parse_args()
out=root/'firmware/test-output/scene3d-equivalence';out.mkdir(parents=True,exist_ok=True)
source='firmware/EvilKeyV1/src/apps/ek_scene3d.c'
baseline=subprocess.check_output(['git','-C',str(root),'show','4bbec7396bd8f9311b96e5e34bbc7d1211c0487b:'+source])
(out/'baseline.c').write_bytes(baseline)
(out/'reference.c').write_text('#define ek_scene3d_create baseline_create\n#define ek_scene3d_destroy baseline_destroy\n#define ek_scene3d_render baseline_render\n#include "baseline.c"\n')
exe=out/'equivalence.exe'
flags=['-DEK_RENDER_HOST_THREADS'] if args.parallel else []
subprocess.run([args.zig,'cc','-Os','-UNDEBUG','-fstack-usage',*flags,'-I'+str(root/'firmware/EvilKeyV1/src/apps'),str(out/'reference.c'),str(root/source),str(root/'firmware/EvilKeyV1/src/apps/ek_render_parallel.c'),str(root/'firmware/tools/scene3d_equivalence_test.c'),'-o',str(exe)],check=True)
r=subprocess.run([str(exe)],capture_output=True,text=True);print(r.stdout,r.stderr);r.check_returncode()
record={'baseline_commit':'4bbec7396bd8f9311b96e5e34bbc7d1211c0487b','baseline_sha256':hashlib.sha256(baseline).hexdigest(),'candidate_sha256':hashlib.sha256((root/source).read_bytes()).hexdigest(),'result':r.stdout,'status':'PASS','hardware':'NOT RUN'}
record['mode']='parallel' if args.parallel else 'serial'
record_path=out/('differential-parallel.json' if args.parallel else 'differential.json')
record_path.write_text(json.dumps(record,indent=2)+'\n')
