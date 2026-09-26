#!/usr/bin/env python3
from pathlib import Path
import shutil, subprocess, tempfile
ROOT=Path(__file__).resolve().parents[1]
CXX=shutil.which('c++') or shutil.which('g++') or shutil.which('clang++')
if not CXX: raise SystemExit('SKIP: no host C++ compiler')
with tempfile.TemporaryDirectory(prefix='picofido-hak5-') as tmp:
    out=Path(tmp)/'hak5_language'
    cmd=[CXX,'-std=c++17','-O1','-g','-Wall','-Wextra','-Werror',
         str(ROOT/'tests/release_026/test_hak5_language_r27.cpp'),
         str(ROOT/'EvilKeyV1/src/Hak5Language.cpp'),'-o',str(out)]
    subprocess.run(cmd,check=True)
    subprocess.run([str(out)],check=True)
print('PASS: R27 Hak5 language adapter host test')
