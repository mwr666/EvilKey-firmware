from pathlib import Path
import subprocess,sys,os
r=Path(__file__).resolve().parents[1]
env=dict(os.environ);env['PYTHONPATH']=str(r/'firmware')
for folder,pattern in [('tests','test_flash_arduino.py'),('tests','test_arduino_layout.py'),('firmware/tests','test_ble_storage_guard.py')]:
    subprocess.run([sys.executable,'-m','unittest','discover','-s',str(r/folder),'-p',pattern],cwd=r,env=env,check=True)
