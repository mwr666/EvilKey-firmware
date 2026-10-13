"""Independent windowed-ABI stack-slot ownership check; not a CPU emulator."""
from pathlib import Path
import re,sys
text=Path(sys.argv[1]).read_text(encoding='utf-8')
frame=int(re.search(r'entry\s+a1,\s*(\d+)',text).group(1))
assert frame>=32 and frame%16==0
bad=[]
for offset in re.findall(r's32i(?:\.n)?\s+a\d+,\s*a1,\s*(\d+)',text):
 offset=int(offset)
 # CALL8 can spill four extra words at callerSP-32..-20. The
 # caller's base-save words occupy callerSP-16..-4. Both are reserved.
 if offset+4>frame-32:bad.append(offset)
if bad:
 print(f'ABI DEFECT DETECTED: frame={frame}, stack writes={bad}; offset16 == callerSP-16 for frame32')
 sys.exit(1)
assert not re.search(r's32i(?:\.n)?\s+a\d+,\s*a1',text)
for name,body in re.findall(r'(ek_(?:strip|pixel)_pie_\w+_blocks):([\s\S]*?)(?=\.size)',text):
 assert 'entry a1, 32' in body and 'retw.n' in body,name
 assert not re.search(r'(?:s32i|s16i|s8i|ee\.vst[^\s]*)[^\n]*a1',body),name
 if name.endswith('swap_blocks'):
  for lane in range(4):assert re.search(rf'ee\.movi\.32\.q\s+q3,\s*a4,\s*{lane}',body)
assert 'ee.vst.128.ip q0, a2, 16' in text
print('ABI ownership PASS: no stack writes; all4 vector mask lanes; output-only stores; frame32')
