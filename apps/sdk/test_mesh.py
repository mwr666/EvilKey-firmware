# SPDX-License-Identifier: MIT
import json,struct,tempfile
from pathlib import Path
from mesh import convert_obj,validate
from pack_ekapp import pack,HEADER
tetra='v 0 0 0\nv 1 0 0\nv 0 1 0\nv 0 0 1\nusemtl paint\nf 1 3 2\nf 1 2 4\nusemtl glass\nf 2 3 4\nf -4 -1 -2\n'
quad='v -1 0 -1\nv 1 0 -1\nv 1 0 1\nv -1 0 1\nf 1/1 2/2 3/3 4/4\n'
for source,expected in ((tetra,(4,4)),(quad,(4,2))):
 data,roles=convert_obj(source);assert validate(data)==expected
for source in ('',tetra.replace('v 0 0 0','v nan 0 0'),quad.replace('4/4','99/4'),quad.replace('4/4','1/4')):
 try:convert_obj(source)
 except (ValueError,struct.error):pass
 else:raise AssertionError('invalid OBJ accepted')
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory);(root/'a.ekmesh').write_bytes(convert_obj(tetra)[0]);(root/'b.ekmesh').write_bytes(convert_obj(quad)[0]);
 (root/'assets.json').write_text(json.dumps({'assets':[{'id':1,'type':'mesh','file':'a.ekmesh','external':True},{'id':2,'type':'mesh','file':'b.ekmesh'}]}))
 (root/'a.wasm').write_bytes(b'\0asm\1\0\0\0');(root/'icon').write_bytes(bytes(8192))
 output=pack(root/'a.wasm',root/'out/example.ekapp','example','Owner','MIT','1.0.0',root/'assets.json','Example',root/'icon','corner-exit-v1',5)
 assert HEADER.unpack(output.read_bytes()[:320])[4]==1
 assert (root/'out/example.models/1.ekmesh').read_bytes()==(root/'a.ekmesh').read_bytes()
 blob=output.read_bytes()[8520:];assert struct.unpack_from('<HHHH',blob,12)==(1,4,0,0) and struct.unpack_from('<HHHH',blob,32)==(2,2,0,0)
print('SDK MESH PASS independent tetrahedron/quad OBJ, negative/slashed indices, material roles, malformed data, embedded/external resources, feature bit and external readback')
