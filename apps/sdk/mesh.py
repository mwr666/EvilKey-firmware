#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Convert static OBJ geometry into a bounded EKMESH1 model (no dependencies)."""
import argparse, math, struct
from pathlib import Path

def validate(data):
    if len(data)<20 or len(data)>65536:raise ValueError('mesh size')
    magic,version,nv,nt,reserved,size=struct.unpack_from('<8sHHHHI',data)
    if magic!=b'EKMESH1\0' or version!=1 or reserved or size!=len(data) or not 1<=nv<=1024 or not 1<=nt<=1280 or size!=20+nv*6+nt*8:raise ValueError('mesh header')
    vertices=list(struct.iter_unpack('<hhh',data[20:20+nv*6]))
    if any(abs(c)>16384 for v in vertices for c in v):raise ValueError('vertex range')
    triangles=list(struct.iter_unpack('<HHHBB',data[20+nv*6:]))
    if any(max(a,b,c)>=nv or len({a,b,c})<3 or role>7 or flag for a,b,c,role,flag in triangles):raise ValueError('triangle index/role')
    return nv,nt

def encode(vertices,triangles):
    # Coordinates are centered full-size normalized [-.5,.5].
    points=[]
    for v in vertices:
        if len(v)!=3 or any(not math.isfinite(c) or not -.5<=c<=.5 for c in v):raise ValueError('vertex coordinate')
        points.append(tuple(round(c*32768) for c in v))
    data=struct.pack('<8sHHHHI',b'EKMESH1\0',1,len(points),len(triangles),0,20+len(points)*6+len(triangles)*8)
    data+=b''.join(struct.pack('<hhh',*v) for v in points)
    data+=b''.join(struct.pack('<HHHBB',a,b,c,role,0) for a,b,c,role in triangles)
    validate(data);return data

def convert_obj(source):
    vertices=[];triangles=[];materials={};role=0
    for raw in source.splitlines():
        words=raw.partition('#')[0].split()
        if not words:continue
        if words[0]=='v':
            if len(words)!=4:raise ValueError('OBJ vertex must be XYZ')
            v=tuple(map(float,words[1:]));
            if not all(math.isfinite(c) for c in v):raise ValueError('nonfinite OBJ')
            vertices.append(v)
        elif words[0]=='usemtl':
            if len(words)!=2:raise ValueError('OBJ material')
            name=words[1]
            if name not in materials:materials[name]=len(materials)
            role=materials[name]
            if role>7:raise ValueError('at most 8 material roles')
        elif words[0]=='f':
            if len(words)<4:raise ValueError('OBJ face')
            face=[]
            for item in words[1:]:
                index=int(item.split('/')[0]);index=index-1 if index>0 else len(vertices)+index
                if not 0<=index<len(vertices):raise ValueError('OBJ face index')
                face.append(index)
            for k in range(1,len(face)-1):triangles.append((face[0],face[k],face[k+1],role))
            # Fan triangulation requires convex planar polygons; triangulate
            # concave polygons in the authoring tool before export.
    if not vertices:raise ValueError('empty OBJ')
    low=[min(v[k] for v in vertices) for k in range(3)];high=[max(v[k] for v in vertices) for k in range(3)]
    span=max(b-a for a,b in zip(low,high))
    if not span:raise ValueError('zero OBJ extent')
    points=[tuple((v[k]-(low[k]+high[k])*.5)/span for k in range(3)) for v in vertices]
    return encode(points,triangles),materials

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('source',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    data,materials=convert_obj(a.source.read_text(encoding='utf-8'));a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(data)
    print(f'{a.output}: vertices/triangles={validate(data)}, roles={materials}')
