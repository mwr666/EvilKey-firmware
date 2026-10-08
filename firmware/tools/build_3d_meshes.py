#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Bake indexed GUI models, normals and logo triangulation; no runtime topology."""
import json
from math import cos, sin, pi, hypot, sqrt
from pathlib import Path
from build_settings_icon_asset import gear_outline, SIZE, SCALE

ROOT = Path(__file__).resolve().parents[1]

def simplify(points, tolerance):
    def distance(p, a, b):
        dx, dy = b[0]-a[0], b[1]-a[1]
        t = max(0, min(1, ((p[0]-a[0])*dx+(p[1]-a[1])*dy)/(dx*dx+dy*dy))) if dx or dy else 0
        return hypot(p[0]-a[0]-t*dx, p[1]-a[1]-t*dy)
    def part(p):
        if len(p) < 3: return p
        d, k = max((distance(v, p[0], p[-1]), i) for i,v in enumerate(p[1:-1],1))
        return part(p[:k+1])[:-1]+part(p[k:]) if d > tolerance else [p[0],p[-1]]
    middle = len(points)//2
    result = part(points[:middle+1])[:-1]+part(points[middle:]+points[:1])[:-1]
    error = max(min(distance(p,a,result[(i+1)%len(result)]) for i,a in enumerate(result)) for p in points)
    assert error <= tolerance+1e-9
    return result, error

class Mesh:
    def __init__(self): self.vertices=[]; self.lookup={}; self.faces=[]
    def vertex(self, p):
        p=tuple(round(x,6) for x in p)
        if p not in self.lookup: self.lookup[p]=len(self.vertices); self.vertices.append(p)
        return self.lookup[p]
    def tri(self,a,b,c, material=0,tone=255,light=1):
        u=[b[i]-a[i] for i in range(3)];v=[c[i]-a[i] for i in range(3)]
        n=[u[1]*v[2]-u[2]*v[1],u[2]*v[0]-u[0]*v[2],u[0]*v[1]-u[1]*v[0]]
        length=sqrt(sum(x*x for x in n))
        if length < .001: return
        self.faces.append((self.vertex(a),self.vertex(b),self.vertex(c),*[x/length for x in n],material,tone,light))
    def quad(self,a,b,c,d,**kw): self.tri(a,b,c,**kw);self.tri(a,c,d,**kw)
    def ring(self,r,inner,z,tone):
        for i in range(32):
            a=i*2*pi/32;b=(i+1)*2*pi/32
            p=(r*cos(a),r*sin(a),z);q=(r*cos(b),r*sin(b),z)
            self.quad(p,q,(inner*cos(b),inner*sin(b),z),(inner*cos(a),inner*sin(a),z),tone=tone)
            self.quad(p,q,(q[0],q[1],z+1.2),(p[0],p[1],z+1.2),tone=tone*100//255)

def gear():
    original=[(x/SCALE-SIZE/2,y/SCALE-SIZE/2) for x,y in gear_outline()]
    points,error=simplify(original,.25)
    normals=[]
    for i,a in enumerate(points):
        p,q=points[i-1],points[(i+1)%len(points)]; dx=q[0]-p[0];dy=q[1]-p[1];l=hypot(dx,dy)
        normals.append((dy/l,-dx/l))
    m=Mesh()
    for i,a in enumerate(points):
        j=(i+1)%len(points);b=points[j];an,bn=normals[i],normals[j];al=hypot(*a);bl=hypot(*b)
        m.quad((*a,0),(*b,0),(b[0]*24/bl,b[1]*24/bl,0),(a[0]*24/al,a[1]*24/al,0),tone=38)
        ao=(a[0]+an[0],a[1]+an[1],-.1);bo=(b[0]+bn[0],b[1]+bn[1],-.1)
        m.quad(ao,bo,(b[0]-bn[0],b[1]-bn[1],-.1),(a[0]-an[0],a[1]-an[1],-.1),tone=240)
        ab=(a[0]+.35*an[0],a[1]+.35*an[1],1.2);bb=(b[0]+.35*bn[0],b[1]+.35*bn[1],1.2)
        m.quad(ao,bo,bb,ab,tone=210,light=2)
        m.quad(ab,bb,(*bb[:2],24),(*ab[:2],24),tone=150,light=2)
    m.ring(24,23,-.2,84);m.ring(23,14,0,22);m.ring(14,12,-.2,240)
    for i in range(32):
        a=i*2*pi/32;b=(i+1)*2*pi/32
        m.quad((12*cos(a),12*sin(a),0),(12*cos(b),12*sin(b),0),(12*cos(b),12*sin(b),24),(12*cos(a),12*sin(a),24),tone=160,light=2)
    return m, {'contour_vertices':len(points),'max_contour_error_px':error}

def apps():
    m=Mesh()
    def point(k,z,inset):
        corner=k//4;angle=(k+8)*2*pi/16
        return ((5,21,21,5)[corner]+(5-inset)*cos(angle),(5,5,21,21)[corner]+(5-inset)*sin(angle),z)
    for i in range(16):
        j=(i+1)%16
        m.quad(point(i,0,0),point(j,0,0),point(j,1.2,.8),point(i,1.2,.8),material=1,tone=190,light=2)
        m.quad(point(i,1.2,.8),point(j,1.2,.8),point(j,24,.8),point(i,24,.8),material=1,tone=135,light=2)
        m.quad(point(i,0,0),point(j,0,0),point(j,0,1),point(i,0,1),material=1)
        m.tri((13,13,0),point(j,0,1),point(i,0,1),material=2)
    return m

def logo():
    m=Mesh();p=[(0,-88),(61,-28),(61,60),(14,23),(32,6),(32,-11),(0,-43),(-32,-11),(-32,6),(-14,23),(-61,60),(-61,-28)]
    cross=lambda a,b,c:(b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0])
    sign=1 if sum(p[i][0]*p[(i+1)%12][1]-p[(i+1)%12][0]*p[i][1] for i in range(12))>0 else -1
    inset=[]
    for i,cur in enumerate(p):
        prev=p[i-1];nxt=p[(i+1)%12];dx=cur[0]-prev[0];dy=cur[1]-prev[1];l=hypot(dx,dy);ax=-dy/l*sign;ay=dx/l*sign
        dx=nxt[0]-cur[0];dy=nxt[1]-cur[1];l=hypot(dx,dy);bx=-dy/l*sign;by=dx/l*sign;f=2/max(.25,1+ax*bx+ay*by)
        inset.append((cur[0]+(ax+bx)*f,cur[1]+(ay+by)*f,-6))
    ids=list(range(12))
    while len(ids)>2:
        for k,ib in enumerate(ids):
            ia=ids[k-1];ic=ids[(k+1)%len(ids)];a,b,c=p[ia],p[ib],p[ic]
            if cross(a,b,c)*sign<=.001:continue
            if any(cross(a,p[j],b)*(-sign)>=0 and cross(b,p[j],c)*(-sign)>=0 and cross(c,p[j],a)*(-sign)>=0 for j in ids if j not in (ia,ib,ic)):continue
            m.tri(inset[ia],inset[ib],inset[ic],light=1);m.tri((*c,5),(*b,5),(*a,5),light=1);ids.pop(k);break
        else:raise RuntimeError('Logo triangulation failed')
    for i,a in enumerate(p):
        j=(i+1)%12;b=p[j]
        m.quad((*a,-2),(*b,-2),(*b,5),(*a,5),light=1)
        m.quad((*a,-2),inset[i],inset[j],(*b,-2),light=1)
    return m

def main():
    g,quality=gear();models={'GEAR':g,'APP_TILE':apps(),'LOGO':logo()}
    lines=['/* SPDX-License-Identifier: AGPL-3.0-or-later', ' * Generated by build_3d_meshes.py; original outlines, depth=24. */','#pragma once',
        'struct WsMeshVertex { float x,y,z; };',
        'struct WsMeshNormal { float nx,ny,nz; };',
        'struct WsMeshShade { uint16_t normal; uint8_t material,tone,light; };',
        'struct WsMeshFace { uint16_t a,b,c,shade; };',
        'struct WsMesh { const WsMeshVertex *vertices; const WsMeshNormal *normals; const WsMeshShade *shades; const WsMeshFace *faces; unsigned vertex_count,normal_count,shade_count,face_count; };']
    for name,m in models.items():
        lines.append(f'static constexpr WsMeshVertex WS_{name}_VERTICES[]={{')
        for p in m.vertices:lines.append('    {'+','.join(f'{x:.6f}f' for x in p)+'},')
        lines.append('};')
        normals={};shades={};indexed=[]
        for a,b,c,nx,ny,nz,mat,tone,light in m.faces:
            # Keys use exactly the old emitted decimal floats. No normal or
            # face order changes are introduced by grouping.
            normal=tuple(f'{v:.8f}' for v in (nx,ny,nz))
            ni=normals.setdefault(normal,len(normals))
            si=shades.setdefault((ni,mat,tone,light),len(shades))
            indexed.append((a,b,c,si))
        lines.append(f'static constexpr WsMeshNormal WS_{name}_NORMALS[]={{')
        lines.extend('    {'+','.join(v+'f' for v in n)+'},' for n in normals)
        lines.append('};');lines.append(f'static constexpr WsMeshShade WS_{name}_SHADES[]={{')
        lines.extend('    {'+','.join(map(str,s))+'},' for s in shades)
        lines.append('};');lines.append(f'static constexpr WsMeshFace WS_{name}_FACES[]={{')
        lines.extend('    {'+','.join(map(str,f))+'},' for f in indexed)
        lines.append('};')
        lines.append(f'static constexpr WsMesh WS_{name}_MESH={{WS_{name}_VERTICES,WS_{name}_NORMALS,WS_{name}_SHADES,WS_{name}_FACES,{len(m.vertices)},{len(normals)},{len(shades)},{len(m.faces)}}};')
    (ROOT/'templates/port/ws_gui_3d_meshes.h').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    report={name:{'vertices':len(m.vertices),'faces':len(m.faces)} for name,m in models.items()};report['quality']=quality
    out=ROOT/'build/performance-analysis';out.mkdir(parents=True,exist_ok=True)
    (out/'mesh-generation.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
if __name__=='__main__':main()
