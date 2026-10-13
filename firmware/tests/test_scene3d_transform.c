/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_scene3d.c"
#include <assert.h>
#include <stdio.h>
static uint32_t seed=0x45ed7381;
static uint32_t random_u32(void){seed=seed*1664525u+1013904223u;return seed;}
int main(void){
 unsigned cases=0;const int edge_values[]={-32768,-32767,-256,-1,0,1,255,256,32766,32767};
 for(unsigned i=0;i<100000;i++){
  EvilKey3DObject o={0};V a;
  float point[3];
  for(unsigned k=0;k<3;k++){
   int coord=i<1000?edge_values[(i/(k==0?1:k==1?10:100))%10]:(int16_t)random_u32();
   point[k]=coord/32768.f;o.scale[k]=i<1000?edge_values[(i+k)%10]:(int16_t)random_u32();
   o.position[k]=(int16_t)random_u32();o.rotation[k]=i%8==0?0:(int)(random_u32()%36001)-18000;
  }
  a=v(point[0],point[1],point[2]);float cs[6];mesh_rotation(&o,cs);MeshTransform t=mesh_transform(&o);
  V original=transformed(a,&o,cs),current=transformed_mesh(a,&o,cs,&t);
  assert(!memcmp(&original,&current,sizeof original));cases++;
 }
 printf("TRANSFORM PASS %u bit-exact Q15/Q8.8 scale/position/all axes/zero+signed boundary+rotations cases\n",cases);
 return 0;
}
