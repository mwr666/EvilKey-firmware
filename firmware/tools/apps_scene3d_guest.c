/* SPDX-License-Identifier: MIT */
#include "evilkey_app_abi.h"
static EvilKeyAppInput input;
static EvilKey3DScene scene;
static struct {uint32_t count;EvilKeyAppCommand commands[3];} out;
static int fault;
uint32_t app_input_ptr(void){return (uint32_t)(uintptr_t)&input;}
uint32_t app_init(void){return (uint32_t)(uintptr_t)&out;}
uint32_t app_step(void){
    scene=(EvilKey3DScene){0};scene.magic=EVILKEY_3D_MAGIC;scene.version=1;scene.object_count=1;scene.material_count=1;
    scene.camera=(EvilKey3DCamera){{0,2048,1536},{0,0,0},50,0,2560,0};
    scene.materials[0]=(EvilKey3DMaterial){0x47d8,0,0};
    scene.objects[0]=(EvilKey3DObject){1,0,{0,0,0},{0,0,0},{256,256,256},0,{0,0}};
    out.count=3;out.commands[0]=(EvilKeyAppCommand){1,0,0,0,280,456,0,0};
    out.commands[1]=(EvilKeyAppCommand){7,0,0,64,280,288,(uint32_t)(uintptr_t)&scene,sizeof(scene)};
    out.commands[2]=(EvilKeyAppCommand){2,0,0,0,280,456,0,0};
    switch(fault){
    case 1:scene.magic=0;break;case 2:scene.object_count=97;break;
    case 3:scene.objects[0].model=0;break;case 4:scene.objects[0].material=8;break;
    case 5:scene.objects[0].scale[0]=0;break;case 6:scene.camera.position[0]=scene.camera.position[1]=scene.camera.position[2]=0;break;
    case 7:scene.flags=1;break;case 8:scene.objects[95].reserved=1;break;
    case 9:out.commands[1].arg0=0xfffffff0u;break;case 10:out.commands[1].width=279;break;
    case 11:out.commands[1].arg1--;break;case 12:scene.materials[7].reserved=1;break;
    case 13:scene.camera.position[1]=2048;scene.camera.position[2]=0;break;
    case 14:scene.object_count=96;for(int i=0;i<96;i++){scene.objects[i]=scene.objects[0];scene.objects[i].model=2;}break;
    case 15:out.commands[2]=out.commands[1];break;
    case 16:scene.objects[0].rotation[0]=18001;break;
    case 17:scene.camera.span=0;break;
    }
    return (uint32_t)(uintptr_t)&out;
}
int32_t probe_fault_next(void){return ++fault;}
int32_t probe_feedback(void){return input.abi==5 && input.reserved[0]==EVILKEY_3D_OK && input.reserved[2]==12;}
