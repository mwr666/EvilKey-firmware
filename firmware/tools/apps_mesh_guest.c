/* SPDX-License-Identifier: MIT */
#include "evilkey_app_abi.h"
static EvilKeyAppInput input;
static EvilKey3DScene scene={.magic=EVILKEY_3D_MAGIC,.version=2,.object_count=1,.material_count=1,
 .camera={{0,2048,1536},{0,0,0},50,0,2560,0},.materials={{0x47d8,0,0}},
 .objects={{.model=0x8000|23,.scale={256,256,256}}}};
static struct {uint32_t count;EvilKeyAppCommand cmd[3];} out;
static int fault;
uint32_t app_input_ptr(void){return (uint32_t)(uintptr_t)&input;}
uint32_t app_init(void){out.count=0;return (uint32_t)(uintptr_t)&out;}
uint32_t app_step(void){
 scene.version=2;scene.flags=0;scene.objects[0].model=0x8000|23;scene.objects[0].reserved2[0]=0;
 out.count=3;out.cmd[0]=(EvilKeyAppCommand){1,0,0,0,280,456,0,0};
 out.cmd[1]=(EvilKeyAppCommand){7,0,0,64,280,288,(uint32_t)(uintptr_t)&scene,sizeof scene};
 out.cmd[2]=(EvilKeyAppCommand){2,0,0,0,280,456,0,0};
 switch(fault){case 1:scene.objects[0].model++;break;case 2:scene.objects[0].reserved2[0]=1;break;
 case 3:scene.version=1;break;case 4:scene.objects[0].model=1;scene.objects[0].reserved2[0]=1;break;
 case 5:out.cmd[2]=(EvilKeyAppCommand){3,0,0,0,0,0,23,0};break;
 case 6:out.cmd[2]=(EvilKeyAppCommand){6,0,0,0,1,1,23,0};break;
 case 7:scene.flags=2;break;case 8:scene.version=1;scene.objects[0].model=1;scene.flags=1;break;}
 return (uint32_t)(uintptr_t)&out;
}
int32_t probe_fault_next(void){return ++fault;}
