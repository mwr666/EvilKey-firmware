/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <assert.h>
#include <string.h>
#include "ws_ft3168_probe.h"
typedef struct {unsigned calls;unsigned fail_mask;} Reader;
static bool read_register(uint8_t reg,uint8_t *out,void *context) {
    static const uint8_t expected[]={0xA0,0x00,0xD0,0xA5,0x86,0xB0};
    static const uint8_t values[]={3,0,0,0,1,0};
    Reader *r=context;assert(r->calls<6);unsigned i=r->calls++;
    assert(reg==expected[i]);*out=values[i];return !(r->fail_mask&(1U<<i));
}
typedef struct {
    uint8_t monitor; unsigned reads,writes;
    bool fail_read,fail_write,ignore_write;
} Monitor;
static bool monitor_read(uint8_t reg,uint8_t *out,void *context) {
    Monitor *m=context;assert(reg==0x86);++m->reads;*out=m->monitor;
    return !m->fail_read;
}
static bool monitor_write(uint8_t reg,uint8_t value,void *context) {
    Monitor *m=context;assert(reg==0x86 && value<=1);++m->writes;
    if(!m->fail_write && !m->ignore_write)m->monitor=value;
    return !m->fail_write;
}
static WsFT3168Probe normal_probe(void) {
    WsFT3168Probe p={{3,0,0,0,1,0},63};return p;
}
static void monitor_tests(void) {
    WsFT3168Probe p=normal_probe();Monitor m={.monitor=1};
    assert(ws_ft3168_monitor_mode(&p,true,monitor_read,monitor_write,&m)==WS_FT_MONITOR_APPLIED);
    assert(m.monitor==0 && p.value[4]==0 && m.reads==1 && m.writes==1);
    /* No repeated writes while controls run; a fresh normal boot restores
     * baseline without depending on RAM/RTC survival or a clean exit. */
    assert(ws_ft3168_monitor_mode(&p,true,monitor_read,monitor_write,&m)==WS_FT_MONITOR_UNCHANGED);
    assert(m.writes==1);
    assert(ws_ft3168_monitor_mode(&p,false,monitor_read,monitor_write,&m)==WS_FT_MONITOR_APPLIED);
    assert(m.monitor==1 && p.value[4]==1 && m.writes==2);
    assert(ws_ft3168_monitor_mode(&p,false,monitor_read,monitor_write,&m)==WS_FT_MONITOR_UNCHANGED);
    /* Unknown identities, monitor values or controls modes never get writes. */
    for(unsigned i=0;i<6;++i) {
        p=normal_probe();m=(Monitor){.monitor=1};
        if(i==0)p.value[0]=2;
        if(i==1)p.value[4]=2;
        if(i==2)p.valid_mask&=(uint8_t)~1U;
        if(i==3)p.value[1]=1;
        if(i==4)p.value[2]=1;
        if(i==5)p.value[3]=1;
        assert(ws_ft3168_monitor_mode(&p,true,monitor_read,monitor_write,&m)==WS_FT_MONITOR_SKIPPED);
        assert(m.writes==0 && m.reads==0);
    }
    p=normal_probe();m=(Monitor){.monitor=1,.fail_write=true};
    assert(ws_ft3168_monitor_mode(&p,true,monitor_read,monitor_write,&m)==WS_FT_MONITOR_WRITE_FAILED);
    assert(p.value[4]==1 && m.reads==1);
    p=normal_probe();m=(Monitor){.monitor=1,.ignore_write=true};
    assert(ws_ft3168_monitor_mode(&p,true,monitor_read,monitor_write,&m)==WS_FT_MONITOR_VERIFY_FAILED);
    assert(p.value[4]==1);
    p=normal_probe();m=(Monitor){.monitor=1,.fail_read=true};
    assert(ws_ft3168_monitor_mode(&p,true,monitor_read,monitor_write,&m)==WS_FT_MONITOR_VERIFY_FAILED);
    assert(!(p.valid_mask&(1U<<4)));
    char text[80];ws_ft3168_probe_text(&p,text,sizeof(text));assert(strstr(text,"A:--"));
    p=normal_probe();p.value[4]=0;m=(Monitor){.monitor=0,.ignore_write=true};
    assert(ws_ft3168_monitor_mode(&p,false,monitor_read,monitor_write,&m)==WS_FT_MONITOR_VERIFY_FAILED);
    assert(p.value[4]==0);
}
static void frame_tests(void) {
    /* Slot 1: CONTACT, id0, 112/38. Slot 2 initially unused (event3/idF). */
    uint8_t f[15]={0,0,1,0x80,112,0,38,0,0,0xff,0xff,0xff,0xff,0,0};
    WsFT3168FrameEvidence e={0};char text[96];
    ws_ft3168_frame_text(&e,text,sizeof(text));assert(strcmp(text,"FRAME --")==0);
    assert(ws_ft3168_candidate_slots(f)==1);
    ws_ft3168_frame_observe(&e,f,14,true,1,true);assert(!e.valid);
    ws_ft3168_frame_observe(&e,f,15,true,1,true);
    ws_ft3168_frame_text(&e,text,sizeof(text));
    assert(strcmp(text,"B1 S1 N1 C1\nE2/I0:112,38 E3/IF:4095,4095")==0);
    /* Inspect a second record despite count=1, but don't treat it as input. */
    f[9]=0x80;f[10]=220;f[11]=0x10;f[12]=40;
    assert(ws_ft3168_candidate_slots(f)==2);
    ws_ft3168_frame_observe(&e,f,15,true,1,true);assert(e.rank==2 && e.frame[2]==1);
    /* Release events and duplicate identities never count as two candidates. */
    f[9]=0x40;assert(ws_ft3168_candidate_slots(f)==1);
    f[9]=0x80;f[11]=0;assert(ws_ft3168_candidate_slots(f)==1);
    f[11]=0x1f;assert(ws_ft3168_candidate_slots(f)==1); /* Out-of-bounds y. */
    f[11]=0x10;
    /* Independent status may reveal a different count than burst status. */
    ws_ft3168_frame_observe(&e,f,15,true,2,true);
    assert(e.rank==3 && e.single_max==2 && e.single==2 && e.frame[2]==1);
    WsFT3168FrameEvidence kept=e;
    f[2]=1;f[9]=0xff;f[11]=0xff;
    ws_ft3168_frame_observe(&e,f,15,true,1,true);assert(memcmp(&e,&kept,sizeof(e))==0);
    ws_ft3168_frame_observe(&e,f,15,true,1,false);assert(memcmp(&e,&kept,sizeof(e))==0);
    /* Settings cannot overwrite the retained gameplay evidence. */
    f[2]=2;ws_ft3168_frame_observe(&e,f,15,true,2,false);assert(memcmp(&e,&kept,sizeof(e))==0);
    ws_ft3168_frame_observe(&e,f,15,false,0,true);
    ws_ft3168_frame_text(&e,text,sizeof(text));assert(strstr(text,"B2 S-- N2 C1"));
    char tiny[4];ws_ft3168_frame_text(&e,tiny,sizeof(tiny));assert(tiny[3]=='\0');
}
int main(void) {
    Reader r={0};WsFT3168Probe probe=ws_ft3168_probe(read_register,&r);
    assert(r.calls==6 && probe.valid_mask==63);
    char text[80];ws_ft3168_probe_text(&probe,text,sizeof(text));
    assert(strcmp(text,"ID:03 D:00 G:00\nP:00 A:01 X:00")==0);
    r=(Reader){.fail_mask=1U|8U};probe=ws_ft3168_probe(read_register,&r);
    assert(r.calls==6 && probe.valid_mask==(63U&~9U));
    ws_ft3168_probe_text(&probe,text,sizeof(text));
    assert(strcmp(text,"ID:-- D:00 G:00\nP:-- A:01 X:00")==0);
    probe=ws_ft3168_probe(NULL,NULL);assert(probe.valid_mask==0);
    char tiny[4];ws_ft3168_probe_text(&probe,tiny,sizeof(tiny));assert(tiny[3]=='\0');
    monitor_tests();
    frame_tests();
    puts("PASS: FT3168 mode restoration, independent count/frame evidence, slot IDs/events, bounds and retained gameplay samples");
}
