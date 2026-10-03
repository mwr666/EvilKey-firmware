/* SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef WS_FT3168_PROBE_H
#define WS_FT3168_PROBE_H
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Read-only startup diagnostics. Register definitions are cross-checked
 * against LILYGO's FT3x68 driver; these values do not prove panel multitouch
 * support. Failed reads stay explicitly unknown, never a synthetic zero. */
typedef struct { uint8_t value[6], valid_mask; } WsFT3168Probe;
typedef bool (*WsFT3168ReadRegister)(uint8_t reg,uint8_t *value,void *context);
static inline WsFT3168Probe ws_ft3168_probe(WsFT3168ReadRegister read,void *context) {
    static const uint8_t regs[]={0xA0,0x00,0xD0,0xA5,0x86,0xB0};
    WsFT3168Probe probe={0};
    if(!read)return probe;
    for(unsigned i=0;i<6;++i) {
        uint8_t value=0;
        if(read(regs[i],&value,context)) {
            probe.value[i]=value;probe.valid_mask|=(uint8_t)(1U<<i);
        }
    }
    return probe;
}
typedef bool (*WsFT3168WriteRegister)(uint8_t reg,uint8_t value,void *context);
typedef enum {
    WS_FT_MONITOR_SKIPPED, WS_FT_MONITOR_UNCHANGED, WS_FT_MONITOR_APPLIED,
    WS_FT_MONITOR_WRITE_FAILED, WS_FT_MONITOR_VERIFY_FAILED
} WsFT3168MonitorResult;
/* Diagnostic experiment, not a documented multitouch enable switch.
 * Controls keep active scanning (0x86=0); every other role restores the
 * observed panel default (1), even after a watchdog/manual reset. This is
 * a volatile operating-mode register, not controller flash/calibration.
 * Unknown devices/register values are never written. */
static inline WsFT3168MonitorResult ws_ft3168_monitor_mode(WsFT3168Probe *probe,
        bool controls,WsFT3168ReadRegister read,WsFT3168WriteRegister write,void *context) {
    const unsigned identity_and_monitor=(1U<<0)|(1U<<4);
    if(!probe || !read || !write ||
       (probe->valid_mask&identity_and_monitor)!=identity_and_monitor ||
       probe->value[0]!=3 || probe->value[4]>1)return WS_FT_MONITOR_SKIPPED;
    /* Do not change a controls panel that is in an unexpected power, device
     * or gesture mode. Restoring the normal default needs only known ID/A. */
    if(controls && ((probe->valid_mask&31U)!=31U || probe->value[1]!=0 ||
                    probe->value[2]!=0 || probe->value[3]!=0))
        return WS_FT_MONITOR_SKIPPED;
    uint8_t desired=controls?0:1;
    if(probe->value[4]==desired)return WS_FT_MONITOR_UNCHANGED;
    bool written=write(0x86,desired,context);
    uint8_t actual=0;
    bool verified=read(0x86,&actual,context);
    if(verified)probe->value[4]=actual;
    else probe->valid_mask&=(uint8_t)~(1U<<4);
    if(!written)return WS_FT_MONITOR_WRITE_FAILED;
    if(!verified || actual!=desired)return WS_FT_MONITOR_VERIFY_FAILED;
    return WS_FT_MONITOR_APPLIED;
}
static inline void ws_ft3168_probe_text(const WsFT3168Probe *probe,char *out,size_t size) {
    char values[6][3];
    for(unsigned i=0;i<6;++i) {
        if(probe->valid_mask&(1U<<i))snprintf(values[i],sizeof(values[i]),"%02X",probe->value[i]);
        else {values[i][0]='-';values[i][1]='-';values[i][2]='\0';}
    }
    snprintf(out,size,"ID:%s D:%s G:%s\nP:%s A:%s X:%s",
             values[0],values[1],values[2],values[3],values[4],values[5]);
}
/* Full 0x00..0x0e frame evidence, independent of accepted touch input.
 * Candidate slots can be stale; never use their count to invent contacts. */
typedef struct {
    uint8_t frame[15], single, single_max, rank;
    bool valid,single_valid;
} WsFT3168FrameEvidence;
static inline unsigned ws_ft3168_candidate_slots(const uint8_t frame[15]) {
    unsigned count=0;uint8_t previous_id=15;
    for(unsigned i=0;i<2;++i) {
        unsigned offset=3+6*i;
        uint8_t event=frame[offset]>>6,id=frame[offset+2]>>4;
        unsigned x=((frame[offset]&15U)<<8)|frame[offset+1];
        unsigned y=((frame[offset+2]&15U)<<8)|frame[offset+3];
        if((event==0 || event==2) && id!=15 && id!=previous_id && x<280 && y<456) {
            ++count;previous_id=id;
        }
    }
    return count;
}
static inline void ws_ft3168_frame_observe(WsFT3168FrameEvidence *e,
        const uint8_t *frame,size_t length,bool single_valid,uint8_t single,bool capture) {
    if(!e || !frame || length!=15)return;
    single&=15;
    if(single_valid && single>e->single_max)e->single_max=single;
    unsigned bulk=frame[2]&15U;
    if(!capture || (!bulk && (!single_valid || !single)))return;
    unsigned candidates=ws_ft3168_candidate_slots(frame);
    unsigned rank=(bulk>=2 || (single_valid && single>=2))?3:(candidates>=2?2:1);
    if(e->valid && rank<e->rank)return;
    memcpy(e->frame,frame,15);e->single=single;e->single_valid=single_valid;
    e->rank=(uint8_t)rank;e->valid=true;
}
static inline void ws_ft3168_frame_text(const WsFT3168FrameEvidence *e,char *out,size_t size) {
    if(!e->valid){snprintf(out,size,"FRAME --");return;}
    char single[4];
    if(e->single_valid)snprintf(single,sizeof(single),"%u",e->single);
    else snprintf(single,sizeof(single),"--");
    unsigned x1=((e->frame[3]&15U)<<8)|e->frame[4];
    unsigned y1=((e->frame[5]&15U)<<8)|e->frame[6];
    unsigned x2=((e->frame[9]&15U)<<8)|e->frame[10];
    unsigned y2=((e->frame[11]&15U)<<8)|e->frame[12];
    snprintf(out,size,"B%u S%s N%u C%u\nE%X/I%X:%u,%u E%X/I%X:%u,%u",
        e->frame[2]&15U,single,e->single_max,ws_ft3168_candidate_slots(e->frame),
        e->frame[3]>>6,e->frame[5]>>4,x1,y1,e->frame[9]>>6,e->frame[11]>>4,x2,y2);
}
#endif
