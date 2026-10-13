/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Bounded, allocation-free run accounting. Caller owns synchronization/clock.
 */
#pragma once
#include "ek_scene3d.h"
#include <stdio.h>

enum { EK_RUN_COUNTDOWN=1,EK_RUN_ACTIVE=2,EK_RUN_PAUSED=3,
       EK_RUN_COMPLETE=4,EK_RUN_FAULT=5,EK_RUN_ABANDONED=6 };
typedef struct {
    char app_id[32],version[20],program_sha256[65];
    uint32_t wasm_bytes,asset_bytes,asset_count,resource_total_bytes,native_context_bytes;
} EkRunIdentity;
typedef struct {uint32_t bins[64],count,max_us;} EkRunHistogram;
enum {EK_STAGE_GUEST,EK_STAGE_OUTPUT,EK_STAGE_NATIVE_WALL,EK_STAGE_DISPLAY_WALL,
      EK_STAGE_SNAPSHOT_COPY,EK_STAGE_OUTPUT_VALIDATE,EK_STAGE_OUTPUT_DRAW,EK_STAGE_OUTPUT_PRESENT,
      EK_STAGE_NATIVE_QUEUE,EK_STAGE_NATIVE_PRECOPY,EK_STAGE_NATIVE_RECONSTRUCT,
      EK_STAGE_DISPLAY_QUEUE,EK_STAGE_DISPLAY_PREPARE,EK_STAGE_STREAM_COPY,EK_STAGE_STREAM_IO,EK_STAGE_COUNT};
typedef struct {uint64_t total_us;uint32_t max_us,count;} EkRunStage;
static inline void ek_run_hist(EkRunHistogram *h,uint32_t us,uint32_t quantum){
    unsigned bin=us/quantum;if(bin>63)bin=63;++h->bins[bin];++h->count;
    if(us>h->max_us)h->max_us=us;
}
static inline uint32_t ek_run_percentile(const EkRunHistogram *h,unsigned pct,uint32_t quantum){
    if(!h->count)return 0;
    uint64_t rank=((uint64_t)h->count*pct+99)/100,sum=0;
    for(unsigned i=0;i<64;i++){sum+=h->bins[i];if(sum>=rank){
        uint32_t upper=i==63?h->max_us:(i+1)*quantum-1;
        return upper<h->max_us?upper:h->max_us;
    }}
    return h->max_us;
}
typedef struct {
    EkRunIdentity identity;
    uint32_t draw_lvgl_count; /* Existing alignment padding before64-bit fields. */
    uint64_t active_us,window_at_us,last_frame_active_us;
    uint32_t sequence,epoch,tag,phase,partial,valid;
    uint32_t produced,completed,window_frames,windows,min_millifps,max_frame_gap_us;
    uint32_t attempts,timeouts,work_faults,other_faults,over_budget,display_failures;
    uint32_t max_total_us,max_copy_us,max_wait_us,max_objects,max_materials,max_faces;
    uint32_t max_pixels,max_gas,max_memory,telemetry_errors,vm_errors;
    EkSceneProfile max_precopy,first_fault;
    EkRunHistogram native_hist,gap_hist,end_to_end_hist;
    EkRunStage stages[EK_STAGE_COUNT];
    uint32_t draw_total_us[5],draw_count_flags;
    uint32_t mixed_frames,full_frames,cadence_8ms_frames,cadence_50ms_frames;
} EkRunRecord;
typedef struct {
    EkRunRecord record[2];
    EkRunIdentity identity;
    uint64_t last_wall_us;
    uint32_t sequence;
    int current;
    uint32_t modal;
} EkRunMetrics;
typedef struct {uint32_t sequence,scene,eligible;uint64_t started_us;} EkRunFrame;
static inline uint32_t ek_run_sat(uint64_t n){return n>UINT32_MAX?UINT32_MAX:(uint32_t)n;}
static inline uint32_t ek_run_precopy(const EkSceneProfile *p){
    return p->stats.elapsed_us>=p->reconstruct_us?p->stats.elapsed_us-p->reconstruct_us:0;
}
static inline uint32_t ek_run_fps(uint32_t frames,uint64_t us){
    return us?ek_run_sat((uint64_t)frames*1000000000ULL/us):0;
}
static inline EkRunRecord *ek_run_current(EkRunMetrics *m){
    return m->current>=0&&m->current<2?&m->record[m->current]:NULL;
}
static inline void ek_run_stage(EkRunRecord *r,unsigned stage,uint32_t us){
    if(!r||stage>=EK_STAGE_COUNT)return;
    EkRunStage *s=&r->stages[stage];if(s->count==UINT32_MAX)return;
    ++s->count;if(us>s->max_us)s->max_us=us;
    s->total_us=UINT64_MAX-s->total_us<us?UINT64_MAX:s->total_us+us;
}
static inline void ek_run_active_stage(EkRunMetrics *m,unsigned stage,uint32_t us){
    EkRunRecord *r=ek_run_current(m);
    if(r&&r->phase==EK_RUN_ACTIVE&&!m->modal)ek_run_stage(r,stage,us);
}
/* Compact optional diagnostics; saturate explicitly without changing gameplay. */
static inline uint32_t ek_run_draw_count(const EkRunRecord *r){return r->draw_count_flags&0x3fffffffu;}
static inline uint32_t ek_run_draw_flags(const EkRunRecord *r){return r->draw_count_flags>>30;}
static inline void ek_run_draw_sum(EkRunRecord *r,unsigned group,uint32_t us){
    if(!r||group>=5)return;
    uint32_t *total=&r->draw_total_us[group];
    if(UINT32_MAX-*total<us){*total=UINT32_MAX;r->draw_count_flags|=0x40000000u;}
    else *total+=us;
}
static inline void ek_run_draw(EkRunMetrics *m,const uint32_t groups[4]){
    EkRunRecord *r=ek_run_current(m);
    if(!r||r->phase!=EK_RUN_ACTIVE||m->modal||!groups)return;
    if(ek_run_draw_count(r)==0x3fffffffu)r->draw_count_flags|=0x40000000u;
    else ++r->draw_count_flags;
    for(unsigned g=0;g<4;g++)ek_run_draw_sum(r,g,groups[g]);
}
static inline void ek_run_advance(EkRunMetrics *m,uint64_t now){
    EkRunRecord *r=ek_run_current(m);
    if(r&&r->phase==EK_RUN_ACTIVE&&!m->modal&&now>=m->last_wall_us){
        r->active_us+=now-m->last_wall_us;
        uint64_t span=r->active_us-r->window_at_us;
        if(span>=1000000){
            uint32_t full=(uint32_t)(span/1000000);
            uint32_t fps=full>1?0:(r->completed-r->window_frames)*1000;
            if(!r->windows||fps<r->min_millifps)r->min_millifps=fps;
            r->windows+=full;r->window_at_us+=(uint64_t)full*1000000;r->window_frames=r->completed;
        }
        uint64_t gap=r->active_us-r->last_frame_active_us;
        if(gap>r->max_frame_gap_us)r->max_frame_gap_us=gap>UINT32_MAX?UINT32_MAX:(uint32_t)gap;
    }
    m->last_wall_us=now;
}
static inline void ek_run_identity(EkRunMetrics *m,const EkRunIdentity *identity,uint64_t now){
    ek_run_advance(m,now);
    EkRunRecord *r=ek_run_current(m);
    if(r&&r->phase!=EK_RUN_COMPLETE&&r->phase!=EK_RUN_FAULT)r->phase=EK_RUN_ABANDONED;
    m->identity=*identity;m->current=-1;m->modal=0;m->last_wall_us=now;
}
static inline void ek_run_invalid(EkRunMetrics *m,uint64_t now){
    ek_run_advance(m,now);EkRunRecord *r=ek_run_current(m);
    if(r){r->valid=0;++r->telemetry_errors;}
}
static inline void ek_run_token(EkRunMetrics *m,uint32_t token,uint32_t gas,uint32_t memory,uint64_t now){
    ek_run_advance(m,now);
    if(!token)return;
    uint32_t epoch=token&0x7fffffu,partial=(token>>23)&1,tag=(token>>24)&15,phase=token>>28;
    if(!epoch||!tag||phase<1||phase>6){ek_run_invalid(m,now);return;}
    EkRunRecord *r=ek_run_current(m);
    if(!r||r->epoch!=epoch||r->tag!=tag){
        if(r&&r->phase!=EK_RUN_COMPLETE&&r->phase!=EK_RUN_FAULT)r->phase=EK_RUN_ABANDONED;
        int slot=-1;
        for(int i=0;i<2;i++)if(m->record[i].tag==tag&&!strcmp(m->record[i].identity.app_id,m->identity.app_id))slot=i;
        if(slot<0)slot=!m->record[0].sequence?0:!m->record[1].sequence?1:
            m->record[0].sequence<m->record[1].sequence?0:1;
        m->current=slot;r=&m->record[slot];memset(r,0,sizeof(*r));
        r->identity=m->identity;r->epoch=epoch;r->tag=tag;r->partial=partial;r->valid=1;
        if(!++m->sequence)++m->sequence;r->sequence=m->sequence;
    }else if(r->partial!=partial||(r->phase==EK_RUN_COMPLETE&&phase!=EK_RUN_COMPLETE)){
        ek_run_invalid(m,now);return;
    }
    r->phase=phase;if(gas>r->max_gas)r->max_gas=gas;
    if(memory>r->max_memory)r->max_memory=memory;
}
static inline void ek_run_modal(EkRunMetrics *m,unsigned modal,uint64_t now){
    ek_run_advance(m,now);m->modal=modal?1u:0u;
}
static inline void ek_run_stop(EkRunMetrics *m,unsigned vm_error,uint64_t now){
    ek_run_advance(m,now);EkRunRecord *r=ek_run_current(m);
    if(r){
        if(vm_error){++r->vm_errors;r->valid=0;}
        if(r->phase!=EK_RUN_COMPLETE&&r->phase!=EK_RUN_FAULT)r->phase=EK_RUN_ABANDONED;
    }
}
static inline EkRunFrame ek_run_native(EkRunMetrics *m,const EkSceneProfile *p,
        uint32_t scene,uint32_t wait,uint32_t objects,uint32_t materials,uint32_t faces,uint64_t now){
    EkRunFrame frame={0};ek_run_advance(m,now);EkRunRecord *r=ek_run_current(m);
    if(!r||r->phase==EK_RUN_COMPLETE||r->phase==EK_RUN_ABANDONED)return frame;
    ++r->attempts;
    ek_run_hist(&r->native_hist,ek_run_precopy(p),512);
    if(r->attempts==1||ek_run_precopy(p)>ek_run_precopy(&r->max_precopy))r->max_precopy=*p;
    if(ek_run_precopy(p)>20000)++r->over_budget;
    if(p->stats.status!=EVILKEY_3D_OK){
        if(!r->first_fault.stats.status)r->first_fault=*p;
        if(p->stats.status==EVILKEY_3D_TIMEOUT)++r->timeouts;
        else if(p->stats.status==EVILKEY_3D_WORK_LIMIT)++r->work_faults;
        else ++r->other_faults;
    }
#define EK_RUN_MAX(field,value) do{if((value)>r->field)r->field=(value);}while(0)
    EK_RUN_MAX(max_total_us,p->stats.elapsed_us);EK_RUN_MAX(max_copy_us,p->reconstruct_us);
    EK_RUN_MAX(max_wait_us,wait);EK_RUN_MAX(max_objects,objects);EK_RUN_MAX(max_materials,materials);
    EK_RUN_MAX(max_faces,faces);EK_RUN_MAX(max_pixels,p->stats.pixel_tests);
#undef EK_RUN_MAX
    if(p->stats.status==EVILKEY_3D_OK){frame.sequence=r->sequence;frame.scene=scene;
        frame.eligible=r->phase==EK_RUN_ACTIVE&&!m->modal;}
    return frame;
}
static inline EkRunFrame ek_run_present(EkRunMetrics *m,EkRunFrame *pending,uint64_t now){
    ek_run_advance(m,now);EkRunRecord *r=ek_run_current(m);EkRunFrame front=*pending;
    memset(pending,0,sizeof(*pending));
    if(!r||front.sequence!=r->sequence||!front.eligible||r->phase!=EK_RUN_ACTIVE||m->modal)
        memset(&front,0,sizeof(front));
    else ++r->produced;
    return front;
}
static inline void ek_run_display(EkRunMetrics *m,EkRunFrame *ticket,unsigned success,uint64_t now){
    ek_run_advance(m,now);EkRunRecord *r=ek_run_current(m);EkRunFrame f=*ticket;
    memset(ticket,0,sizeof(*ticket));
    if(!r||f.sequence!=r->sequence||!f.eligible||!f.scene)return;
    if(!success){++r->display_failures;return;}
    if(r->phase!=EK_RUN_ACTIVE||m->modal)return;
    ++r->completed;
    uint32_t gap=ek_run_sat(r->active_us-r->last_frame_active_us);
    if(gap>r->max_frame_gap_us)r->max_frame_gap_us=gap;
    r->last_frame_active_us=r->active_us;
    ek_run_hist(&r->gap_hist,gap,4096);
    if(now>=f.started_us)ek_run_hist(&r->end_to_end_hist,ek_run_sat(now-f.started_us),4096);
}
static inline void ek_run_display_profile(EkRunMetrics *m,EkRunFrame *ticket,
    unsigned success,uint64_t now,uint32_t display_us,uint32_t copy_us,unsigned method){
    EkRunRecord *r=ek_run_current(m);uint32_t before=r?r->completed:0;
    ek_run_display(m,ticket,success,now);
    if(r&&r==ek_run_current(m)&&r->completed!=before){
        ek_run_stage(r,EK_STAGE_DISPLAY_WALL,display_us);
        ek_run_stage(r,EK_STAGE_SNAPSHOT_COPY,copy_us);
        if(method==4||method==5)++r->mixed_frames;else ++r->full_frames;
    }
}
/* Only call for the same consumed final-DMA ticket as display_profile. */
static inline void ek_run_display_detail(EkRunRecord *r,const uint32_t detail[4],unsigned cadence){
    if(!r||!detail)return;
    for(unsigned i=0;i<4;i++)ek_run_stage(r,EK_STAGE_DISPLAY_QUEUE+i,detail[i]);
    if(cadence==8)++r->cadence_8ms_frames;
    else if(cadence==50)++r->cadence_50ms_frames;
    else {r->valid=0;++r->telemetry_errors;}
}
/* Pure serializer: all identity values originate in validated package fields. */
static inline int ek_run_report(char *out,size_t capacity,const EkRunMetrics *m){
    size_t used=0;
    for(unsigned i=0;i<2;i++){
        const EkRunRecord *r=&m->record[i];
        int n=snprintf(out+used,capacity>used?capacity-used:0,
            "\n[app.run%u]\nsequence=%u\napp_id=%s\napp_version=%s\nprogram_sha256=%s\n"
            "tag=%u\nepoch=%u\nphase=%u\npartial=%u\nvalid=%u\nwasm_bytes=%u\nasset_bytes=%u\nasset_count=%u\nresource_total_bytes=%u\nnative_context_bytes=%u\n"
            "active_us=%llu\nproduced_new_frames=%u\ncompleted_new_frames=%u\navg_millifps=%u\n"
            "min_window_millifps=%u\nfull_windows=%u\nmax_new_frame_gap_us=%u\n"
            "native_attempts=%u\nnative_precopy_max_us=%u\nnative_total_max_us=%u\nnative_copy_max_us=%u\n"
            "native_wait_max_us=%u\ntimeouts=%u\nwork_faults=%u\nother_faults=%u\nover_budget=%u\n"
            "display_failures=%u\nvm_errors=%u\ntelemetry_errors=%u\n"
            "max_objects=%u\nmax_materials=%u\nmax_faces=%u\nmax_pixel_tests=%u\nmax_app_gas=%u\nmax_linear_memory_bytes=%u\n"
            "max_profile_status=%u\nmax_profile_elapsed_us=%u\nmax_profile_clear_us=%u\nmax_profile_camera_us=%u\n"
            "max_profile_geometry_us=%u\nmax_profile_raster_us=%u\nmax_profile_copy_us=%u\n"
            "first_fault_status=%u\nfirst_fault_elapsed_us=%u\nfirst_fault_precopy_us=%u\n"
            "first_fault_clear_us=%u\nfirst_fault_camera_us=%u\nfirst_fault_geometry_us=%u\n"
            "first_fault_raster_us=%u\nfirst_fault_copy_us=%u\nfirst_fault_triangles=%u\nfirst_fault_pixel_tests=%u\n",
            i,r->sequence,r->identity.app_id,r->identity.version,r->identity.program_sha256,
            r->tag,r->epoch,r->phase,r->partial,r->valid,r->identity.wasm_bytes,r->identity.asset_bytes,r->identity.asset_count,r->identity.resource_total_bytes,r->identity.native_context_bytes,
            (unsigned long long)r->active_us,r->produced,r->completed,ek_run_fps(r->completed,r->active_us),
            r->min_millifps,r->windows,r->max_frame_gap_us,r->attempts,ek_run_precopy(&r->max_precopy),r->max_total_us,r->max_copy_us,
            r->max_wait_us,r->timeouts,r->work_faults,r->other_faults,r->over_budget,r->display_failures,r->vm_errors,r->telemetry_errors,
            r->max_objects,r->max_materials,r->max_faces,r->max_pixels,r->max_gas,r->max_memory,
            r->max_precopy.stats.status,r->max_precopy.stats.elapsed_us,r->max_precopy.clear_us,r->max_precopy.setup_us,
            r->max_precopy.geometry_us,r->max_precopy.raster_us,r->max_precopy.reconstruct_us,
            r->first_fault.stats.status,r->first_fault.stats.elapsed_us,ek_run_precopy(&r->first_fault),
            r->first_fault.clear_us,r->first_fault.setup_us,r->first_fault.geometry_us,r->first_fault.raster_us,
            r->first_fault.reconstruct_us,r->first_fault.stats.triangles,r->first_fault.stats.pixel_tests);
        if(n<0||(size_t)n>=capacity-used)return -1;used+=(size_t)n;
        n=snprintf(out+used,capacity-used,"draw_profile_version=2\ndraw_sampling_interval=32\nstage_profile_version=2\nsnapshot_mixed_frames=%u\nsnapshot_full_frames=%u\ncadence_8ms_frames=%u\ncadence_50ms_frames=%u\n",
                   r->mixed_frames,r->full_frames,r->cadence_8ms_frames,r->cadence_50ms_frames);
        if(n<0||(size_t)n>=capacity-used)return -1;used+=(size_t)n;
        static const char *const names[]={"guest","output","native_wall","display_wall","snapshot_copy",
            "output_validate","output_draw","output_present","native_queue","native_precopy","native_reconstruct",
            "display_queue","display_prepare","stream_copy","stream_io"};
        for(unsigned stage=0;stage<EK_STAGE_COUNT;stage++){
            const EkRunStage *s=&r->stages[stage];
            if(stage>=EK_STAGE_OUTPUT_VALIDATE)
                n=snprintf(out+used,capacity-used,"detail_%s=%u,%llu,%u,%llu\n",names[stage],s->count,
                    (unsigned long long)s->total_us,s->max_us,(unsigned long long)(s->count?s->total_us/s->count:0));
            else n=snprintf(out+used,capacity-used,"%s_count=%u\n%s_total_us=%llu\n%s_max_us=%u\n%s_mean_us=%llu\n",
                names[stage],s->count,names[stage],(unsigned long long)s->total_us,
                names[stage],s->max_us,names[stage],(unsigned long long)(s->count?s->total_us/s->count:0));
            if(n<0||(size_t)n>=capacity-used)return -1;used+=(size_t)n;
        }
        n=snprintf(out+used,capacity-used,"draw_profile_valid=%u\ndraw_profile_flags=%u\n",ek_run_draw_flags(r)?0u:1u,ek_run_draw_flags(r));
        if(n<0||(size_t)n>=capacity-used)return -1;used+=(size_t)n;
        static const char *const draw_names[]={"rect","opaque","key","text","lvgl"};
        for(unsigned g=0;g<5;g++){
            uint32_t count=g==4?r->draw_lvgl_count:ek_run_draw_count(r),total=r->draw_total_us[g];
            n=snprintf(out+used,capacity-used,"detail_draw_%s=%u,%u,%u\n",draw_names[g],count,total,count?total/count:0);
            if(n<0||(size_t)n>=capacity-used)return -1;used+=(size_t)n;
        }
        n=snprintf(out+used,capacity-used,
            "max_profile_triangles=%u\nmax_profile_pixel_tests=%u\nmax_profile_clock_calls=%u\nmax_profile_max_clock_gap_us=%u\n"
            "first_fault_clock_calls=%u\nfirst_fault_max_clock_gap_us=%u\n"
            "native_p50_upper_us=%u\nnative_p95_upper_us=%u\nnative_samples=%u\nnative_hist_overflow=%u\n"
            "gap_p50_upper_us=%u\ngap_p95_upper_us=%u\ngap_samples=%u\ngap_hist_overflow=%u\n"
            "end_to_end_p50_upper_us=%u\nend_to_end_p95_upper_us=%u\nend_to_end_max_us=%u\nend_to_end_samples=%u\nend_to_end_hist_overflow=%u\n",
            r->max_precopy.stats.triangles,r->max_precopy.stats.pixel_tests,r->max_precopy.clock_calls,r->max_precopy.max_clock_gap_us,
            r->first_fault.clock_calls,r->first_fault.max_clock_gap_us,
            ek_run_percentile(&r->native_hist,50,512),ek_run_percentile(&r->native_hist,95,512),r->native_hist.count,r->native_hist.bins[63],
            ek_run_percentile(&r->gap_hist,50,4096),ek_run_percentile(&r->gap_hist,95,4096),r->gap_hist.count,r->gap_hist.bins[63],
            ek_run_percentile(&r->end_to_end_hist,50,4096),ek_run_percentile(&r->end_to_end_hist,95,4096),r->end_to_end_hist.max_us,
            r->end_to_end_hist.count,r->end_to_end_hist.bins[63]);
        if(n<0||(size_t)n>=capacity-used)return -1;used+=(size_t)n;
    }
    return (int)used;
}
