/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <assert.h>
#include <stdlib.h>
#include "ek_run_metrics.h"
static uint32_t token(unsigned epoch,unsigned tag,unsigned phase,unsigned partial){
    return epoch|(partial<<23)|(tag<<24)|(phase<<28);
}
static EkSceneProfile profile(unsigned status,unsigned pre,unsigned copy){
    EkSceneProfile p={{status,pre+copy,778,28980},2219,60,pre-2279,7248,copy,902,5730};return p;
}
int main(void){
    assert(sizeof(EkRunMetrics)<=3072);
    EkRunMetrics compact={0};compact.current=0;compact.record[0].phase=EK_RUN_ACTIVE;
    uint32_t groups[4]={1,2,3,0};ek_run_draw(&compact,groups);assert(ek_run_draw_count(&compact.record[0])==1&&compact.record[0].draw_total_us[2]==3);
    compact.record[0].phase=EK_RUN_COMPLETE;ek_run_draw(&compact,groups);assert(ek_run_draw_count(&compact.record[0])==1);
    compact.record[0].draw_total_us[0]=UINT32_MAX-2;ek_run_draw_sum(&compact.record[0],0,3);assert(compact.record[0].draw_total_us[0]==UINT32_MAX&&ek_run_draw_flags(&compact.record[0])==1);
    compact.record[0].phase=EK_RUN_ACTIVE;compact.record[0].draw_count_flags=0xbfffffffU;
    ek_run_draw(&compact,groups);assert(ek_run_draw_count(&compact.record[0])==1073741823U&&ek_run_draw_flags(&compact.record[0])==3);
    EkRunMetrics m={0};m.current=-1;EkRunIdentity identity={0};
    strcpy(identity.app_id,"evil.racer3d");strcpy(identity.version,"0.13.0");
    memset(identity.program_sha256,'a',64);identity.wasm_bytes=64000;identity.asset_bytes=516708;identity.asset_count=31;
    uint64_t zero=5000000000ULL;ek_run_identity(&m,&identity,zero);
    ek_run_token(&m,token(1,1,1,0),100,131072,zero);
    EkSceneProfile p=profile(1,15274,5730);
    EkRunFrame pending=ek_run_native(&m,&p,1,1234,30,8,1178,zero+50000);
    EkRunFrame f=ek_run_present(&m,&pending,zero+51000);
    ek_run_display(&m,&f,1,zero+52000);
    assert(m.record[0].attempts==1&&m.record[0].completed==0&&m.record[0].active_us==0);
    zero+=1000000;ek_run_token(&m,token(1,1,2,0),4789392,131072,zero);
    for(unsigned i=0;i<25;i++){
        uint64_t now=zero+20000+i*40000;
        pending=ek_run_native(&m,&p,i+2,999,30,8,1178,now-1000);pending.started_us=now-17000;
        f=ek_run_present(&m,&pending,now-500);ek_run_display(&m,&f,1,now);
        ek_run_display(&m,&f,1,now); /* duplicate ACK consumes no ticket */
    }
    ek_run_token(&m,token(1,1,3,0),20,131072,zero+1000000);
    assert(m.record[0].active_us==1000000&&m.record[0].completed==25);
    assert(m.record[0].produced==25&&m.record[0].windows==1&&m.record[0].min_millifps==25000);
    assert(ek_run_fps(25,m.record[0].active_us)==25000);
    ek_run_token(&m,token(1,1,2,0),20,131072,zero+101000000);
    ek_run_modal(&m,1,zero+101500000);
    ek_run_modal(&m,0,zero+151500000);
    ek_run_token(&m,token(1,1,4,0),20,131072,zero+152000000);
    assert(m.record[0].active_us==2000000&&m.record[0].windows==2&&m.record[0].min_millifps==0);
    assert(m.record[0].max_frame_gap_us==1020000);
    ek_run_stop(&m,0,zero+200000000);assert(m.record[0].phase==4);
    EkRunRecord finished=m.record[0];
    ek_run_token(&m,token(2,2,2,1),150,131072,zero+201000000);
    p=profile(2,20001,0);pending=ek_run_native(&m,&p,100,100,30,8,1178,zero+201020001);
    f=ek_run_present(&m,&pending,zero+201021000);ek_run_display(&m,&f,1,zero+201022000);
    p=profile(1,10000,5000);pending=ek_run_native(&m,&p,101,150,10,5,500,zero+201030000);
    f=ek_run_present(&m,&pending,zero+201031000);ek_run_display(&m,&f,0,zero+201032000);
    assert(m.record[1].completed==0&&m.record[1].produced==1&&m.record[1].display_failures==1);
    assert(m.record[1].timeouts==1&&m.record[1].over_budget==1);
    assert(ek_run_precopy(&m.record[1].max_precopy)==20001&&m.record[1].first_fault.stats.status==2);
    assert(memcmp(&finished,&m.record[0],sizeof(finished))==0);
    ek_run_stop(&m,1,zero+202000000);assert(m.record[1].phase==6&&m.record[1].vm_errors==1);
    assert(m.record[1].partial==1&&m.record[1].valid==0);
    ek_run_token(&m,token(3,2,2,0),1,131072,zero+203000000);
    assert(m.record[1].epoch==3&&m.record[1].attempts==0&&m.record[1].partial==0);
    ek_run_invalid(&m,zero+203000010);assert(!m.record[1].valid&&m.record[1].telemetry_errors==1);
    ek_run_token(&m,token(3,2,4,0),1,131072,zero+206000000);
    assert(m.record[1].windows==3&&m.record[1].min_millifps==0);
    /* A finished row cannot silently become a resumed full run. */
    ek_run_token(&m,token(3,2,2,0),1,131072,zero+207000000);assert(m.record[1].phase==4);
    char report[12288];int report_bytes=ek_run_report(report,sizeof(report),&m);assert(report_bytes>0);printf("Report rows bytes=%d\n",report_bytes);
    assert(strstr(report,"app_id=evil.racer3d")&&strstr(report,"native_precopy_max_us=15274"));
    assert(ek_run_report(report,10,&m)==-1);
    EkRunMetrics worst={0};
    memset(worst.record,0xff,sizeof worst.record);
    for(int i=0;i<2;i++){
        memset(worst.record[i].identity.app_id,'a',31);worst.record[i].identity.app_id[31]=0;
        memset(worst.record[i].identity.version,'9',19);worst.record[i].identity.version[19]=0;
        memset(worst.record[i].identity.program_sha256,'a',64);worst.record[i].identity.program_sha256[64]=0;
    }
    int worst_bytes=ek_run_report(report,sizeof report,&worst);assert(worst_bytes>0);
    printf("Worst run rows bytes=%d\n",worst_bytes);
    EkRunHistogram hist={0};
    for(unsigned i=1;i<=100;i++)ek_run_hist(&hist,i*1000,4096);
    unsigned p50=ek_run_percentile(&hist,50,4096),p95=ek_run_percentile(&hist,95,4096);
    assert(p50>=50000&&p50-50000<4096&&p95>=95000&&p95-95000<4096);
    for(unsigned i=0;i<100;i++)ek_run_hist(&hist,700000,4096);
    assert(hist.bins[63]==100&&ek_run_percentile(&hist,95,4096)==700000);
    printf("RUN METRICS PASS:25newFPS independent1s oracle,clock>32bit,pause/modal retention,two tags,partial,errors,max,late/duplicate ACK,histograms,report guard; tracker=%zuB\n",sizeof(m));
}
