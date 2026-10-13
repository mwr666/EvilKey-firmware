#include "ek_run_metrics.h"
#include <assert.h>
#include <string.h>
int main(void){
 EkRunMetrics m={0};m.current=-1;EkRunIdentity id={0};strcpy(id.app_id,"probe");
 ek_run_active_stage(&m,EK_STAGE_GUEST,99);assert(!m.record[0].stages[0].count);
 ek_run_identity(&m,&id,0);ek_run_token(&m,0x21000001,100,65536,0);
 EkRunRecord *r=ek_run_current(&m);ek_run_active_stage(&m,EK_STAGE_GUEST,101);
 ek_run_active_stage(&m,EK_STAGE_GUEST,301);assert(r->stages[0].count==2&&r->stages[0].total_us==402&&r->stages[0].max_us==301);
 ek_run_active_stage(&m,EK_STAGE_OUTPUT,400);ek_run_active_stage(&m,EK_STAGE_NATIVE_WALL,500);
 EkSceneProfile p={0};p.stats.status=1;p.stats.elapsed_us=15000;p.reconstruct_us=5000;
 EkRunFrame f=ek_run_native(&m,&p,9,0,1,1,12,100);f=ek_run_present(&m,&f,200);
 ek_run_display_profile(&m,&f,1,300,12345,1200,4);
 assert(r->completed==1&&r->mixed_frames==1&&r->full_frames==0);
 assert(r->stages[3].count==1&&r->stages[3].total_us==12345&&r->stages[4].count==1);
 ek_run_display_profile(&m,&f,1,400,12345,1200,4);assert(r->stages[3].count==1);
 f=ek_run_native(&m,&p,10,0,1,1,12,400);f=ek_run_present(&m,&f,500);
 ek_run_display_profile(&m,&f,0,600,5,6,4);assert(r->display_failures==1&&r->stages[3].count==1);
 f=(EkRunFrame){r->sequence+1,11,1,0};ek_run_display_profile(&m,&f,1,700,5,6,4);assert(r->completed==1);
 ek_run_modal(&m,1,800);ek_run_active_stage(&m,EK_STAGE_GUEST,999);assert(r->stages[0].count==2);
 ek_run_modal(&m,0,900);ek_run_token(&m,0x31000001,100,65536,1000);
 ek_run_active_stage(&m,EK_STAGE_GUEST,999);assert(r->stages[0].count==2);
 ek_run_token(&m,0x21000001,100,65536,1100);
 f=ek_run_native(&m,&p,12,0,1,1,12,1200);f=ek_run_present(&m,&f,1300);
 ek_run_display_profile(&m,&f,1,1400,2000,1000,3);assert(r->completed==2&&r->full_frames==1);
 ek_run_token(&m,0x41000001,100,65536,1500);ek_run_active_stage(&m,EK_STAGE_GUEST,999);assert(r->stages[0].count==2);
 char text[12288];int n=ek_run_report(text,sizeof text,&m);assert(n>0&&n<12288);
 assert(strstr(text,"guest_count=2\nguest_total_us=402\nguest_max_us=301\nguest_mean_us=201"));
 assert(strstr(text,"display_wall_count=2\ndisplay_wall_total_us=14345\ndisplay_wall_max_us=12345\ndisplay_wall_mean_us=7172"));
 char guard[20];memset(guard,0x55,sizeof guard);assert(ek_run_report(guard+1,4,&m)==-1&&guard[0]==0x55&&guard[5]==0x55);
 ek_run_token(&m,0x22000001,100,65536,1600);ek_run_active_stage(&m,EK_STAGE_GUEST,20);assert(r->stages[0].total_us==402);
 ek_run_token(&m,0x21000002,100,65536,1700);r=ek_run_current(&m);assert(r->stages[0].count==0&&r->completed==0);
 r->stages[0]=(EkRunStage){UINT64_MAX-1,UINT32_MAX,3};ek_run_stage(r,0,10);assert(r->stages[0].total_us==UINT64_MAX&&r->stages[0].count==4);
 r->stages[0].count=UINT32_MAX;ek_run_stage(r,0,10);assert(r->stages[0].count==UINT32_MAX);
 for(unsigned method=5;method<=6;method++){f=ek_run_native(&m,&p,20+method,0,1,1,12,1800+method*100);f=ek_run_present(&m,&f,1850+method*100);ek_run_display_profile(&m,&f,1,1900+method*100,20,10,method);}
 assert(r->completed==2&&r->mixed_frames==1&&r->full_frames==1);
 puts("RUN STAGES PASS exchange methods5/6; active/pause/modal/complete/empty/reset/retention; duplicate/failed/stale ACK; mixed/full; exact means/saturation/serializer guards");
}
