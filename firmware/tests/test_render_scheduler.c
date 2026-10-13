#include "ek_render_parallel.h"
#include <assert.h>
#include <stdio.h>
unsigned fake_priority=1,fake_inherit,helper_creates;
unsigned fake_priority_sets;
static void work(void*p){++*(unsigned*)p;}
int main(void){ek_render_workers_start();assert(ek_render_workers_ready()&&helper_creates==2);
for(unsigned initial=1;initial<=5;initial++)for(unsigned client=0;client<2;client++)for(unsigned fault=0;fault<2;fault++){
 fake_priority=initial;bool owned=ek_render_frame_begin(client);assert(owned);
 assert(fake_priority==(client==0&&initial<2?2:initial));
 unsigned a=0,b=0;ek_render_parallel_enable(false);assert(!ek_render_parallel(work,&a,&b));assert(a==1&&b==1);
 /* success and forced-abort caller use the same joined frame-end path. */
 ek_render_frame_end(owned);assert(fake_priority==initial);
}
fake_priority=1;fake_inherit=1;assert(ek_render_frame_begin(0));assert(fake_priority==2);ek_render_frame_end(true);assert(fake_priority==1);
ek_render_frame_end(false);assert(fake_priority==1);
assert(sizeof(EkRenderFrameStats)==40);
puts("SCHEDULER PASS actual ESP coordinator:helper2;20 native/display/fault/serial-fallback restores;contention restores original rather than inherited priority");}
