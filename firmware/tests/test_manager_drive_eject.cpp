/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include <cassert>
#include <cstdint>
#include <thread>
#include <initializer_list>
struct Lun {
 bool media_present=true;
 bool (*start_stop)(uint8_t,bool,bool)=nullptr;
 void (*scsi_complete)(const uint8_t *)=nullptr;
 int32_t (*read)(uint32_t,uint32_t,void *,uint32_t)=nullptr;
 int32_t (*write)(uint32_t,uint32_t,uint8_t *,uint32_t)=nullptr;
};
static Lun s_luns[2];static unsigned s_active_lun=1,raw_reads,raw_writes;
struct Msc {bool present=true;void mediaPresent(bool v){present=v;s_luns[0].media_present=v;}};
static Msc media;static Msc *s_msc=&media;
static volatile bool s_manager_media_ready=true;
static bool s_descriptor_manager_drive=true;
static bool s_manager_eject_armed,s_manager_eject_pending;
#define FIDO_V1_MANAGER_DRIVE 1
#define ESP_LOGI(...) ((void)0)
#include "manager-drive-under-test.inc"
#include "msc-adapter-under-test.inc"
int main(){
 uint8_t eject[16]={0x1b};eject[4]=2;
 assert(!pf_manager_drive_take_eject());
 for(auto mode:{0u,1u,3u}){
  uint8_t other[16]={0x1b};other[4]=(uint8_t)mode;
  assert(manager_drive_start_stop(0,(mode&1)!=0,(mode&2)!=0));
  manager_drive_scsi_complete(other);assert(!pf_manager_drive_take_eject());
 }
 assert(manager_drive_start_stop(0,false,true));
 assert(!s_manager_media_ready&&!media.present&&!pf_manager_drive_take_eject());
 uint8_t sync[16]={0x35};manager_drive_scsi_complete(sync);assert(!pf_manager_drive_take_eject());
 manager_drive_scsi_complete(nullptr);assert(!pf_manager_drive_take_eject());
 manager_drive_scsi_complete(eject);assert(pf_manager_drive_take_eject());assert(!pf_manager_drive_take_eject());
 manager_drive_scsi_complete(eject);assert(!pf_manager_drive_take_eject());
 s_descriptor_manager_drive=false;assert(manager_drive_start_stop(0,false,true));
 manager_drive_scsi_complete(eject);assert(!pf_manager_drive_take_eject());
 s_descriptor_manager_drive=true;
 // Aborted/uncompleted command never causes a disable event.
 assert(manager_drive_start_stop(0,false,true));assert(!pf_manager_drive_take_eject());
 assert(manager_drive_start_stop(0,true,false));manager_drive_scsi_complete(eject);assert(!pf_manager_drive_take_eject());
 // One USB writer versus board consumer; atomic publication, no missed events.
 std::thread usb([&](){for(unsigned i=0;i<10000;i++){
  while(__atomic_load_n(&s_manager_eject_pending,__ATOMIC_ACQUIRE))std::this_thread::yield();
  manager_drive_start_stop(0,false,true);manager_drive_scsi_complete(eject);
 }});
 unsigned seen=0;while(seen<10000){if(pf_manager_drive_take_eject())++seen;else std::this_thread::yield();}
 usb.join();assert(!pf_manager_drive_take_eject());
 s_luns[0].start_stop=manager_drive_start_stop;s_luns[0].scsi_complete=manager_drive_scsi_complete;
 s_luns[0].read=[](uint32_t,uint32_t,void *,uint32_t)->int32_t{++raw_reads;return 512;};
 s_luns[0].write=[](uint32_t,uint32_t,uint8_t *,uint32_t)->int32_t{++raw_writes;return 512;};
 uint8_t sector[512]={};media.mediaPresent(true);s_manager_media_ready=true;
 assert(tud_msc_read10_cb(0,0,0,sector,512)==512&&raw_reads==1);
 assert(tud_msc_write10_cb(0,0,0,sector,512)==512&&raw_writes==1);
 assert(!tud_msc_start_stop_cb(1,0,false,true)&&s_manager_media_ready);
 assert(tud_msc_start_stop_cb(0,0,false,true)&&!s_manager_media_ready);
 tud_msc_scsi_complete_cb(1,eject);assert(!pf_manager_drive_take_eject());
 tud_msc_scsi_complete_cb(0,eject);assert(pf_manager_drive_take_eject());
 assert(!tud_msc_read10_cb(0,0,0,sector,512)&&raw_reads==1);
 assert(!tud_msc_write10_cb(0,0,0,sector,512)&&raw_writes==1);
 assert(!tud_msc_read10_cb(1,0,0,sector,512)&&raw_reads==1);
 assert(!tud_msc_write10_cb(1,0,0,sector,512)&&raw_writes==1);
}
