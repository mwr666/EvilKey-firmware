/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "SD.h"
#include "../../EvilKeyV1/src/apps/ek_storage.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
SDClass SD;
static bool allowed=true;
uint32_t millis(void){return 0x1234;}
extern "C" bool pf_apps_storage_role_allowed(void){return allowed;}
static void lose_role(){allowed=false;}
static void no_partial(){for(const auto &item:SD.logs)assert(item.first.find(".tmp")==std::string::npos);}
int main(){
 char filename[32];std::vector<uint8_t> data(1800);for(size_t i=0;i<data.size();i++)data[i]=(uint8_t)i;
 assert(!ek_storage_diagnostics_write(data.data(),data.size(),filename,sizeof(filename)));
 assert(ek_storage_begin());
 SD.save={9,8,7};SD.save_exists=true;SD.entries.push_back({"keep.ekapp",{1,2,3}});
 auto apps=SD.entries[0].bytes;auto save=SD.save;
 assert(ek_storage_diagnostics_write(data.data(),data.size(),filename,sizeof(filename)));
 std::string first="/evilkey/diagnostics/"+std::string(filename);
 assert(SD.logs[first]==data&&SD.directories.count("/evilkey/diagnostics"));no_partial();
 assert(ek_storage_diagnostics_write(data.data(),data.size(),filename,sizeof(filename)));
 std::string second="/evilkey/diagnostics/"+std::string(filename);assert(first!=second&&SD.logs[first]==data);
 auto committed=SD.logs;
 for(unsigned fault=0;fault<7;fault++){
  SD.fail_log_open=fault==0;SD.log_io.short_write=fault==1;
  SD.fail_log_read_open=fault==2;SD.log_io.corrupt_read=fault==3;
  SD.fail_rename=fault==4;SD.log_io.fail_read=fault==5;
  SD.log_io.on_write=fault==6?lose_role:nullptr;
  assert(!ek_storage_diagnostics_write(data.data(),data.size(),filename,sizeof(filename)));
  assert(!filename[0]);allowed=true;no_partial();assert(SD.logs==committed);
 }
 SD.fail_log_open=SD.fail_log_read_open=SD.fail_rename=false;SD.log_io={};
 allowed=false;assert(!ek_storage_diagnostics_write(data.data(),data.size(),filename,sizeof(filename)));allowed=true;
 SD.directories.clear();SD.fail_mkdir=true;
 assert(!ek_storage_diagnostics_write(data.data(),data.size(),filename,sizeof(filename)));
 SD.fail_mkdir=false;
 assert(!ek_storage_diagnostics_write(nullptr,1,filename,sizeof(filename)));
 assert(!ek_storage_diagnostics_write(data.data(),8193,filename,sizeof(filename)));
 assert(!ek_storage_diagnostics_write(data.data(),data.size(),filename,1));
 assert(SD.save==save&&SD.entries[0].bytes==apps&&SD.logs==committed);
 assert(ek_storage_diagnostics_write(data.data(),data.size(),filename,sizeof(filename)));no_partial();
 /* The next sequence is10: retain both prior final reports and unrelated
  * interrupted temporary reports while exhausting the bounded name search. */
 for(unsigned i=10;i<74;i++){
  char collision[80];snprintf(collision,sizeof(collision),"/evilkey/diagnostics/diag-00001234-%04u.txt%s",i,i&1?".tmp":"");
  SD.logs[collision]={0x71};
 }
 auto crowded=SD.logs;
 assert(!ek_storage_diagnostics_write(data.data(),data.size(),filename,sizeof(filename)));
 assert(!strcmp(ek_storage_error(),"SD names exhausted")&&SD.logs==crowded);
 puts("PASS diagnostics SD: distinct verified files, mkdir/open/short write/read/mismatch/rename/role errors, owned temp cleanup, existing reports/apps/save preserved");
}
