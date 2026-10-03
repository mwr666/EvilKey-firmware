/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "SD.h"
#include "../../EvilKeyV1/src/apps/ek_storage.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
SDClass SD;
uint32_t millis(void){return 1000;}
extern "C" bool pf_apps_storage_role_allowed(void){return true;}
static std::vector<uint8_t> package(const char *id){
 std::vector<uint8_t> b(EK_PACKAGE_PAYLOAD_OFFSET+8,0);
 memcpy(b.data(),"EKEYAPP1",8);b[8]=64;b[9]=1;b[10]=5;b[12]=4;b[288]=1;
 strcpy((char *)b.data()+22,id);b[54]=8;
 strcpy((char *)b.data()+90,"Owner");strcpy((char *)b.data()+154,"MIT");
 strcpy((char *)b.data()+192,"Long Launcher Display Name");
 memcpy(b.data()+EK_PACKAGE_PAYLOAD_OFFSET,"\0asm\1\0\0\0",8);
 return b;
}
int main(void){
 assert(ek_storage_begin());assert(ek_storage_scan_begin()==0);
 for(unsigned count:{0u,1u,5u,9u,10u,70u}) {
  SD.entries.clear();SD.catalog_exists=true;SD.directory_opens=0;
  for(unsigned i=0;i<count;++i) {
   char id[32];snprintf(id,sizeof(id),"game.%02u",i);
   SD.entries.push_back({std::string(id)+".ekapp",package(id)});
  }
  SD.entries.push_back({"game.00.save",std::vector<uint8_t>(9216,1)});
  SD.entries.push_back({"game.00.save.bak",std::vector<uint8_t>(9216,2)});
  SD.entries.push_back({"game.00.ekapp.tmp",package("game.00")});
  SD.entries.push_back({"folder.ekapp",package("game.00"),true});
  SD.entries.push_back({"bad.ekapp",std::vector<uint8_t>(320,0)});
  SD.entries.push_back({"wrong.name.ekapp",package("game.00")});
  assert(ek_storage_scan_begin()==1);
  unsigned found=0,reads=0;EkPackageInfo info;bool read=false;int step;
  while((step=ek_storage_scan_step(&info,&read))>0) {
   reads+=read?1:0;if(step==1)++found;
  }
  assert(step==0 && found==count && reads==count+2 && SD.directory_opens==1);
  for(unsigned i=count;i<count+4;++i)assert(SD.entries[i].read_bytes==0);
  assert(ek_storage_scan_begin()==1);ek_storage_scan_end();assert(ek_storage_scan_step(&info,&read)==0);
  printf("catalog %u apps: one directory open, %u package headers, zero save/backup/temp reads\n",count,reads);
 }
 auto b=package("valid");EkPackageInfo info;
 assert(ek_package_parse(b.data(),320,b.size(),&info));
 b[192]=0;assert(!ek_package_parse(b.data(),320,b.size(),&info));
 b=package("valid");b[192]=0xc0;b[193]=0x80;b[194]=0;assert(!ek_package_parse(b.data(),320,b.size(),&info));
 b=package("valid");b[290]=1;assert(!ek_package_parse(b.data(),320,b.size(),&info));
 b=package("valid");b[10]=4;assert(!ek_package_parse(b.data(),320,b.size(),&info));
 b=package("valid");b[288]=0;assert(!ek_package_parse(b.data(),320,b.size(),&info));
 b=package("valid");b[288]=2;assert(!ek_package_parse(b.data(),320,b.size(),&info));
 b=package("valid");assert(!ek_package_parse(b.data(),320,b.size()-1,&info));
 SD.entries.clear();SD.entries.push_back({"valid.ekapp",package("valid")});
 auto &icon_package=SD.entries[0].bytes;
 assert(ek_package_parse(icon_package.data(),320,icon_package.size(),&info));
 uint8_t icon[8192];assert(ek_storage_icon(&info,icon,sizeof(icon)));
 icon_package[320]=1;assert(!ek_storage_icon(&info,icon,sizeof(icon)));
 icon_package[320]=0;icon_package[256]=1;assert(!ek_storage_icon(&info,icon,sizeof(icon)));
 icon_package.resize(320);assert(!ek_storage_icon(&info,icon,sizeof(icon)));
 assert(!ek_storage_icon(&info,icon,8191));
 puts("PASS catalog, cancellation, mandatory UTF-8 name, reserved bytes, revision and exact bounds");
 puts("PASS icon read, pixel/hash mismatch, changed cached digest, short file and short output (digest mock)");
}
