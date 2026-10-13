/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "SD.h"
#include "mbedtls/sha256.h"
#include "../../EvilKeyV1/src/apps/ek_storage.h"
#include "../../EvilKeyV1/src/apps/ek_mesh.h"
#include <assert.h>
#include <stdio.h>
SDClass SD;bool models_alloc_fail=false;static bool allowed=true;
uint32_t millis(void){return 1000;}
extern "C" bool pf_apps_storage_role_allowed(void){return allowed;}
int main(int argc,char **argv){
 assert(argc==2);FILE *file=fopen(argv[1],"rb");assert(file);uint8_t data[65536];size_t n=fread(data,1,sizeof data,file);fclose(file);
 uint8_t ref[36]={0};ref[0]=n;ref[1]=n>>8;mbedtls_sha256(data,n,ref+4,0);
 EkAssets assets={};auto reset=[&](){ek_storage_models_free(&assets);assets={};assets.count=1;assets.items[0]={23,4,0,0,ref,36};};
 assert(ek_storage_begin());reset();assert(!ek_storage_models_load("../escape",&assets,0));
 assert(!ek_storage_models_load("example",&assets,100));assert(!assets.items[0].owned);
 SD.entries.push_back({"example.models/23.ekmesh",std::vector<uint8_t>(data,data+n)});
 reset();assert(ek_storage_models_load("example",&assets,100));assert(assets.items[0].flags==2&&assets.items[0].owned&&assets.items[0].length==n&&!memcmp(data,assets.items[0].rgb565,n));
 reset();ref[4]^=1;assert(!ek_storage_models_load("example",&assets,100));ref[4]^=1;
 reset();SD.entries[0].bytes.pop_back();assert(!ek_storage_models_load("example",&assets,100));SD.entries[0].bytes.push_back(data[n-1]);
 reset();assert(!ek_storage_models_load("example",&assets,1048576));
 reset();allowed=false;assert(!ek_storage_models_load("example",&assets,100));allowed=true;
 reset();SD.entry_io.fail_read=true;assert(!ek_storage_models_load("example",&assets,100));SD.entry_io.fail_read=false;
 reset();models_alloc_fail=true;assert(!ek_storage_models_load("example",&assets,100));models_alloc_fail=false;
 reset();assets.count=2;assets.items[1]={24,4,0,0,ref,36};assert(!ek_storage_models_load("example",&assets,100));assert(!assets.items[0].owned&&assets.items[0].rgb565==nullptr);
 reset();SD.entries[0].bytes[0]^=1;mbedtls_sha256(SD.entries[0].bytes.data(),n,ref+4,0);assert(!ek_storage_models_load("example",&assets,100));
 ek_storage_models_free(&assets);ek_storage_end();puts("MODELS SD PASS namespaced read-only path, exact content/ownership, missing/size/hash/geometry/quota/read/alloc/USB errors, cleanup after second-model failure (digest mock)");
}
