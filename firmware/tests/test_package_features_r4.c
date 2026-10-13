/* SPDX-License-Identifier: AGPL-3.0-or-later */
#include "ek_package.h"
#include <assert.h>
#include <stdio.h>
extern int baseline_parse(const uint8_t *,size_t,size_t,EkPackageInfo *);
int main(int argc,char **argv){
 assert(argc==2);FILE *f=fopen(argv[1],"rb");assert(f);uint8_t h[320];assert(fread(h,1,320,f)==320);fseek(f,0,SEEK_END);size_t n=ftell(f);fclose(f);EkPackageInfo info;
 for(unsigned abi=4;abi<=5;abi++)for(unsigned flags=0;flags<8;flags++){
  h[12]=abi;h[14]=flags;assert(ek_package_parse(h,sizeof h,n,&info)==(abi==4?flags==0:flags<=3));
  assert(baseline_parse(h,sizeof h,n,&info)==(abi==4?flags==0:flags<=1));
 }
 puts("PACKAGE FEATURES PASS 16 old-r3/new-r4 ABI4/5 cases; r3 rejects feature2/3, new rejects unknown4..7, ABI4 remains feature0");
}
