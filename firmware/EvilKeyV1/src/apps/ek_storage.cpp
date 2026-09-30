/* SPDX-License-Identifier: AGPL-3.0-or-later
 * EvilKey Apps store. The user copies .ekapp files to microSD;
 * the ordinary FIDO role mounts the card only while the Apps screen is open.
 */
#include "ek_storage.h"
#include "ek_assets.h"
#include "../engine/board/ws_pins.h"
#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include <esp_heap_caps.h>
#include <mbedtls/sha256.h>
#include <string.h>
#include <stdio.h>

extern "C" bool pf_apps_storage_role_allowed(void);
static SPIClass s_spi(HSPI);
static bool s_mounted;
static char s_error[80];
static constexpr char kApps[]="/evilkey/apps";

static int fail(const char *why) {
    snprintf(s_error,sizeof(s_error),"%s",why);
    return 0;
}
static bool path(char *out,size_t cap,const char *id,const char *extension) {
    if (!ek_package_valid_id(id)) return false;
    int n=snprintf(out,cap,"%s/%s.%s",kApps,id,extension);
    return n>0 && static_cast<size_t>(n)<cap;
}
static bool read_exact(File &f,uint8_t *data,size_t count) {
    return f.read(data,count)==count;
}
static bool package_info(File &f,EkPackageInfo *info) {
    uint8_t header[EK_PACKAGE_HEADER_SIZE];
    if (f.isDirectory() || f.size()>EK_PACKAGE_MAX_BYTES ||
        !read_exact(f,header,sizeof(header))) return false;
    return ek_package_parse(header,sizeof(header),f.size(),info)!=0;
}
static bool hash_payload(File &f,const EkPackageInfo &info,uint8_t *output) {
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    bool ok=mbedtls_sha256_starts(&sha,0)==0;
    uint8_t block[512];
    uint32_t left=info.wasm_size+info.asset_size;
    size_t offset=0;
    while (ok && left) {
        size_t take=left>sizeof(block)?sizeof(block):left;
        if (!read_exact(f,block,take) || mbedtls_sha256_update(&sha,block,take)!=0) {
            ok=false;break;
        }
        if (output) {memcpy(output+offset,block,take);offset+=take;}
        left-=take;
    }
    uint8_t digest[32];
    if (ok) ok=mbedtls_sha256_finish(&sha,digest)==0 &&
                memcmp(digest,info.sha256,sizeof(digest))==0;
    mbedtls_sha256_free(&sha);
    return ok;
}

extern "C" int ek_storage_begin(void) {
    if (s_mounted) return 1;
    if (!pf_apps_storage_role_allowed()) return fail("USB role owns microSD");
    if (!s_spi.begin(WS_SD_SCLK,WS_SD_MISO,WS_SD_MOSI,WS_SD_CS))
        return fail("microSD SPI unavailable");
    if (!SD.begin(WS_SD_CS,s_spi,16000000U,"/evilkey-apps",4,false)) {
        s_spi.end();return fail("microSD not mounted");
    }
    s_mounted=true;
    /* No mkdir, remove, rename, format or write operation. A missing directory
     * simply means that the card has no EvilKey Apps yet. */
    s_error[0]=0;
    return 1;
}
extern "C" void ek_storage_end(void) {
    if (!s_mounted) return;
    SD.end();s_spi.end();s_mounted=false;
}
extern "C" const char *ek_storage_error(void) {return s_error;}
extern "C" int ek_storage_entry(unsigned index,EkPackageInfo *info) {
    if (!s_mounted || !info) return 0;
    File directory=SD.open(kApps,FILE_READ);
    if (!directory || !directory.isDirectory()) return 0;
    unsigned seen=0;
    bool found=false;
    File file;
    while ((file=directory.openNextFile())) {
        if (!file.isDirectory()) {
            EkPackageInfo parsed;
            const char *name=strrchr(file.name(),'/');
            name=name?name+1:file.name();
            char expected[48];
            if (package_info(file,&parsed) &&
                snprintf(expected,sizeof(expected),"%s.ekapp",parsed.id)>0 &&
                strcmp(name,expected)==0 && seen++==index) {
                *info=parsed;found=true;file.close();break;
            }
        }
        file.close();
    }
    directory.close();
    return found?1:0;
}
extern "C" int ek_storage_load(const char *id,uint8_t **payload,
                                 size_t *wasm_size,size_t *asset_size) {
    if (!s_mounted || !ek_package_valid_id(id) || !payload || !wasm_size || !asset_size)
        return fail("Invalid app request");
    *payload=nullptr;*wasm_size=0;*asset_size=0;
    char filename[80];
    if (!path(filename,sizeof(filename),id,"ekapp")) return fail("Invalid app path");
    File file=SD.open(filename,FILE_READ);
    if (!file) return fail("App file missing");
    EkPackageInfo info;
    if (!package_info(file,&info) || strcmp(info.id,id)!=0) {
        file.close();return fail("App header invalid");
    }
    uint8_t *buffer=(uint8_t *)heap_caps_malloc(info.wasm_size+info.asset_size,
                                                  MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if (!buffer) {file.close();return fail("No memory for app");}
    bool ok=hash_payload(file,info,buffer);
    file.close();
    if (!ok) {free(buffer);return fail("App SHA-256 mismatch");}
    EkAssets assets;
    if (!ek_assets_parse(buffer+info.wasm_size,info.asset_size,&assets)) {
        free(buffer);return fail("App assets invalid");
    }
    *payload=buffer;*wasm_size=info.wasm_size;*asset_size=info.asset_size;
    s_error[0]=0;return 1;
}

/* Two sector-aligned records in one <id>.save. An update to one record must
 * not write the same physical 512-byte sector as the previous valid record.
 * The FAT filesystem itself must still be treated as removable media. */
static constexpr size_t kSaveMax=EVILKEY_APP_MAX_SAVE_BYTES;
static constexpr size_t kSaveSector=512;
static constexpr size_t kSaveSlot=
    ((16+kSaveMax+kSaveSector-1)/kSaveSector)*kSaveSector;
static constexpr size_t kSaveFile=2*kSaveSlot;
static_assert(kSaveSlot%kSaveSector==0,"Save records must not share a sector");
static uint8_t s_save_slot[kSaveSlot]; /* accessed only by the Apps worker */
static uint32_t s_last_save_ms;
static bool s_has_saved;

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static void put32(uint8_t *p,uint32_t n) {
    for (unsigned i=0;i<4;++i) p[i]=(uint8_t)(n>>(8*i));
}
static uint32_t crc32(const uint8_t *data,size_t size) {
    uint32_t crc=0xffffffffU;
    for (size_t i=0;i<size;++i) {
        crc^=data[i];
        for (unsigned bit=0;bit<8;++bit)
            crc=(crc>>1)^((crc&1U)?0xedb88320U:0U);
    }
    return ~crc;
}
static bool read_slot(File &f,unsigned slot,uint32_t *sequence,size_t *size) {
    if (!f.seek(slot*kSaveSlot) || !read_exact(f,s_save_slot,kSaveSlot) ||
        memcmp(s_save_slot,"EKS4",4)!=0) return false;
    size_t length=le32(s_save_slot+8);
    if (length>kSaveMax || le32(s_save_slot+12)!=crc32(s_save_slot+16,length))
        return false;
    *sequence=le32(s_save_slot+4);*size=length;
    return true;
}
static int newest_slot(File &f,uint32_t *sequence,size_t *size) {
    uint32_t a=0,b=0;size_t sa=0,sb=0;
    bool va=read_slot(f,0,&a,&sa),vb=read_slot(f,1,&b,&sb);
    if (!va && !vb) return -1;
    if (vb && (!va || (int32_t)(b-a)>0)) {
        *sequence=b;*size=sb;return 1;
    }
    *sequence=a;*size=sa;return 0;
}
extern "C" int ek_storage_save_load(const char *id,uint8_t *out,size_t capacity,
                                     size_t *out_size) {
    if (out_size) *out_size=0;
    if (!s_mounted || !out || !out_size || capacity<kSaveMax) return 0;
    char filename[80];
    if (!path(filename,sizeof(filename),id,"save")) return 0;
    File f=SD.open(filename,FILE_READ);
    if (!f || f.isDirectory() || f.size()!=kSaveFile) {f.close();return 0;}
    uint32_t sequence;size_t size;
    int slot=newest_slot(f,&sequence,&size);
    bool ok=slot>=0 && read_slot(f,(unsigned)slot,&sequence,&size);
    if (ok) memcpy(out,s_save_slot+16,size);
    f.close();
    if (ok) *out_size=size;
    return ok?1:0;
}
extern "C" int ek_storage_save_write(const char *id,const uint8_t *data,size_t size) {
    if (!s_mounted || !pf_apps_storage_role_allowed() ||
        (!data && size) || size>kSaveMax) return fail("Save denied");
    uint32_t now=millis();
    if (s_has_saved && now-s_last_save_ms<1000U)
        return fail("Save rate limited");
    char filename[80];
    if (!path(filename,sizeof(filename),id,"save")) return fail("Invalid save path");
    File f=SD.open(filename,FILE_READ);
    if (!f) {
        f=SD.open(filename,FILE_WRITE);
        if (!f) return fail("Cannot create save");
        memset(s_save_slot,0,sizeof(s_save_slot));
        bool created=f.write(s_save_slot,kSaveSlot)==kSaveSlot &&
                     f.write(s_save_slot,kSaveSlot)==kSaveSlot;
        f.flush();f.close();
        if (!created) return fail("Save allocation failed");
    } else {
        bool valid_size=!f.isDirectory() && f.size()==kSaveFile;
        f.close();
        if (!valid_size) return fail("Save file invalid");
    }
    f=SD.open(filename,"r+");
    if (!f || f.size()!=kSaveFile) {f.close();return fail("Save open failed");}
    uint32_t sequence=0;size_t old_size=0;
    int previous=newest_slot(f,&sequence,&old_size);
    unsigned target=previous==0?1U:0U;
    memset(s_save_slot,0,sizeof(s_save_slot));
    memcpy(s_save_slot,"EKS4",4);
    put32(s_save_slot+4,sequence+1);
    put32(s_save_slot+8,(uint32_t)size);
    put32(s_save_slot+12,crc32(data,size));
    if (size) memcpy(s_save_slot+16,data,size);
    bool ok=f.seek(target*kSaveSlot) && f.write(s_save_slot,kSaveSlot)==kSaveSlot;
    f.flush();f.close();
    if (!ok) return fail("Save write failed");
    f=SD.open(filename,FILE_READ);
    uint32_t check_sequence=0;size_t check_size=0;
    ok=f && read_slot(f,target,&check_sequence,&check_size) &&
       check_sequence==sequence+1 && check_size==size &&
       (!size || memcmp(s_save_slot+16,data,size)==0);
    f.close();
    if (!ok) return fail("Save readback failed");
    s_last_save_ms=now;s_has_saved=true;s_error[0]=0;return 1;
}
