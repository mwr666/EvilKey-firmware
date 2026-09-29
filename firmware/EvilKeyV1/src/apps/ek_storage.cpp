/* SPDX-License-Identifier: AGPL-3.0-or-later
 * Read-only EvilKey Apps store. The user copies .ekapp files to microSD;
 * the ordinary FIDO role mounts the card only while the Apps screen is open.
 */
#include "ek_storage.h"
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
static bool path(char *out,size_t cap,const char *id) {
    if (!ek_package_valid_id(id)) return false;
    int n=snprintf(out,cap,"%s/%s.ekapp",kApps,id);
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
    uint32_t left=info.wasm_size;
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
extern "C" int ek_storage_load(const char *id,uint8_t **bytecode,size_t *size) {
    if (!s_mounted || !ek_package_valid_id(id) || !bytecode || !size)
        return fail("Invalid app request");
    *bytecode=nullptr;*size=0;
    char filename[80];
    if (!path(filename,sizeof(filename),id)) return fail("Invalid app path");
    File file=SD.open(filename,FILE_READ);
    if (!file) return fail("App file missing");
    EkPackageInfo info;
    if (!package_info(file,&info) || strcmp(info.id,id)!=0) {
        file.close();return fail("App header invalid");
    }
    uint8_t *buffer=(uint8_t *)heap_caps_malloc(info.wasm_size,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
    if (!buffer) {file.close();return fail("No memory for app");}
    bool ok=hash_payload(file,info,buffer);
    file.close();
    if (!ok) {free(buffer);return fail("App SHA-256 mismatch");}
    *bytecode=buffer;*size=info.wasm_size;s_error[0]=0;return 1;
}
