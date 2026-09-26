/* Host test of the authenticated PFM1/PFM2 inner handler. */
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "ws_settings.h"
#include "ws_manager_drive_state.h"
#include "../../EvilKeyV1/src/pf_firmware_version.h"
#define CTAP2_ERR_PIN_AUTH_INVALID 0x33
#define CTAP1_ERR_INVALID_PARAMETER 2
#define CTAP2_ERR_MISSING_PARAMETER 0x14
#define CTAP2_ERR_NOT_ALLOWED 0x30
#define CTAP2_ERR_PROCESSING 0x21
#define CTAP_PERMISSION_ACFG 0x20
#define FIDO_V1_LOCAL_UV 1
#define FIDO_V1_TOUCH_CONFIRM 1
#define FIDO_V1_BOOT_CONFIRM_FALLBACK 0
#define FIDO_V1_DISPLAY 1
#define FIDO_V1_MANAGER_DRIVE 1
#define CBOR_ERROR(e) do{error=(e);goto err;}while(0)
#define CBOR_CHECK(x) do{if((x)!=0){error=0x21;goto err;}}while(0)
typedef struct{unsigned n;} CborEncoder;
typedef struct{uint8_t permissions;bool in_use,has_rp_id,user_verified;} token_t;
static token_t paut;uint32_t initial_usage_time_limit;static uint32_t now;
static unsigned invalidations,writes,reads,drive_writes,drive_applies;static ws_settings_result_t write_result;static ws_settings_t settings;
static bool drive_ro,drive_ok=true,drive_enabled=true;
uint32_t board_millis(void){return now;}
bool getUserVerifiedFlagValue(void){return paut.in_use&&paut.user_verified;}
void fido_object_authorization_session_invalidate(void){invalidations++;}
ws_settings_result_t ws_settings_apply(const uint8_t*d,size_t n){writes++;assert(d&&n==32);return write_result;}
void ws_settings_get(ws_settings_t*s,bool*ok){reads++;*s=settings;*ok=true;}
bool ws_manager_drive_decode(const uint8_t*d,size_t n,bool*ro){if(!d||n!=8||memcmp(d,"PFM2",4)||d[4]!=1||d[5]>1||d[6]||d[7])return false;*ro=d[5]!=0;return true;}
void ws_manager_drive_encode(uint8_t out[8]){memset(out,0,8);memcpy(out,"PFM2",4);out[4]=1;out[5]=drive_ro?1:0;}
bool ws_manager_drive_set_read_only(bool ro){drive_writes++;drive_ro=ro;return drive_ok;}
bool ws_manager_drive_storage_ok(void){return drive_ok;}
bool ws_manager_drive_enabled(void){return drive_enabled;}
void pf_manager_drive_apply_read_only(bool ro){drive_applies++;assert(ro==drive_ro);}
static int cbor_encoder_create_map(CborEncoder*a,CborEncoder*b,unsigned n){assert(n==5||n==6);*b=*a;return 0;}
static int cbor_encode_uint(CborEncoder*a,uint64_t n){a->n++;(void)n;return 0;}
static int cbor_encode_byte_string(CborEncoder*a,const uint8_t*d,size_t n){assert(d&&(n==32||n==8));a->n++;return 0;}
static int cbor_encode_text_stringz(CborEncoder*a,const char*s){assert(!strcmp(s,"0.2.10-dev"));a->n++;return 0;}
static int cbor_encode_boolean(CborEncoder*a,bool b){(void)b;a->n++;return 0;}
static int cbor_encoder_close_container(CborEncoder*a,CborEncoder*b){*a=*b;return 0;}
static size_t cbor_encoder_get_buffer_size(CborEncoder*a,uint8_t*b){(void)b;return a->n;}
static int call(uint64_t id,bool bytes,bool extra,bool hmac_ok){
 int error=0;uint64_t subcommand=255,vendorCommandId=id;bool vendorCommandIdPresent=true,vendorParamIntPresent=extra;
 uint8_t wire[32];ws_settings_encode(&settings,wire);if(id==WS_MANAGER_DRIVE_WRITE_ID){memset(wire,0,32);memcpy(wire,"PFM2",4);wire[4]=1;wire[5]=1;}
 size_t wire_len=(id==WS_MANAGER_DRIVE_WRITE_ID)?8:32;
 struct{bool present;uint8_t*data;size_t len;}vendorParamByteString={bytes,wire,wire_len};struct{bool present;}vendorParamTextString={false};
 CborEncoder encoder={0};size_t resp_size=0;struct{struct{uint8_t data[128];}init;}response,*ctap_resp=&response;
 if(!hmac_ok||!(paut.permissions&CTAP_PERMISSION_ACFG))return CTAP2_ERR_PIN_AUTH_INVALID;
 #include "ws_manager_config.h"
 err:(void)resp_size;return error;
}
static void fresh(void){paut=(token_t){32,true,false,true};now=1000;initial_usage_time_limit=1000;invalidations=writes=reads=drive_writes=drive_applies=0;write_result=WS_SETTINGS_OK;drive_ro=false;drive_ok=true;drive_enabled=true;ws_settings_defaults(&settings);}
int main(void){
 fresh();assert(call(WS_MANAGER_READ_ID,false,false,true)==0);assert(reads==1&&writes==0&&paut.permissions==0&&invalidations==1);
 fresh();assert(call(WS_MANAGER_WRITE_ID,true,false,true)==0&&writes==1);
 fresh();assert(call(WS_MANAGER_DRIVE_READ_ID,false,false,true)==0&&drive_writes==0&&drive_applies==0);
 fresh();assert(call(WS_MANAGER_DRIVE_WRITE_ID,true,false,true)==0&&drive_writes==1&&drive_ro&&drive_applies==1);
 puts("PASS PFM1/PFM2: authenticated display and Manager Drive read/write operations");
 fresh();assert(call(WS_MANAGER_DRIVE_WRITE_ID,false,false,true)==0x14&&drive_writes==0);
 fresh();assert(call(WS_MANAGER_DRIVE_READ_ID,true,false,true)==2&&drive_writes==0);
 fresh();drive_ok=false;assert(call(WS_MANAGER_DRIVE_WRITE_ID,true,false,true)==0x21&&drive_applies==0);
 fresh();paut.in_use=false;assert(call(WS_MANAGER_DRIVE_WRITE_ID,true,false,true)==0x33&&drive_writes==0);
 fresh();paut.has_rp_id=true;assert(call(WS_MANAGER_DRIVE_WRITE_ID,true,false,true)==0x33&&drive_writes==0);
 fresh();paut.user_verified=false;assert(call(WS_MANAGER_DRIVE_WRITE_ID,true,false,true)==0x33&&drive_writes==0);
 fresh();now+=30001;assert(call(WS_MANAGER_DRIVE_WRITE_ID,true,false,true)==0x33&&drive_writes==0);
 puts("PASS PFM2: invalid, failed and stale authorization paths never produce success");
 return 0;
}
