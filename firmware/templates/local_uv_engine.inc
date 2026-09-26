/* PF_LOCAL_UV_024 -- compiled in cbor_client_pin.c to reuse the real PIN verifier.
 * No second PIN, no automatic approval, no plaintext PIN sent over USB.
 * Numeric UI uses the existing format-1 FIDO PIN and device-key wrapping.
 * Host ClientPIN is deliberately retained for provisioning and compatibility.
 */
extern bool has_keydev_dec;
extern uint8_t keydev_dec[32];

#include "local_uv_binding.h"

static void pf_uv_forget_working_secrets(void) {
    mbedtls_platform_zeroize(session_pin,32);
    mbedtls_platform_zeroize(keydev_dec,32);
    has_keydev_dec=false;
    keydev_unlocked=false;
    stopUsingPinUvAuthToken();
    fido_object_authorization_session_invalidate();
}

bool pf_local_uv_ready(void) {
#if FIDO_V1_LOCAL_UV
    /* R16_RW_PIN_INIT_FIX: Settings can run before the host sends CTAPHID_INIT.
     * At that point ef_pin may still be NULL even though file_scan_flash() has
     * already restored a valid PIN record. Resolve EF_PIN directly instead of
     * treating the lazy global pointer as proof that no PIN is configured.
     * R15 legacy/current record handling remains unchanged. */
    file_t *pin=pf_local_uv_pin_file();
    if(!pin || !file_has_data(pin) || !file_get_data(pin)) return false;
    uint32_t n=file_get_size(pin);
    if(n==PIN_LEGACY_DATA_LEN) return true;
    return n==PIN_DATA_LEN && file_get_data(pin)[2]==1;
#else
    return false;
#endif
}

static int pf_uv_unlock_and_migrate_pin(uint8_t stored[PIN_DATA_LEN],uint16_t stored_len,
                                        const uint8_t h[32],uint8_t key[32]) {
#if !FIDO_V1_LOCAL_UV
    (void)stored;(void)stored_len;(void)h;(void)key;
    return CTAP2_ERR_NOT_ALLOWED;
#else
    const bool legacy=stored_len==PIN_LEGACY_DATA_LEN;
    if(legacy) {
        /* Reproduce upstream ClientPIN's legacy-key migration before switching
         * to the current session KDF. This preserves credentials created before
         * the 35-byte PIN record was introduced. */
        hash_multi(CONST_BYTE_ARRAY(h,16),session_pin);
        if(load_keydev(key)!=PICOKEYS_OK) return CTAP2_ERR_PROCESSING;
        if(encrypt_keydev_f1(key)!=PICOKEYS_OK) return CTAP2_ERR_PROCESSING;
    }
    pin_derive_session(CONST_BYTE_ARRAY(h,16),session_pin);
    if(check_keydev_encrypted(session_pin)!=PICOKEYS_OK || load_keydev(key)!=PICOKEYS_OK)
        return CTAP2_ERR_PROCESSING;
    if(legacy) {
        uint8_t upgraded[PIN_DATA_LEN]={0};
        upgraded[0]=MAX_PIN_RETRIES;
        upgraded[1]=stored[1];
        upgraded[2]=1;
        pin_derive_verifier(CONST_BYTE_ARRAY(h,16),upgraded+3);
        if(file_put_data(ef_pin,CONST_BYTE_ARRAY(upgraded,sizeof(upgraded)))!=PICOKEYS_OK) {
            mbedtls_platform_zeroize(upgraded,sizeof(upgraded));
            return CTAP2_ERR_PROCESSING;
        }
        flash_commit();
        memcpy(stored,upgraded,sizeof(upgraded));
        mbedtls_platform_zeroize(upgraded,sizeof(upgraded));
        new_pin_mismatches=0;
        needs_power_cycle=false;
    }
    return CTAP2_OK;
#endif
}

int pf_local_uv_verify(uint8_t permissions) {
#if !FIDO_V1_LOCAL_UV
    (void)permissions;
    return CTAP2_ERR_NOT_ALLOWED;
#else
    uint8_t stored[PIN_DATA_LEN]={0}, h[32]={0}, verifier[32]={0}, key[32]={0};
    uint16_t stored_len=0;
    char pin[WS_PIN_MAX_BYTES+1]={0};
    size_t length=0;
    int result=CTAP2_ERR_PROCESSING;
    /* Never let an earlier successful operation substitute for a new PIN check. */
    pf_uv_forget_working_secrets();
    if(!pf_local_uv_ready()) { result=CTAP2_ERR_NOT_ALLOWED;goto done; }
    if(!load_pin_data(ef_pin,stored,&stored_len)) goto done;
    /* Exhausting ClientPIN disables ALL user verification, as required by CTAP. */
    if((stored[0]&PIN_RETRY_COUNT_MASK)==0) { result=CTAP2_ERR_UV_BLOCKED;goto done; }
    if(minpin_force_change_pending(file_search_by_fid(EF_MINPINLEN,NULL,SPECIFY_EF))) {
        result=CTAP2_ERR_PIN_POLICY_VIOLATION;goto done;
    }
    int budget=ws_uv_retries_get();
    if(budget<0) goto done;
    if(budget==0) { result=CTAP2_ERR_UV_BLOCKED;goto done; }
    int input=ws_board_get_pin(pin,sizeof(pin),&length,(unsigned)budget,permissions);
    if(input) {
        result=input==1?CTAP2_ERR_KEEPALIVE_CANCEL:input==2?CTAP2_ERR_USER_ACTION_TIMEOUT:CTAP2_ERR_PROCESSING;
        goto done;
    }
    if(cancel_button) { result=CTAP2_ERR_KEEPALIVE_CANCEL;goto done; }
    if(length<4 || length>WS_PIN_MAX_BYTES) goto done;
    for(size_t i=0;i<length;++i) if(pin[i]<'0' || pin[i]>'9') goto done;
    /* Commit BEFORE comparing, so an ordinary power cycle cannot refund a guess. */
    if(!ws_uv_retries_reserve()) goto done;
    if(mbedtls_sha256((const uint8_t *)pin,length,h,0)!=0) goto done;
    mbedtls_platform_zeroize(pin,sizeof(pin));
    uint8_t off=stored_len==PIN_LEGACY_DATA_LEN?2U:3U;
    if(off==2U) double_hash_pin(CONST_BYTE_ARRAY(h,16),verifier);
    else pin_derive_verifier(CONST_BYTE_ARRAY(h,16),verifier);
    if(mbedtls_ct_memcmp(verifier,stored+off,32)!=0) {
        result=budget==1?CTAP2_ERR_UV_BLOCKED:CTAP2_ERR_UV_INVALID;goto done;
    }
    if(!pf_local_uv_bind_keydev_file()) { result=CTAP2_ERR_PROCESSING;goto done; }
    /* Loading the real key is essential; a cosmetic UV flag would not unlock
     * PIN-wrapped resident credentials. Do not fall back to an unwrapped key. */
    result=pf_uv_unlock_and_migrate_pin(stored,stored_len,h,key);
    if(result!=CTAP2_OK) goto done;
    if(cancel_button) { result=CTAP2_ERR_KEEPALIVE_CANCEL;goto done; }
    if(!ws_uv_retries_reset()) goto done;
    result=CTAP2_OK;
done:
    mbedtls_platform_zeroize(pin,sizeof(pin));
    mbedtls_platform_zeroize(stored,sizeof(stored));
    mbedtls_platform_zeroize(h,sizeof(h));
    mbedtls_platform_zeroize(verifier,sizeof(verifier));
    mbedtls_platform_zeroize(key,sizeof(key));
    if(result!=CTAP2_OK) pf_uv_forget_working_secrets();
    ws_board_pin_feedback(result);
    return result;
#endif
}


/* R13 narrow local policy check for Settings READ ONLY -> READ/WRITE.
 * The PIN is collected by the existing on-device pinpad. We reuse the same
 * stored verifier, retry budget and wrapped-device-key validation as normal
 * local UV, but ALWAYS tear down the working PIN/session state before return.
 * Success therefore authorizes exactly one local configuration transition and
 * never creates/reuses a CTAP pinUvAuthToken or user-verification session. */
int pf_local_uv_verify_supplied_pin(const char *pin,size_t length) {
#if !FIDO_V1_LOCAL_UV
    (void)pin;(void)length;
    return CTAP2_ERR_NOT_ALLOWED;
#else
    uint8_t stored[PIN_DATA_LEN]={0}, h[32]={0}, verifier[32]={0}, key[32]={0};
    uint16_t stored_len=0;
    int result=CTAP2_ERR_PROCESSING;
    int budget=-1;
    pf_uv_forget_working_secrets();
    if(!pin || !pf_local_uv_ready()) { result=CTAP2_ERR_NOT_ALLOWED;goto done; }
    if(!load_pin_data(ef_pin,stored,&stored_len)) goto done;
    if((stored[0]&PIN_RETRY_COUNT_MASK)==0) { result=CTAP2_ERR_UV_BLOCKED;goto done; }
    if(minpin_force_change_pending(file_search_by_fid(EF_MINPINLEN,NULL,SPECIFY_EF))) {
        result=CTAP2_ERR_PIN_POLICY_VIOLATION;goto done;
    }
    budget=ws_uv_retries_get();
    if(budget<0) goto done;
    if(budget==0) { result=CTAP2_ERR_UV_BLOCKED;goto done; }
    if(length<4 || length>WS_PIN_MAX_BYTES) { result=CTAP2_ERR_UV_INVALID;goto done; }
    for(size_t i=0;i<length;++i) {
        if(pin[i]<'0' || pin[i]>'9') { result=CTAP2_ERR_UV_INVALID;goto done; }
    }
    /* Match the normal local-UV anti-rollback rule: consume the attempt before
     * comparing, so a power loss cannot refund a wrong PIN guess. */
    if(!ws_uv_retries_reserve()) goto done;
    if(mbedtls_sha256((const uint8_t *)pin,length,h,0)!=0) goto done;
    uint8_t off=stored_len==PIN_LEGACY_DATA_LEN?2U:3U;
    if(off==2U) double_hash_pin(CONST_BYTE_ARRAY(h,16),verifier);
    else pin_derive_verifier(CONST_BYTE_ARRAY(h,16),verifier);
    if(mbedtls_ct_memcmp(verifier,stored+off,32)!=0) {
        result=budget==1?CTAP2_ERR_UV_BLOCKED:CTAP2_ERR_UV_INVALID;goto done;
    }
    if(!pf_local_uv_bind_keydev_file()) { result=CTAP2_ERR_PROCESSING;goto done; }
    /* Validate the same wrapped device key as the normal FIDO verifier. The
     * resulting session/key material is deliberately destroyed below. */
    result=pf_uv_unlock_and_migrate_pin(stored,stored_len,h,key);
    if(result!=CTAP2_OK) goto done;
    if(!ws_uv_retries_reset()) goto done;
    result=CTAP2_OK;
done:
    mbedtls_platform_zeroize(stored,sizeof(stored));
    mbedtls_platform_zeroize(h,sizeof(h));
    mbedtls_platform_zeroize(verifier,sizeof(verifier));
    mbedtls_platform_zeroize(key,sizeof(key));
    /* Unlike pf_local_uv_verify(), Settings authentication never leaves a UV
     * session alive, even after a correct PIN. */
    pf_uv_forget_working_secrets();
    return result;
#endif
}

static int pf_local_uv_token(uint8_t protocol,uint64_t permissions,
                            int64_t kty,int64_t alg,int64_t crv,
                            const CborByteString *x,const CborByteString *y,
                            const CborCharString *rp,uint8_t out[48],uint16_t *out_len) {
#if !FIDO_V1_LOCAL_UV
    (void)protocol;(void)permissions;(void)kty;(void)alg;(void)crv;
    (void)x;(void)y;(void)rp;(void)out;(void)out_len;
    return CTAP2_ERR_INVALID_SUBCOMMAND;
#else
    *out_len=0;
    mbedtls_platform_zeroize(out,48);
    const uint64_t supported=CTAP_PERMISSION_MC|CTAP_PERMISSION_GA|CTAP_PERMISSION_CM|
        CTAP_PERMISSION_LBW|CTAP_PERMISSION_ACFG|CTAP_PERMISSION_PCMR;
    if(!x->present || !y->present) return CTAP2_ERR_MISSING_PARAMETER;
    if((protocol!=1 && protocol!=2) || kty!=2 || alg!=-25 || crv!=1 ||
       x->len!=32 || y->len!=32 || !x->data || !y->data) return CTAP1_ERR_INVALID_PARAMETER;
    if(!permissions) return CTAP1_ERR_INVALID_PARAMETER;
    if((permissions & ~supported) ||
       ((permissions&CTAP_PERMISSION_PCMR) && permissions!=CTAP_PERMISSION_PCMR))
        return CTAP2_ERR_UNAUTHORIZED_PERMISSION;
    if((permissions&(CTAP_PERMISSION_MC|CTAP_PERMISSION_GA)) && !rp->present)
        return CTAP2_ERR_MISSING_PARAMETER;
    if(rp->present && (!rp->data || !rp->len || rp->len>1024)) return CTAP1_ERR_INVALID_PARAMETER;
    if(!hkey_init) return CTAP2_ERR_PROCESSING;
    if(mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.X,x->data,x->len)!=0 ||
       mbedtls_mpi_read_binary(&hkey.ctx.mbed_ecdh.Qp.Y,y->data,y->len)!=0 ||
       mbedtls_mpi_lset(&hkey.ctx.mbed_ecdh.Qp.Z,1)!=0 ||
       mbedtls_ecp_check_pubkey(&hkey.ctx.mbed_ecdh.grp,&hkey.ctx.mbed_ecdh.Qp)!=0)
        return CTAP1_ERR_INVALID_PARAMETER;
    uint8_t shared[64]={0};
    int result=ecdh(protocol,&hkey.ctx.mbed_ecdh.Qp,shared);
    if(result) { result=CTAP1_ERR_INVALID_PARAMETER;goto done; }
    result=pf_local_uv_verify((uint8_t)permissions);
    if(result) goto done;
    if(cancel_button) { result=CTAP2_ERR_KEEPALIVE_CANCEL;goto done; }
    const uint8_t *token=NULL;
    if(permissions==CTAP_PERMISSION_PCMR) {
        if(!ppaut.data || ppaut.len!=32) { result=CTAP2_ERR_PROCESSING;goto done; }
        ppaut.permissions=CTAP_PERMISSION_PCMR;
        token=ppaut.data;
    } else {
        if(resetPinUvAuthToken()!=0 || !paut.data || paut.len!=32) {
            result=CTAP2_ERR_PROCESSING;goto done;
        }
        beginUsingPinUvAuthToken(true);
        /* Entry plus explicit OK supplies UP, not just UV. It is bound to the
         * token's permissions/RP and consumed by the normal CTAP command path. */
        user_present_time_limit=board_millis();
        paut.permissions=(uint8_t)permissions;
        paut.has_rp_id=rp->present;
        if(rp->present && mbedtls_sha256((const uint8_t *)rp->data,rp->len,paut.rp_id_hash,0)!=0) {
            result=CTAP2_ERR_PROCESSING;goto done;
        }
        token=paut.data;
    }
    if(encrypt(protocol,shared,token,32,out)!=0) { result=CTAP2_ERR_PROCESSING;goto done; }
    *out_len=protocol==1?32:48;
    result=CTAP2_OK;
done:
    mbedtls_platform_zeroize(shared,sizeof(shared));
    if(result) {
        mbedtls_platform_zeroize(out,48);
        pf_uv_forget_working_secrets();
        ppaut.permissions=0;
    }
    return result;
#endif
}
